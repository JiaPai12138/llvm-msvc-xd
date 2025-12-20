// PhiEliminateTool.hpp - header-only, LLVM 18 adapted
#pragma once
#include <map>
#include <utility>

#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h" // SplitEdge

namespace vmp {

class PhiEliminateTool {
public:
  struct Stats {
    unsigned NumPhiEliminated = 0;
    unsigned NumEdgesSplit    = 0;
    unsigned NumSelect01      = 0;
  };

  /// simplifySelect01: convert `select i1 %c, i32 1, i32 0` -> `zext i1 %c to i32`
  explicit PhiEliminateTool(bool simplifySelect01 = true)
      : SimplifySelect01(simplifySelect01) {}

  /// Execute on single function: optional select(0/1) folding, then eliminate all PHI
  /// Returns whether IR was modified
  bool run(llvm::Function &F) {
    bool Changed = false;
    if (SimplifySelect01)
      Changed |= foldSimpleSelect01(F);
    Changed |= eliminateAllPhi(F);
    return Changed;
  }

  const Stats& getStats() const { return S; }

private:
  bool SimplifySelect01;
  Stats S;

  // --- pass 1: fold select 0/1 to zext/sext ---
  bool foldSimpleSelect01(llvm::Function &F) {
    bool Changed = false;
    llvm::SmallVector<llvm::SelectInst*, 16> Work;
    for (llvm::BasicBlock &BB : F)
      for (llvm::Instruction &I : BB)
        if (auto *SI = llvm::dyn_cast<llvm::SelectInst>(&I))
          Work.push_back(SI);

    for (auto *SI : Work) {
      llvm::Value *Cond = SI->getCondition();
      llvm::Type  *Ty   = SI->getType();
      auto *CTrue  = llvm::dyn_cast<llvm::ConstantInt>(SI->getTrueValue());
      auto *CFalse = llvm::dyn_cast<llvm::ConstantInt>(SI->getFalseValue());
      if (!CTrue || !CFalse) continue;
      if (!Cond->getType()->isIntegerTy(1)) continue;

      if (CTrue->isOne() && CFalse->isZero() && Ty->isIntegerTy()) {
        llvm::IRBuilder<> B(SI);
        llvm::Value *Z = B.CreateZExt(Cond, Ty, SI->getName());
        SI->replaceAllUsesWith(Z);
        SI->eraseFromParent();
        ++S.NumSelect01;
        Changed = true;
      } else if (CTrue->isZero() && CFalse->isOne() && Ty->isIntegerTy()) {
        llvm::IRBuilder<> B(SI);
        llvm::Value *NotC = B.CreateNot(Cond, "notc");
        llvm::Value *Z = B.CreateZExt(NotC, Ty, SI->getName());
        SI->replaceAllUsesWith(Z);
        SI->eraseFromParent();
        ++S.NumSelect01;
        Changed = true;
      }
    }
    return Changed;
  }

  // --- pass 2: eliminate PHI (Demote to stack), auto split critical edges ---
  bool eliminateAllPhi(llvm::Function &F) {
    bool Changed = false;

    llvm::SmallVector<llvm::PHINode*, 32> AllPhis;
    for (llvm::BasicBlock &BB : F) {
      for (llvm::Instruction &I : BB) {
        if (auto *PN = llvm::dyn_cast<llvm::PHINode>(&I))
          AllPhis.push_back(PN);
        else
          break;
      }
    }

    if (AllPhis.empty()) return false;

    std::map<std::pair<llvm::BasicBlock*, llvm::BasicBlock*>, llvm::BasicBlock*> EdgeSplitCache;

    llvm::BasicBlock &Entry = F.getEntryBlock();
    llvm::Instruction *AllocaIP = &*Entry.getFirstInsertionPt();

    for (llvm::PHINode *PN : AllPhis) {
      if (!PN || PN->use_empty()) {
        if (PN) { PN->eraseFromParent(); ++S.NumPhiEliminated; Changed = true; }
        continue;
      }

      // 1) Create stack slot for this PHI
      auto *AI = new llvm::AllocaInst(PN->getType(), 0, PN->getName() + ".phi.spill", AllocaIP);

      // 2) Insert store on each incoming edge
      llvm::BasicBlock *DestBB = PN->getParent();
      const unsigned N = PN->getNumIncomingValues();

      for (unsigned i = 0; i < N; ++i) {
        llvm::Value      *V    = PN->getIncomingValue(i);
        llvm::BasicBlock *Pred = PN->getIncomingBlock(i);

        llvm::BasicBlock *InsertBB = Pred;

        auto *TI = Pred->getTerminator();
        const unsigned Succs = TI->getNumSuccessors();
        if (Succs > 1) {
          auto Key = std::make_pair(Pred, DestBB);
          auto It = EdgeSplitCache.find(Key);
          if (It != EdgeSplitCache.end()) {
            InsertBB = It->second;
          } else {
            llvm::BasicBlock *NewEdgeBB = llvm::SplitEdge(Pred, DestBB);
            InsertBB = NewEdgeBB;
            EdgeSplitCache.emplace(Key, NewEdgeBB);
            ++S.NumEdgesSplit;
          }
        }

        llvm::IRBuilder<> B(InsertBB->getTerminator());
        B.CreateStore(V, AI);
      }

      // 3) Insert load in destination block and replace PHI uses
      llvm::Instruction *IP = DestBB->getFirstNonPHI();
      llvm::IRBuilder<> BL(IP);
      llvm::LoadInst *Ld = BL.CreateLoad(PN->getType(), AI, PN->getName() + ".ld");
      PN->replaceAllUsesWith(Ld);

      // 4) Delete original PHI
      PN->eraseFromParent();
      ++S.NumPhiEliminated;
      Changed = true;
    }

    return Changed;
  }
};

} // namespace vmp
