// SwitchToIf.h - LLVM 18 adapted
// Switch statements to if/else chain transformation
// Usage: vmp::SwitchToIfTool{}.transform(F);

#pragma once
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/SmallVector.h"

namespace vmp {

struct SwitchToIfTool {
  unsigned transform(llvm::Function &F) {
    using namespace llvm;
    SmallVector<SwitchInst*, 8> WL;
    for (auto &BB : F)
      if (auto *SI = dyn_cast<SwitchInst>(BB.getTerminator()))
        WL.push_back(SI);

    unsigned changed = 0;
    for (SwitchInst *SI : WL)
      if (lowerOneSwitch(SI)) ++changed;
    return changed;
  }

private:
  static bool lowerOneSwitch(llvm::SwitchInst *SI) {
    using namespace llvm;

    BasicBlock *OrigBB = SI->getParent();
    Value *Cond = SI->getCondition();
    if (!isa<IntegerType>(Cond->getType())) return false;

    SmallVector<std::pair<ConstantInt*, BasicBlock*>, 16> Cases;
    Cases.reserve(SI->getNumCases());
    for (auto &C : SI->cases())
      Cases.emplace_back(C.getCaseValue(), C.getCaseSuccessor());

    BasicBlock *DefaultBB = SI->getDefaultDest();
    DebugLoc DL = SI->getDebugLoc();

    llvm::IRBuilder<> B(SI);
    if (DL) B.SetCurrentDebugLocation(DL);

    if (Cases.empty()) {
      (void)B.CreateBr(DefaultBB);
      SI->eraseFromParent();
      return true;
    }

    ConstantInt *C0 = Cases[0].first;
    BasicBlock  *T0 = Cases[0].second;

    if (Cases.size() == 1) {
      Value *Eq = B.CreateICmpEQ(Cond, C0);
      (void)B.CreateCondBr(Eq, T0, DefaultBB);
      SI->eraseFromParent();
      return true;
    }

    BasicBlock *Else0 = BasicBlock::Create(OrigBB->getContext(),
                                           OrigBB->getName() + ".sw.if.else0",
                                           OrigBB->getParent());
    {
      Value *Eq = B.CreateICmpEQ(Cond, C0);
      (void)B.CreateCondBr(Eq, T0, Else0);
    }
    SI->eraseFromParent();

    BasicBlock *CurElse = Else0;
    for (size_t i = 1; i < Cases.size(); ++i) {
      ConstantInt *Ci = Cases[i].first;
      BasicBlock  *Ti = Cases[i].second;

      llvm::IRBuilder<> BE(CurElse);
      if (DL) BE.SetCurrentDebugLocation(DL);

      const bool last = (i + 1 == Cases.size());
      if (!last) {
        BasicBlock *NextElse = BasicBlock::Create(CurElse->getContext(),
                              OrigBB->getName() + ".sw.if.else" + std::to_string(i),
                              OrigBB->getParent());
        Value *Eq = BE.CreateICmpEQ(Cond, Ci);
        (void)BE.CreateCondBr(Eq, Ti, NextElse);
        CurElse = NextElse;
      } else {
        Value *Eq = BE.CreateICmpEQ(Cond, Ci);
        (void)BE.CreateCondBr(Eq, Ti, DefaultBB);
      }
    }
    return true;
  }
};

} // namespace vmp
