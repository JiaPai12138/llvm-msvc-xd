// IRVMModuleTool.h - LLVM 18 adapted
// Orchestrates VM transformation for functions marked with x-svm attribute:
//   (1) Normalize (PHI elimination / switch->if) + handle collection
//   (2) Bytecode generation + global emit + rewrite to vm_exec stub

#pragma once
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <cctype>

#include "SVM/FuncRedirector.hpp"
#include "SVM/GlobalInit.hpp"
#include "SVM/HandleCallTool.h"
#include "SVM/VMCodeGen.h"
#include "SVM/PhiSimplifyTool.h"
#include "SVM/SwitchToIf.h"

namespace vmp {

class IRVMModuleTool {
public:
  struct Stats {
    unsigned NumCandidates = 0;
    unsigned NumSkippedPre = 0;
    unsigned NumSkippedPostSimplify = 0;
    unsigned NumSkippedCodegen = 0;
    unsigned NumEmitted = 0;
    unsigned NumRewritten = 0;
    unsigned NumExceptions = 0;
  };

  IRVMModuleTool() = default;

  /// Set whether enabled globally via command line
  void setGlobalFlag(bool enabled) { GlobalFlag = enabled; }

  /// Main entry: transform all candidate functions in M
  bool run(llvm::Module &M) {
    using namespace llvm;
    TheDL = &M.getDataLayout();

    vmp::HandleCallTool handleTool;
    handleTool.bindModule(M);

    vmp::SwitchToIfTool switchTool;

    // Pass 1: normalize + collect
    for (Function &F : M) {
      if (!isCandidate(F)) continue;
      S.NumCandidates++;

      // Pre-check: VM coverage capability
      {
        std::string why;
        if (!isVMFriendly(F, *TheDL, why)) {
          llvm::errs() << "[x-svm] skip (pre) " << F.getName() << " : " << why << "\n";
          S.NumSkippedPre++;
          continue;
        }
      }

      // PHI elimination (with select(0/1) simplification)
      vmp::PhiEliminateTool phiTool(/*simplifySelect01=*/true);
      (void)phiTool.run(F);
      auto st = phiTool.getStats();

#ifdef SVM_IRVM_DEBUG
      llvm::errs() << "[x-svm] phi eliminated=" << st.NumPhiEliminated
                   << ", edges split=" << st.NumEdgesSplit
                   << ", select01=" << st.NumSelect01 << " @ " << F.getName() << "\n";
#endif
      // switch -> if
      (void)switchTool.transform(F);

      // Post-check: residual PHI/SWITCH
      bool hasPhi = false, hasSwitch = false;
      for (Instruction &I : instructions(F)) {
        hasPhi    |= llvm::isa<llvm::PHINode>(I);
        hasSwitch |= llvm::isa<llvm::SwitchInst>(I);
        if (hasPhi || hasSwitch) break;
      }
      if (hasPhi || hasSwitch) {
#ifdef SVM_IRVM_DEBUG
        llvm::errs() << "[x-svm] skip (post-simplify) " << F.getName()
                     << " : still has " << (hasPhi ? "PHI " : "")
                     << (hasSwitch ? "SWITCH " : "") << "\n";
#endif
        S.NumSkippedPostSimplify++;
        continue;
      }

      std::string why2;
      if (!isVMFriendlyPostNormalize(F, *TheDL, why2)) {
        #ifdef SVM_IRVM_DEBUG
        llvm::errs() << "[x-svm] skip (post) " << F.getName() << " : " << why2 << "\n";
        #endif
        S.NumSkippedPostSimplify++;
        continue;
      }

      // Collect call/const handles
      handleTool.collectFromFunction(F);
    }

    // Pass 2: generate bytecode + emit + rewrite
    for (llvm::Function &F : M) {
      if (!isCandidate(F)) continue;

      // Defensive check
      {
        std::string why;
        if (!isVMFriendlyPostNormalize(F, *TheDL, why)) {
          #ifdef SVM_IRVM_DEBUG
          llvm::errs() << "[x-svm] skip (codegen) " << F.getName() << " : " << why << "\n";
          #endif
          S.NumSkippedCodegen++;
          continue;
        }
      }

      vmp::VMCodeGen gen(F, handleTool);
      gen.run();
      const auto &bytes = gen.code();

      auto *ArrTy = llvm::ArrayType::get(llvm::Type::getInt8Ty(M.getContext()),
                                         bytes.size());
      std::string codeName = sanitizeName(F.getName()) + "_code";
#ifdef SVM_IRVM_DEBUG
      llvm::errs() << "[x-svm] emit code global: " << codeName
                   << " (" << bytes.size() << " bytes)\n";
#endif
      llvm::GlobalVariable *GV =
          ginit::ensureDefinableGV(M, codeName.c_str(), ArrTy, llvm::Align(1));
      GV->setLinkage(llvm::GlobalValue::ExternalLinkage);
      GV->setConstant(true);
      GV->setSection(".rodata.svm");

      if (!ginit::setBytes(GV, bytes)) {
        llvm::errs() << "[x-svm]   ! FAILED to initialize bytes for "
                     << F.getName() << "\n";
        S.NumSkippedCodegen++;
        continue;
      } else {
        #ifdef SVM_IRVM_DEBUG
        llvm::errs() << "[x-svm]   + bytes initialized\n";
        #endif
        S.NumEmitted++;
      }

      frx::VMExecOptions opt{};
      frx::rewriteToVMExec(F, GV, bytes.size(), opt);
      #ifdef SVM_IRVM_DEBUG
      llvm::errs() << "[x-svm]   + rewritten to vm_exec stub: "
                   << F.getName() << "\n";
      #endif
      S.NumRewritten++;
    }

    // Materialize handle_call (stub if empty) to satisfy vm_exec references.
    (void)handleTool.materializeHandle(M, /*forceCreateStubIfEmpty=*/true);

    return (S.NumRewritten > 0);
  }

  const Stats& getStats() const { return S; }

private:
  const llvm::DataLayout *TheDL = nullptr;
  Stats S{};
  bool GlobalFlag = false;

  // Check if function is a candidate using toObfuscate pattern
  bool isCandidate(llvm::Function &F) {
    if (F.isDeclaration()) return false;
    return toObfuscate(GlobalFlag, &F, "x-svm");
  }

  // Check function attribute annotation
  static bool toObfuscate(bool globalFlag, llvm::Function *F, llvm::StringRef attr) {
    // If global flag is enabled, process unless explicitly disabled
    // If global flag is disabled, only process if explicitly enabled via annotation

    std::string attrNo = "no-" + attr.str();

    // Check for explicit disable annotation
    if (hasAnnotation(F, attrNo)) {
      return false;
    }

    // Check for explicit enable annotation
    if (hasAnnotation(F, attr)) {
      return true;
    }

    // Fall back to global flag
    return globalFlag;
  }

  static bool hasAnnotation(llvm::Function *F, llvm::StringRef name) {
    // Check function attributes
    if (F->hasFnAttribute(name)) return true;

    // Check llvm.global.annotations
    llvm::Module *M = F->getParent();
    if (!M) return false;

    auto *GA = M->getNamedGlobal("llvm.global.annotations");
    if (!GA) return false;

    auto *Init = llvm::dyn_cast_or_null<llvm::ConstantArray>(GA->getInitializer());
    if (!Init) return false;

    for (unsigned i = 0; i < Init->getNumOperands(); ++i) {
      auto *CS = llvm::dyn_cast<llvm::ConstantStruct>(Init->getOperand(i));
      if (!CS || CS->getNumOperands() < 2) continue;

      // First operand is the annotated value (function)
      auto *FnRef = CS->getOperand(0)->stripPointerCasts();
      if (FnRef != F) continue;

      // Second operand is the annotation string
      auto *StrGV = llvm::dyn_cast<llvm::GlobalVariable>(
          CS->getOperand(1)->stripPointerCasts());
      if (!StrGV || !StrGV->hasInitializer()) continue;

      auto *StrInit = llvm::dyn_cast<llvm::ConstantDataArray>(StrGV->getInitializer());
      if (!StrInit || !StrInit->isString()) continue;

      llvm::StringRef Str = StrInit->getAsString();
      // Remove null terminator if present
      if (!Str.empty() && Str.back() == '\0')
        Str = Str.drop_back();

      if (Str == name) return true;
    }

    return false;
  }

  static std::string sanitizeName(llvm::StringRef S) {
    std::string R; R.reserve(S.size());
    for (char c : S) R.push_back(std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
    return R;
  }

  /// Pre-normalization VM coverage check
  static bool isVMFriendly(llvm::Function &F, const llvm::DataLayout &DL, std::string &Why) {
    using namespace llvm;
    if (F.isDeclaration()) {
      Why = "is declaration";
      return false;
    }

    for (Instruction &I : instructions(F)) {
      Type *Ty = I.getType();
      if (!Ty->isVoidTy() &&
          !(Ty->isIntegerTy() || Ty->isPointerTy() || Ty->isFloatTy() || Ty->isDoubleTy())) {
        if (Ty->isVectorTy() || Ty->isArrayTy() || Ty->isStructTy()) {
          Why = "aggregate or vector result not supported";
          return false;
        }
      }

      switch (I.getOpcode()) {
        case Instruction::Alloca: {
          auto &AI = cast<AllocaInst>(I);
          if (!AI.isStaticAlloca()) { Why = "variable-sized alloca not supported"; return false; }
          break;
        }
        case Instruction::Load: {
          auto &LI = cast<LoadInst>(I);
          if (LI.isAtomic()) { Why = "atomic load not supported"; return false; }
          if (LI.getType()->isVectorTy()) { Why = "vector load not supported"; return false; }
          break;
        }
        case Instruction::Store: {
          auto &SI = cast<StoreInst>(I);
          if (SI.isAtomic()) { Why = "atomic store not supported"; return false; }
          if (SI.getValueOperand()->getType()->isVectorTy()) { Why = "vector store not supported"; return false; }
          break;
        }

        // Whitelist: VMCodeGen covers these
        case Instruction::GetElementPtr:
        case Instruction::Trunc:
        case Instruction::ZExt:
        case Instruction::SExt:
        case Instruction::FPToUI:
        case Instruction::FPToSI:
        case Instruction::UIToFP:
        case Instruction::SIToFP:
        case Instruction::FPExt:
        case Instruction::FPTrunc:
        case Instruction::PtrToInt:
        case Instruction::IntToPtr:
        case Instruction::BitCast:
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Mul:
        case Instruction::UDiv:
        case Instruction::SDiv:
        case Instruction::URem:
        case Instruction::SRem:
        case Instruction::Shl:
        case Instruction::LShr:
        case Instruction::AShr:
        case Instruction::And:
        case Instruction::Or:
        case Instruction::Xor:
        case Instruction::FAdd:
        case Instruction::FSub:
        case Instruction::FMul:
        case Instruction::FDiv:
        case Instruction::FRem:
        case Instruction::ICmp:
        case Instruction::FCmp:
        case Instruction::Br:
        case Instruction::Switch:
        case Instruction::Ret:
        case Instruction::PHI:
        case Instruction::Select:
          break;

        case Instruction::Call:
        case Instruction::CallBr: {
          auto &CB = cast<CallBase>(I);
          if (CB.isInlineAsm()) { Why = "inline asm not supported"; return false; }
          if (CB.isMustTailCall()) { Why = "musttail call not supported"; return false; }
          for (unsigned i = 0; i < CB.arg_size(); ++i) {
            Type *AT = CB.getArgOperand(i)->getType();
            if (AT->isVectorTy()) { Why = "vector arg not supported"; return false; }
          }
          break;
        }

        // Reject: EH / atomic / complex control flow
        case Instruction::Invoke:
        case Instruction::LandingPad:
        case Instruction::Resume:
        case Instruction::CleanupRet:
        case Instruction::CatchRet:
        case Instruction::CatchPad:
        case Instruction::CleanupPad:
        case Instruction::CatchSwitch:
        case Instruction::IndirectBr:
        case Instruction::Fence:
        case Instruction::AtomicCmpXchg:
        case Instruction::AtomicRMW:
        case Instruction::VAArg:
        case Instruction::Freeze:
          Why = "advanced/eh/atomic/control-flow not supported";
          return false;

        default:
          Why = "unsupported opcode: " + std::string(I.getOpcodeName());
          return false;
      }
    }
    return true;
  }

  /// Post-normalization check (stricter - no PHI/Switch)
  static bool isVMFriendlyPostNormalize(llvm::Function &F, const llvm::DataLayout &DL, std::string &Why) {
    using namespace llvm;
    for (Instruction &I : instructions(F)) {
      if (isa<PHINode>(I)) {
        Why = "residual PHI node";
        return false;
      }
      if (isa<SwitchInst>(I)) {
        Why = "residual switch";
        return false;
      }
    }
    return isVMFriendly(F, DL, Why);
  }
};

} // namespace vmp
