//===- SmallVmpPass.cpp - SmallVmp VM Obfuscation pass --------------------===//
//
// This file implements the SmallVmpPass which transforms functions marked
// with x-svm attribute into VM-protected bytecode.
//
// Usage:
//   clang -mllvm -x-svm -c source.c -o source.o
//
// Mark functions with:
//   __attribute__((annotate("x-svm")))
//   int my_func(int x) { return x * 2; }
//
// Note: User code must include VMP.h to provide the vm_exec interpreter.
//
//===----------------------------------------------------------------------===//

#include "SmallVmpPass.h"
#include "SVM/IRVMModuleTool.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// Command line option: -x-svm enables VM protection globally
static cl::opt<bool> RunSmallVmp("x-svm", cl::init(false),
                                  cl::desc("OLLVM - SmallVmp VM Protection"));

PreservedAnalyses SmallVmpPass::run(Module &M, ModuleAnalysisManager &AM) {
  // Check if any function needs processing
  bool hasCandidate = false;

  srand(time(nullptr));
  
  if (RunSmallVmp) {
    hasCandidate = true;
  } else {
    // Check for per-function annotations
    for (Function &F : M) {
      if (F.isDeclaration()) continue;

      // Quick check for annotations
      if (auto *GA = M.getNamedGlobal("llvm.global.annotations")) {
        if (auto *Init = dyn_cast_or_null<ConstantArray>(GA->getInitializer())) {
          for (unsigned i = 0; i < Init->getNumOperands(); ++i) {
            auto *CS = dyn_cast<ConstantStruct>(Init->getOperand(i));
            if (!CS || CS->getNumOperands() < 2) continue;

            auto *FnRef = CS->getOperand(0)->stripPointerCasts();
            if (FnRef != &F) continue;

            auto *StrGV = dyn_cast<GlobalVariable>(
                CS->getOperand(1)->stripPointerCasts());
            if (!StrGV || !StrGV->hasInitializer()) continue;

            auto *StrInit = dyn_cast<ConstantDataArray>(StrGV->getInitializer());
            if (!StrInit || !StrInit->isString()) continue;

            StringRef Str = StrInit->getAsString();
            if (!Str.empty() && Str.back() == '\0')
              Str = Str.drop_back();

            if (Str == "x-svm") {
              hasCandidate = true;
              break;
            }
          }
        }
      }
      if (hasCandidate) break;
    }
  }

  if (!hasCandidate) {
    return PreservedAnalyses::all();
  }
  #ifdef SVM_VMP_DEBUG
  errs() << "[SmallVmpPass] Processing module: " << M.getName() << "\n";
  #endif
  vmp::IRVMModuleTool tool;
  tool.setGlobalFlag(RunSmallVmp);

  bool changed = tool.run(M);

  auto st = tool.getStats();
  #ifdef SVM_VMP_DEBUG
  errs() << "[SmallVmpPass] Summary:\n"
         << "  candidates=" << st.NumCandidates
         << " emitted=" << st.NumEmitted
         << " rewritten=" << st.NumRewritten
         << " skipped(pre)=" << st.NumSkippedPre
         << " skipped(post)=" << st.NumSkippedPostSimplify
         << " skipped(codegen)=" << st.NumSkippedCodegen
         << "\n";
  #endif
  if (changed) {
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}
