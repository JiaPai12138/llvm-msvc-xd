//===- SmallVmpPass.h - SmallVmp VM Obfuscation pass ----------------------===//
//
// This file defines the SmallVmpPass which transforms functions marked with
// x-svm attribute into VM-protected bytecode.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBFUSCATION_SMALLVMPPASS_H
#define LLVM_OBFUSCATION_SMALLVMPPASS_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class SmallVmpPass : public PassInfoMixin<SmallVmpPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }
};

} // namespace llvm

#endif // LLVM_OBFUSCATION_SMALLVMPPASS_H
