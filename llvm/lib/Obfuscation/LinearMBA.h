#ifndef LLVM_OBFUSCATION_LINEARMBA_H
#define LLVM_OBFUSCATION_LINEARMBA_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class LinearMBAPass : public PassInfoMixin<LinearMBAPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  static bool isRequired() { return true; }
};

} // namespace llvm

#endif // LLVM_OBFUSCATION_LINEARMBA_H
