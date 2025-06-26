#ifndef LLVM_ANTI_IDA_OBFUSCATION_H
#define LLVM_ANTI_IDA_OBFUSCATION_H

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
// #include <Obfuscation/PassRegistry.h>

namespace llvm {

class AntiIDAPass : public PassInfoMixin<AntiIDAPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

  static bool isRequired() { return true; }

private:
  void injectBytes(Function &F);
};

} // namespace llvm

#endif