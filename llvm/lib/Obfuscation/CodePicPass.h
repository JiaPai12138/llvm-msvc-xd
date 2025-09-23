#ifndef LLVM_CODE_PIC_PASS_H
#define LLVM_CODE_PIC_PASS_H

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"


namespace llvm {

class CodePicPass : public PassInfoMixin<CodePicPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  PreservedAnalyses run(Function& F, FunctionAnalysisManager& FM);
  explicit CodePicPass();
  static bool isRequired() { return true; }
};

} // namespace llvm

#endif 