#ifndef LLVM_VMPOBFUCATOR_OBFUSCATION_H
#define LLVM_VMPOBFUCATOR_OBFUSCATION_H

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"

#include <cstring>
#include <map>
#include <random>
#include <vector>
#include <cstdint>
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DataLayout.h"

namespace llvm {

class VmObfuscatorPass : public PassInfoMixin<VmObfuscatorPass> {
private:
    std::vector<uint8_t> bytecode;
    std::map<Value *, int> allocaMap;
    std::map<Value *, bool> valueOnStack;
    std::map<BasicBlock *, size_t> blockAddresses;
    std::map<BasicBlock *, std::vector<size_t>> pendingBranches;
    int nextAllocaSlot = 0;
    std::map<Function *, unsigned> callIndex;
    std::vector<Function *> callTargets;
    std::map<GlobalValue *, unsigned> dataIndex;
    std::vector<GlobalValue *> dataItems;
    std::vector<uint64_t> dataKey;
    std::map<std::pair<Function *, GlobalVariable *>, unsigned> encDataIndex;
    std::vector<uint8_t> dataIsEnc;
    std::vector<uint32_t> dataLen;
    std::vector<uint64_t> dataSalt;
    Module *Mod = nullptr;
    const DataLayout *DL = nullptr;
    std::map<Value *, size_t> localBase;
    size_t localMemOffset = 0;
    std::map<BasicBlock *, std::vector<PHINode *>> phisInBlock;
    std::mt19937_64 rng;
    uint64_t currentKey = 0;
    uint32_t currentImmMask = 0;
    Function *CurFn = nullptr;
    uint64_t dataGlobalKey = 0;

    uint32_t computeImmMask(uint64_t key) const;
    void refreshFunctionKey();
    uint32_t encryptImmediate(int32_t value) const;
    static bool tryExtractBytesFromGV(GlobalVariable *GV, std::vector<uint8_t> &out);
    static uint64_t stream_next(uint64_t &s);
    void encryptBytesWithKey(const std::vector<uint8_t> &plain, std::vector<uint8_t> &enc, uint64_t salt, uint64_t key);
    unsigned getOrAddGlobalDataIndex(GlobalValue *GV);
    unsigned getOrAddEncryptedStringIndex(Function *F, GlobalVariable *GV);
    void emitPushGlobalForCurrentFunction(GlobalValue *GV);
    void emitByte(uint8_t byte);
    void emitPushImm(int32_t value);
    void emitPushArg(uint8_t argIndex);
    void emitStore(uint8_t addr);
    void emitLoad(uint8_t addr);
    void emitAdd();
    void emitSub();
    void emitMul();
    void emitDiv();
    void emitCmpGT();
    void emitCmpLT();
    void emitCmpEQ();
    void emitCmpNE();
    void emitBrCond(uint16_t target = 0);
    void emitJmp(uint16_t target = 0);
    void emitRet();
    void forcePushValue(Value *val);
    void emitCall(uint16_t index, uint8_t argc, uint32_t ptrMask);
    void emitPushGlob(uint16_t index);
    int getAllocaSlot(Value *alloca);
    int getTempSlot(Value *v);
    void ensureOnStack(Value *val);
    void patchBranches(BasicBlock *block, size_t address);
    size_t getOrAssignLocalBase(AllocaInst *AI);
    bool translateInstruction(Instruction &I);

public:
    VmObfuscatorPass();
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
    static bool isRequired() { return true; }
};

} // namespace llvm

#endif
