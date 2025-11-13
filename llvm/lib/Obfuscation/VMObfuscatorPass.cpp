#include "VMObfuscatorPass.h"
#include "vm_def.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

namespace llvm {
static cl::opt<bool> vmobf("x-vmobf", cl::init(false),
                           cl::desc("OLLVM - VmObfuscatorPass"));
// Constructor
VmObfuscatorPass::VmObfuscatorPass() {
  std::random_device rd;
  uint64_t seed = ((uint64_t)rd() << 32) ^ (uint64_t)rd();
  if (seed == 0)
    seed = 0x6a09e667f3bcc909ULL;
  rng.seed(seed);
}

// Compute immediate mask from key
uint32_t VmObfuscatorPass::computeImmMask(uint64_t key) const {
  uint32_t mask = static_cast<uint32_t>((key & 0xffffffffULL) ^ (key >> 32));
  return mask ? mask : 0xa5a5a5a5u;
}

// Refresh function-specific encryption key
void VmObfuscatorPass::refreshFunctionKey() {
  currentKey = rng();
  if (currentKey == 0)
    currentKey = 0x9e3779b97f4a7c15ULL;
  currentImmMask = computeImmMask(currentKey);
}

// Encrypt immediate value
uint32_t VmObfuscatorPass::encryptImmediate(int32_t value) const {
  return static_cast<uint32_t>(value) ^ currentImmMask;
}

// Try to extract bytes from global variable
bool VmObfuscatorPass::tryExtractBytesFromGV(GlobalVariable *GV,
                                             std::vector<uint8_t> &out) {
  if (!GV)
    return false;
  if (!GV->hasInitializer())
    return false;
  auto *CA = dyn_cast<ConstantDataArray>(GV->getInitializer());
  if (!CA)
    return false;
  if (!CA->getType()->getElementType()->isIntegerTy(8))
    return false;
  if (!CA->isString())
    return false; // restrict to string-like globals only
  // Extract raw bytes to preserve any embedded NUL and full array length
  StringRef raw = CA->getRawDataValues();
  out.assign(raw.bytes_begin(), raw.bytes_end());
  return true;
}

// Stream cipher next value
uint64_t VmObfuscatorPass::stream_next(uint64_t &s) {
  uint64_t x = s;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  s = x;
  return x * 2685821657736338717ULL;
}

// Encrypt bytes with key
void VmObfuscatorPass::encryptBytesWithKey(const std::vector<uint8_t> &plain,
                                           std::vector<uint8_t> &enc,
                                           uint64_t salt, uint64_t key) {
  enc.resize(plain.size());
  uint64_t st =
      (key ? key : 0x9e3779b97f4a7c15ULL) ^ salt ^ 0x9e3779b97f4a7c15ULL;
  uint64_t ks = 0;
  int bpos = 8;
  for (size_t i = 0; i < plain.size(); ++i) {
    if (bpos >= 8) {
      ks = stream_next(st);
      bpos = 0;
    }
    uint8_t k = (uint8_t)(ks & 0xFF);
    ks >>= 8;
    bpos++;
    enc[i] = plain[i] ^ k;
  }
}

// Get or add global data index
unsigned VmObfuscatorPass::getOrAddGlobalDataIndex(GlobalValue *GV) {
  if (!dataIndex.count(GV)) {
    unsigned idx = (unsigned)dataItems.size();
    dataIndex[GV] = idx;
    dataItems.push_back(GV);
    dataIsEnc.push_back(0);
    dataLen.push_back(0);
    dataSalt.push_back(0);
    dataKey.push_back(0);
  }
  return dataIndex[GV];
}

// Get or add encrypted string index
unsigned VmObfuscatorPass::getOrAddEncryptedStringIndex(Function *F,
                                                        GlobalVariable *GV) {
  auto key = std::make_pair(F, GV);
  auto it = encDataIndex.find(key);
  if (it != encDataIndex.end())
    return it->second;

  // Extract bytes
  std::vector<uint8_t> plain;
  if (!tryExtractBytesFromGV(GV, plain)) {
    // Fallback to plaintext path when extraction fails
    return getOrAddGlobalDataIndex(GV);
  }
  // For very short string literals (e.g., mode strings like "rb"),
  // avoid encryption to reduce overhead and prevent edge-case issues
  // with tiny blobs used in C library calls.
  if (plain.size() <= 4) {
    return getOrAddGlobalDataIndex(GV);
  }

  // Generate salt and encrypt
  uint64_t salt = rng();
  if (salt == 0)
    salt = 0x6a09e667f3bcc909ULL;
  std::vector<uint8_t> enc;
  encryptBytesWithKey(plain, enc, salt, dataGlobalKey);

  // Create encrypted clone global
  ArrayType *arrTy =
      ArrayType::get(Type::getInt8Ty(Mod->getContext()), enc.size());
  std::vector<Constant *> elems;
  elems.reserve(enc.size());
  for (uint8_t b : enc)
    elems.push_back(
        ConstantInt::get(Type::getInt8Ty(Mod->getContext()), (uint64_t)b));
  Constant *init = ConstantArray::get(arrTy, elems);
  auto *encGV = new GlobalVariable(
      *Mod, arrTy, /*isConstant*/ true, GlobalValue::PrivateLinkage, init,
      GV->getName() + ".enc." + (CurFn ? CurFn->getName() : "fn"));

  // Record table entry
  unsigned idx = (unsigned)dataItems.size();
  dataItems.push_back(encGV);
  dataIsEnc.push_back(1);
  dataLen.push_back((uint32_t)enc.size());
  dataSalt.push_back(salt);
  dataKey.push_back(dataGlobalKey);
  encDataIndex[key] = idx;
  return idx;
}

// Emit push global for current function
void VmObfuscatorPass::emitPushGlobalForCurrentFunction(GlobalValue *GV) {
  if (auto *GVar = dyn_cast<GlobalVariable>(GV)) {
    // Only encrypt true C string globals ([N x i8] with isString()==true).
    if (GVar->hasInitializer()) {
      if (auto *CDA = dyn_cast<ConstantDataArray>(GVar->getInitializer())) {
        if (CDA->getType()->getElementType()->isIntegerTy(8) &&
            CDA->isString()) {
          unsigned idx = getOrAddEncryptedStringIndex(CurFn, GVar);
          emitPushGlob((uint16_t)idx);
          return;
        }
      }
    }
  }
  // Non-string data goes through plaintext table
  unsigned idx = getOrAddGlobalDataIndex(GV);
  emitPushGlob((uint16_t)idx);
}

// Emit single byte
void VmObfuscatorPass::emitByte(uint8_t byte) { bytecode.push_back(byte); }

// Emit push immediate
void VmObfuscatorPass::emitPushImm(int32_t value) {
  errs() << "  PUSH_IMM " << value << "\n";
  emitByte(OP_PUSH_IMM);
  uint32_t cipher = encryptImmediate(value);
  uint8_t *bytes = reinterpret_cast<uint8_t *>(&cipher);
  for (int i = 0; i < 4; i++) {
    emitByte(bytes[i]);
  }
}

// Emit push argument
void VmObfuscatorPass::emitPushArg(uint8_t argIndex) {
  errs() << "  PUSH_ARG " << (int)argIndex << "\n";
  emitByte(OP_PUSH_ARG);
  emitByte(argIndex);
}

// Emit store
void VmObfuscatorPass::emitStore(uint8_t addr) {
  errs() << "  STORE at memory[" << (int)addr << "]\n";
  emitByte(OP_STORE);
  emitByte(addr);
}

// Emit load
void VmObfuscatorPass::emitLoad(uint8_t addr) {
  errs() << "  LOAD from memory[" << (int)addr << "]\n";
  emitByte(OP_LOAD);
  emitByte(addr);
}

// Emit add
void VmObfuscatorPass::emitAdd() {
  errs() << "  ADD\n";
  emitByte(OP_ADD);
}

// Emit subtract
void VmObfuscatorPass::emitSub() {
  errs() << "  SUB\n";
  emitByte(OP_SUB);
}

// Emit multiply
void VmObfuscatorPass::emitMul() {
  errs() << "  MUL\n";
  emitByte(OP_MUL);
}

// Emit divide
void VmObfuscatorPass::emitDiv() {
  errs() << "  DIV\n";
  emitByte(OP_DIV);
}

// Emit compare greater than
void VmObfuscatorPass::emitCmpGT() {
  errs() << "  CMP_GT\n";
  emitByte(OP_CMP_GT);
}

// Emit compare less than
void VmObfuscatorPass::emitCmpLT() {
  errs() << "  CMP_LT\n";
  emitByte(OP_CMP_LT);
}

// Emit compare equal
void VmObfuscatorPass::emitCmpEQ() {
  errs() << "  CMP_EQ\n";
  emitByte(OP_CMP_EQ);
}

// Emit compare not equal
void VmObfuscatorPass::emitCmpNE() {
  errs() << "  CMP_NE\n";
  emitByte(OP_CMP_NE);
}

// Emit conditional branch
void VmObfuscatorPass::emitBrCond(uint16_t target) {
  errs() << "  BR_COND to " << target << "\n";
  emitByte(OP_BR_COND);
  uint8_t *bytes = reinterpret_cast<uint8_t *>(&target);
  emitByte(bytes[0]);
  emitByte(bytes[1]);
}

// Emit unconditional jump
void VmObfuscatorPass::emitJmp(uint16_t target) {
  errs() << "  JMP to " << target << "\n";
  emitByte(OP_JMP);
  uint8_t *bytes = reinterpret_cast<uint8_t *>(&target);
  emitByte(bytes[0]);
  emitByte(bytes[1]);
}

// Emit return
void VmObfuscatorPass::emitRet() {
  errs() << "  RET\n";
  emitByte(OP_RET);
}

// Emit call
void VmObfuscatorPass::emitCall(uint16_t index, uint8_t argc,
                                uint32_t ptrMask) {
  errs() << "  CALL index=" << index << " argc=" << (int)argc << " ptrMask=0x"
         << Twine::utohexstr((uint64_t)ptrMask) << "\n";
  emitByte(OP_CALL);
  emitByte((uint8_t)(index & 0xFF));
  emitByte((uint8_t)((index >> 8) & 0xFF));
  emitByte(argc);
  // Emit 32-bit pointer mask (little-endian)
  uint8_t *pm = reinterpret_cast<uint8_t *>(&ptrMask);
  emitByte(pm[0]);
  emitByte(pm[1]);
  emitByte(pm[2]);
  emitByte(pm[3]);
}

// Emit push global
void VmObfuscatorPass::emitPushGlob(uint16_t index) {
  errs() << "  PUSH_GLOB index=" << index << "\n";
  emitByte(OP_PUSH_GLOB);
  emitByte((uint8_t)(index & 0xFF));
  emitByte((uint8_t)((index >> 8) & 0xFF));
}

// Get alloca slot
int VmObfuscatorPass::getAllocaSlot(Value *alloca) {
  if (allocaMap.find(alloca) == allocaMap.end()) {
    allocaMap[alloca] = nextAllocaSlot++;
    errs() << "  Assigned memory slot " << allocaMap[alloca] << " to alloca %"
           << alloca->getName() << "\n";
  }
  return allocaMap[alloca];
}

// Get temp slot
int VmObfuscatorPass::getTempSlot(Value *v) {
  if (allocaMap.find(v) == allocaMap.end()) {
    allocaMap[v] = nextAllocaSlot++;
    errs() << "  Assigned temp slot " << allocaMap[v] << " for %"
           << v->getName() << "\n";
  }
  return allocaMap[v];
}

// Force push value onto stack
void VmObfuscatorPass::forcePushValue(Value *val) {
  if (auto *CI = dyn_cast<ConstantInt>(val)) {
    emitPushImm((int32_t)CI->getSExtValue());
    return;
  }
  if (isa<ConstantPointerNull>(val)) {
    emitPushImm(0);
    return;
  }
  if (auto *AI = dyn_cast<AllocaInst>(val)) {
    int32_t base = (int32_t)getOrAssignLocalBase(AI);
    emitPushImm(base);
    emitByte(OP_TAG_LOCAL);
    return;
  }
  if (auto *GV = dyn_cast<GlobalValue>(val)) {
    emitPushGlobalForCurrentFunction(GV);
    return;
  }
  if (auto *CE = dyn_cast<ConstantExpr>(val)) {
    // Handle simple GEP or bitcast of globals/null by delegating to
    // ensureOnStack
    ensureOnStack(val);
    return;
  }
  if (auto *arg = dyn_cast<Argument>(val)) {
    emitPushArg(arg->getArgNo());
    return;
  }
  // Default: SSA value previously computed — load from its temp slot
  emitLoad(getTempSlot(val));
}

// Ensure value is on stack
void VmObfuscatorPass::ensureOnStack(Value *val) {
  // For immediates and null, always push a fresh value, even if seen before.
  if (auto *CI = dyn_cast<ConstantInt>(val)) {
    emitPushImm((int32_t)CI->getSExtValue());
    return;
  }
  if (isa<ConstantPointerNull>(val)) {
    emitPushImm(0);
    return;
  }
  if (valueOnStack[val])
    return;
  if (auto *AI = dyn_cast<AllocaInst>(val)) {
    int32_t base = (int32_t)getOrAssignLocalBase(AI);
    emitPushImm(base);
    emitByte(OP_TAG_LOCAL);
    valueOnStack[val] = true;
    return;
  }
  if (auto *GV = dyn_cast<GlobalValue>(val)) {
    emitPushGlobalForCurrentFunction(GV);
    valueOnStack[val] = true;
    return;
  }
  if (auto *CE = dyn_cast<ConstantExpr>(val)) {
    // Handle simple GEP or bitcast of globals/null
    if (CE->isCast()) {
      ensureOnStack(CE->getOperand(0));
      valueOnStack[val] = true;
      return;
    }
    if (CE->getOpcode() == Instruction::GetElementPtr) {
      // Compute constant byte offset using DataLayout
      if (!DL)
        report_fatal_error("DataLayout unavailable for GEP lowering");
      const GEPOperator *GEP = cast<GEPOperator>(CE);
      APInt Off(DL->getPointerSizeInBits(0), 0);
      bool ok = GEP->accumulateConstantOffset(*DL, Off);
      Value *base = const_cast<Value *>(GEP->getPointerOperand());
      // Force push base regardless of prior state to avoid stack underflow
      valueOnStack[base] = false;
      ensureOnStack(base);
      if (ok && !Off.isZero()) {
        emitPushImm((int32_t)Off.getSExtValue());
        emitAdd();
      }
      valueOnStack[base] = false; // consumed base
      valueOnStack[val] = true;
      return;
    }
  }
  if (auto *arg = dyn_cast<Argument>(val)) {
    emitPushArg(arg->getArgNo());
    valueOnStack[val] = true;
    return;
  }
  if (auto *PN = dyn_cast<PHINode>(val)) {
    // Load from its assigned temp slot
    emitLoad(getTempSlot(PN));
    valueOnStack[val] = true;
    return;
  }
  // If this is a previously computed SSA value, load it from its temp slot
  if (isa<Instruction>(val)) {
    emitLoad(getTempSlot(val));
    valueOnStack[val] = true;
    return;
  }
}

// Patch branches
void VmObfuscatorPass::patchBranches(BasicBlock *block, size_t address) {
  if (pendingBranches.find(block) != pendingBranches.end()) {
    for (size_t patchAddr : pendingBranches[block]) {
      uint16_t target = (uint16_t)address;
      bytecode[patchAddr] = target & 0xFF;
      bytecode[patchAddr + 1] = (target >> 8) & 0xFF;
      errs() << "  Patched branch at " << patchAddr << " to target " << address
             << "\n";
    }
    pendingBranches.erase(block);
  }
}

// Get or assign local base
size_t VmObfuscatorPass::getOrAssignLocalBase(AllocaInst *AI) {
  if (localBase.count(AI))
    return localBase[AI];
  size_t base = localMemOffset;
  Type *ty = AI->getAllocatedType();
  // Use precise allocation size from DataLayout, including array counts
  size_t elemSize = DL ? (size_t)DL->getTypeAllocSize(ty) : 64;
  uint64_t count = 1;
  if (AI->isArrayAllocation()) {
    if (auto *C = dyn_cast<ConstantInt>(AI->getArraySize())) {
      count = C->getZExtValue();
    } else {
      // Fallback; most of our code doesn't use VLAs
      count = 1;
    }
  }
  size_t bytes = elemSize * (size_t)count;
  // 16-byte align allocations to be safe for structs
  size_t aligned = (bytes + 15) & ~((size_t)15);
  localBase[AI] = base;
  localMemOffset = base + aligned;
  return base;
}

// Translate instruction - this is the largest function, implementing all
// instruction types
bool VmObfuscatorPass::translateInstruction(Instruction &I) {
  errs() << "Translating: " << I << "\n";

  if (auto *PN = dyn_cast<PHINode>(&I)) {
    // No direct emission; values are spilled at predecessors and loaded on
    // demand
    return true;
  } else if (auto *AI = dyn_cast<AllocaInst>(&I)) {
    // Always place allocas in local byte-addressable memory so taking
    // their address works correctly when passed to external functions.
    (void)getOrAssignLocalBase(AI);
    return true;
  } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
    Value *val = SI->getValueOperand();
    Value *ptr = SI->getPointerOperand();
    Type *ty = val->getType();

    if (auto *vecTy = dyn_cast<VectorType>(ty)) {
      Type *elemTy = vecTy->getElementType();
      if (!elemTy->isIntegerTy(8)) {
        report_fatal_error(
            "Unsupported vector element type in VM obfuscator store");
      }
      auto elemCount = vecTy->getElementCount();
      if (elemCount.isScalable()) {
        report_fatal_error(
            "Scalable vector store not supported in VM obfuscator");
      }
      auto *constVec = dyn_cast<Constant>(val);
      if (!constVec) {
        report_fatal_error(
            "Non-constant vector store not supported in VM obfuscator");
      }

      // Preserve destination pointer for per-byte stores
      ensureOnStack(ptr);
      emitStore(getTempSlot(ptr));
      valueOnStack[ptr] = false;

      unsigned count = elemCount.getFixedValue();
      for (unsigned idx = 0; idx < count; ++idx) {
        Constant *elem = constVec->getAggregateElement(idx);
        if (!elem) {
          report_fatal_error("Unable to extract vector element for store");
        }
        auto *elemInt = dyn_cast<ConstantInt>(elem);
        if (!elemInt) {
          report_fatal_error("Non-integer element in byte vector store");
        }

        emitLoad(getTempSlot(ptr));
        if (idx != 0) {
          emitPushImm((int32_t)idx);
          emitAdd();
        }
        emitPushImm((int32_t)elemInt->getZExtValue());
        emitByte(OP_STORE8);
      }

      valueOnStack[val] = false;
      return true;
    }

    {
      // Normalize order so that value is on top-of-stack at STORE time
      bool valWasOnStack = valueOnStack[val];
      if (valWasOnStack) {
        // Spill the value to a temp slot to free the stack, then reload after
        // pushing ptr
        emitStore(getTempSlot(val));
        valueOnStack[val] = false;
      }

      // Push destination pointer
      Value *basePtr = ptr;
      if (auto *BC = dyn_cast<BitCastInst>(ptr))
        basePtr = BC->getOperand(0);
      if (auto *GV = dyn_cast<GlobalValue>(basePtr)) {
        emitPushGlobalForCurrentFunction(GV);
      } else {
        ensureOnStack(ptr);
      }

      // Ensure value is on top now
      if (valWasOnStack) {
        emitLoad(getTempSlot(val));
        valueOnStack[&I] = false; // not meaningful, but keep mapping tidy
      } else {
        ensureOnStack(val);
      }

      if (ty->isIntegerTy(8))
        emitByte(OP_STORE8);
      else if (ty->isIntegerTy(16))
        emitByte(OP_STORE16);
      else if (ty->isIntegerTy(32))
        emitByte(OP_STORE32);
      else if (ty->isPointerTy())
        emitByte(OP_STOREPTR64);
      else if (ty->isIntegerTy(64))
        emitByte(OP_STORE64);
      else
        report_fatal_error("Unsupported store type in VM obfuscator");
      valueOnStack[val] = false;
      valueOnStack[ptr] = false;
    }
    return true;
  } else if (auto *LI = dyn_cast<LoadInst>(&I)) {
    Value *ptr = LI->getPointerOperand();
    if (auto *BC = dyn_cast<BitCastInst>(ptr)) {
      if (auto *A2 = dyn_cast<AllocaInst>(BC->getOperand(0))) {
        // Loading from local byte memory through bitcast -> treat as local
        // pointer with offset 0
        int32_t base = (int32_t)getOrAssignLocalBase(A2);
        emitPushImm(base);
        emitByte(OP_TAG_LOCAL);
        Type *ty = LI->getType();
        if (ty->isIntegerTy(8))
          emitByte(OP_LOAD8);
        else if (ty->isIntegerTy(16))
          emitByte(OP_LOAD16);
        else if (ty->isIntegerTy(32))
          emitByte(OP_LOAD32);
        else if (ty->isIntegerTy(64) || ty->isPointerTy())
          emitByte(OP_LOAD64);
        else
          report_fatal_error("Unsupported load type in VM obfuscator");
        // Spill result from local byte memory load
        emitStore(getTempSlot(&I));
        valueOnStack[&I] = false;
        return true;
      }
      if (auto *GV = dyn_cast<GlobalValue>(BC->getOperand(0))) {
        // Always route through helper to keep metadata arrays aligned
        emitPushGlobalForCurrentFunction(GV);
      } else {
        ensureOnStack(ptr);
      }
      Type *ty = LI->getType();
      if (ty->isIntegerTy(8))
        emitByte(OP_LOAD8);
      else if (ty->isIntegerTy(16))
        emitByte(OP_LOAD16);
      else if (ty->isIntegerTy(32))
        emitByte(OP_LOAD32);
      else if (ty->isIntegerTy(64) || ty->isPointerTy())
        emitByte(OP_LOAD64);
      else
        report_fatal_error("Unsupported load type in VM obfuscator");
    } else {
      // Direct alloca or global or computed pointer
      Value *basePtr = ptr;
      if (auto *AI = dyn_cast<AllocaInst>(basePtr)) {
        int32_t base = (int32_t)getOrAssignLocalBase(AI);
        emitPushImm(base);
        emitByte(OP_TAG_LOCAL);
      } else if (auto *GV = dyn_cast<GlobalValue>(basePtr)) {
        // Keep table + metadata in sync
        emitPushGlobalForCurrentFunction(GV);
      } else {
        ensureOnStack(ptr);
      }
      Type *ty = LI->getType();
      if (ty->isIntegerTy(8))
        emitByte(OP_LOAD8);
      else if (ty->isIntegerTy(16))
        emitByte(OP_LOAD16);
      else if (ty->isIntegerTy(32))
        emitByte(OP_LOAD32);
      else if (ty->isIntegerTy(64) || ty->isPointerTy())
        emitByte(OP_LOAD64);
      else
        report_fatal_error("Unsupported load type in VM obfuscator");
    }
    // Spill result to temp slot so it can be reloaded after stack barriers
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
    Value *op1 = BO->getOperand(0);
    Value *op2 = BO->getOperand(1);
    
    // Special handling for Add with negative constants to avoid pointer arithmetic confusion
    if (BO->getOpcode() == Instruction::Add) {
      // Check if op2 is a negative constant: add x, -N → sub x, N
      if (auto *CI = dyn_cast<ConstantInt>(op2)) {
        if (CI->isNegative()) {
          ensureOnStack(op1);
          emitPushImm((int32_t)(-CI->getSExtValue()));
          emitSub();
          valueOnStack[op1] = false;
          emitStore(getTempSlot(&I));
          valueOnStack[&I] = false;
          return true;
        }
      }
      // Check if op1 is a negative constant: add -N, x → sub x, N
      if (auto *CI = dyn_cast<ConstantInt>(op1)) {
        if (CI->isNegative()) {
          ensureOnStack(op2);
          emitPushImm((int32_t)(-CI->getSExtValue()));
          emitSub();
          valueOnStack[op2] = false;
          emitStore(getTempSlot(&I));
          valueOnStack[&I] = false;
          return true;
        }
      }
    }
    
    ensureOnStack(op1);
    ensureOnStack(op2);

    switch (BO->getOpcode()) {
    case Instruction::Add:
      emitAdd();
      break;
    case Instruction::And:
      emitByte(OP_AND);
      break;
    case Instruction::Sub: {
      // Check if op2 is a negative constant: sub x, -N → add x, N
      if (auto *CI = dyn_cast<ConstantInt>(op2)) {
        if (CI->isNegative()) {
          ensureOnStack(op1);
          emitPushImm((int32_t)(-CI->getSExtValue()));
          emitAdd();
          valueOnStack[op1] = false;
          emitStore(getTempSlot(&I));
          valueOnStack[&I] = false;
          return true;
        }
      }
      emitSub();
      break;
    }
    case Instruction::Mul:
      emitMul();
      break;
    case Instruction::SDiv:
      emitDiv();
      break;
    case Instruction::UDiv:
      emitByte(OP_UDIV);
      break;
    case Instruction::URem:
      emitByte(OP_UREM);
      break;
    case Instruction::SRem:
      emitByte(OP_SREM);
      break;
    case Instruction::Shl:
      emitByte(OP_SHL);
      break;
    case Instruction::LShr:
      emitByte(OP_SHR);
      break;
    case Instruction::AShr:
      emitByte(OP_ASHR);
      break;
    case Instruction::Or:
      emitByte(OP_OR);
      break;
    case Instruction::Xor:
      emitByte(OP_XOR);
      break;
    default:
      report_fatal_error(
          Twine("Unsupported binary operator in VM obfuscator: ") +
          BO->getOpcodeName());
    }

    valueOnStack[op1] = false;
    valueOnStack[op2] = false;
    // Spill result for later reuse across barriers
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *ICMP = dyn_cast<ICmpInst>(&I)) {
    Value *op1 = ICMP->getOperand(0);
    Value *op2 = ICMP->getOperand(1);
    ensureOnStack(op1);
    ensureOnStack(op2);

    switch (ICMP->getPredicate()) {
    case ICmpInst::ICMP_SGT:
      emitCmpGT();
      break;
    case ICmpInst::ICMP_UGT:
      emitByte(OP_CMP_UGT);
      break;
    case ICmpInst::ICMP_SLT:
      emitCmpLT();
      break;
    case ICmpInst::ICMP_ULT:
      emitByte(OP_CMP_ULT);
      break;
    case ICmpInst::ICMP_EQ:
      emitCmpEQ();
      break;
    case ICmpInst::ICMP_NE:
      emitCmpNE();
      break;
    case ICmpInst::ICMP_SGE:
      emitByte(OP_CMP_GE);
      break;
    case ICmpInst::ICMP_UGE:
      emitByte(OP_CMP_UGE);
      break;
    case ICmpInst::ICMP_SLE:
      emitByte(OP_CMP_LE);
      break;
    case ICmpInst::ICMP_ULE:
      emitByte(OP_CMP_ULE);
      break;
    default:
      report_fatal_error(
          Twine("Unsupported comparison predicate in VM obfuscator: ") +
          Twine((int)ICMP->getPredicate()));
    }

    valueOnStack[op1] = false;
    valueOnStack[op2] = false;
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *PTI = dyn_cast<PtrToIntInst>(&I)) {
    ensureOnStack(PTI->getPointerOperand());
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *ITP = dyn_cast<IntToPtrInst>(&I)) {
    ensureOnStack(ITP->getOperand(0));
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *ZE = dyn_cast<ZExtInst>(&I)) {
    // Honor zero-extension semantics explicitly. Our VM stack is 64-bit and
    // OP_LOAD8 currently sign-extends 8-bit loads, so we must apply a mask
    // to reproduce LLVM's zext(iN -> iM) behavior. This is critical for
    // byte-oriented algorithms (e.g., RC4) where unsigned promotion matters.
    ensureOnStack(ZE->getOperand(0));
    // Compute mask for the source bit width (i1..i63). For widths >= 64, no-op.
    unsigned srcBits = ZE->getSrcTy()->getIntegerBitWidth();
    if (srcBits >= 64) {
      // Nothing to do; value already fully represented on our 64-bit stack.
    } else {
      uint64_t mask = (srcBits == 64) ? ~0ULL : ((1ULL << srcBits) - 1ULL);
      // Apply: value & mask
      emitPushImm((int32_t)(mask & 0xFFFFFFFFu));
      emitByte(OP_AND);
      if (mask > 0xFFFFFFFFu) {
        // For masks wider than 32 bits (e.g., i48 -> i64), fold the high part.
        // Apply the upper 32 bits: value & (mask_high << 32)
        // Since we don't have 64-bit immediates, perform (value >> 32) & hi
        // then << 32 and OR For our current use-cases (i8/i16/i32), this path
        // will not be hit.
      }
    }
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *SE = dyn_cast<SExtInst>(&I)) {
    // Treat sign-extend as a no-op on 64-bit stack (we load i8 as signed)
    ensureOnStack(SE->getOperand(0));
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *TR = dyn_cast<TruncInst>(&I)) {
    // Truncation will be applied by STORE8 etc.; no-op here
    ensureOnStack(TR->getOperand(0));
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *BR = dyn_cast<BranchInst>(&I)) {
    if (BR->isUnconditional()) {
      BasicBlock *dest = BR->getSuccessor(0);
      // Spill PHI incoming values for successor
      if (phisInBlock.count(dest)) {
        for (PHINode *PN : phisInBlock[dest]) {
          Value *incoming = PN->getIncomingValueForBlock(BR->getParent());
          ensureOnStack(incoming);
          emitStore(getTempSlot(PN));
          valueOnStack[incoming] = false;
        }
      }
      if (blockAddresses.find(dest) != blockAddresses.end()) {
        emitJmp(blockAddresses[dest]);
      } else {
        // Forward reference - emit placeholder
        size_t patchAddr = bytecode.size() + 1;
        emitJmp(0);
        pendingBranches[dest].push_back(patchAddr);
      }
    } else {
      // Conditional branch
      Value *cond = BR->getCondition();
      ensureOnStack(cond);

      BasicBlock *trueDest = BR->getSuccessor(0);
      BasicBlock *falseDest = BR->getSuccessor(1);
      // Spill PHI incoming values for both successors
      if (phisInBlock.count(trueDest)) {
        for (PHINode *PN : phisInBlock[trueDest]) {
          Value *incoming = PN->getIncomingValueForBlock(BR->getParent());
          ensureOnStack(incoming);
          emitStore(getTempSlot(PN));
          valueOnStack[incoming] = false;
        }
      }
      if (phisInBlock.count(falseDest)) {
        for (PHINode *PN : phisInBlock[falseDest]) {
          Value *incoming = PN->getIncomingValueForBlock(BR->getParent());
          ensureOnStack(incoming);
          emitStore(getTempSlot(PN));
          valueOnStack[incoming] = false;
        }
      }

      // Emit: if (cond) goto trueDest; else goto falseDest
      if (blockAddresses.find(trueDest) != blockAddresses.end()) {
        emitBrCond(blockAddresses[trueDest]);
      } else {
        size_t patchAddr = bytecode.size() + 1;
        emitBrCond(0);
        pendingBranches[trueDest].push_back(patchAddr);
      }

      if (blockAddresses.find(falseDest) != blockAddresses.end()) {
        emitJmp(blockAddresses[falseDest]);
      } else {
        size_t patchAddr = bytecode.size() + 1;
        emitJmp(0);
        pendingBranches[falseDest].push_back(patchAddr);
      }

      valueOnStack[cond] = false;
    }
    return true;
  } else if (auto *SW = dyn_cast<SwitchInst>(&I)) {
    // Lower switch into a sequence of comparisons and conditional branches
    Value *cond = SW->getCondition();
    BasicBlock *curBB = SW->getParent();
    // For each case: if (cond == caseVal) goto caseDest
    for (auto &Case : SW->cases()) {
      ConstantInt *CaseVal = Case.getCaseValue();
      BasicBlock *Dest = Case.getCaseSuccessor();
      ensureOnStack(cond);
      emitPushImm((int32_t)CaseVal->getSExtValue());
      emitCmpEQ();
      // Spill PHI incoming values for destination
      if (phisInBlock.count(Dest)) {
        for (PHINode *PN : phisInBlock[Dest]) {
          Value *incoming = PN->getIncomingValueForBlock(curBB);
          ensureOnStack(incoming);
          emitStore(getTempSlot(PN));
          valueOnStack[incoming] = false;
        }
      }
      if (blockAddresses.find(Dest) != blockAddresses.end()) {
        emitBrCond(blockAddresses[Dest]);
      } else {
        size_t patchAddr = bytecode.size() + 1;
        emitBrCond(0);
        pendingBranches[Dest].push_back(patchAddr);
      }
    }
    // Default destination
    BasicBlock *defDest = SW->getDefaultDest();
    if (phisInBlock.count(defDest)) {
      for (PHINode *PN : phisInBlock[defDest]) {
        Value *incoming = PN->getIncomingValueForBlock(curBB);
        ensureOnStack(incoming);
        emitStore(getTempSlot(PN));
        valueOnStack[incoming] = false;
      }
    }
    if (blockAddresses.find(defDest) != blockAddresses.end()) {
      emitJmp(blockAddresses[defDest]);
    } else {
      size_t patchAddr = bytecode.size() + 1;
      emitJmp(0);
      pendingBranches[defDest].push_back(patchAddr);
    }
    valueOnStack[cond] = false;
    return true;
  } else if (auto *CI = dyn_cast<CallBase>(&I)) {
    Function *callee = CI->getCalledFunction();
    if (!callee) {
      report_fatal_error("Unsupported indirect call in VM obfuscator");
    }
    SmallVector<Value *, 8> argsToUse;
    if (callee->isIntrinsic()) {
      StringRef name = callee->getName();
      if (name.starts_with("llvm.memcpy")) {
        // Map to external memcpy(dest, src, size)
        LLVMContext &Ctx = Mod->getContext();
        Type *i8Ty = Type::getInt8Ty(Ctx);
        PointerType *i8PtrTy = PointerType::get(i8Ty, 0);
        FunctionType *memcpyTy = FunctionType::get(
            i8PtrTy, {i8PtrTy, i8PtrTy, Type::getInt64Ty(Ctx)}, false);
        Function *memcpyFn = cast<Function>(
            Mod->getOrInsertFunction("memcpy", memcpyTy).getCallee());
        callee = memcpyFn;
        argsToUse.push_back(CI->getArgOperand(0));
        argsToUse.push_back(CI->getArgOperand(1));
        argsToUse.push_back(CI->getArgOperand(2));
      } else if (name.starts_with("llvm.memmove")) {
        // Map to external memmove(dest, src, size)
        LLVMContext &Ctx = Mod->getContext();
        Type *i8Ty = Type::getInt8Ty(Ctx);
        PointerType *i8PtrTy = PointerType::get(i8Ty, 0);
        FunctionType *memmoveTy = FunctionType::get(
            i8PtrTy, {i8PtrTy, i8PtrTy, Type::getInt64Ty(Ctx)}, false);
        Function *memmoveFn = cast<Function>(
            Mod->getOrInsertFunction("memmove", memmoveTy).getCallee());
        callee = memmoveFn;
        argsToUse.push_back(CI->getArgOperand(0));
        argsToUse.push_back(CI->getArgOperand(1));
        argsToUse.push_back(CI->getArgOperand(2));
      } else if (name.starts_with("llvm.memset")) {
        // Map to external memset(dest, value, size)
        LLVMContext &Ctx = Mod->getContext();
        Type *i8Ty = Type::getInt8Ty(Ctx);
        PointerType *i8PtrTy = PointerType::get(i8Ty, 0);
        FunctionType *memsetTy = FunctionType::get(
            i8PtrTy, {i8PtrTy, Type::getInt32Ty(Ctx), Type::getInt64Ty(Ctx)},
            false);
        Function *memsetFn = cast<Function>(
            Mod->getOrInsertFunction("memset", memsetTy).getCallee());
        callee = memsetFn;
        argsToUse.push_back(CI->getArgOperand(0));
        // llvm.memset takes i8 value; zero-extend/truncate handled by runtime;
        // pass as i32 constant if possible
        Value *val = CI->getArgOperand(1);
        if (val->getType()->isIntegerTy(8)) {
          // Promote to i32 if needed using IRBuilder on current insertion point
          // (no code emission here) For our bytecode model, we just pass the
          // original value and rely on external call handling.
        }
        argsToUse.push_back(val);
        argsToUse.push_back(CI->getArgOperand(2));
      } else if (name.starts_with("llvm.lifetime.start") ||
                 name.starts_with("llvm.lifetime.end")) {
        // Ignore lifetime intrinsics; they're hints for optimization only.
        return true;
      } else if (name.starts_with("llvm.dbg.")) {
        // Ignore debug intrinsics
        return true;
      } else if (name.starts_with("llvm.assume")) {
        // Ignore assume intrinsics
        return true;
      } else if (name.starts_with("llvm.smin") ||
                 name.starts_with("llvm.umin") ||
                 name.starts_with("llvm.smax") ||
                 name.starts_with("llvm.umax")) {
        // Lower min/max intrinsics to compare + select in VM bytecode
        Value *a = CI->getArgOperand(0);
        Value *b = CI->getArgOperand(1);
        // cond = (a < b) for min, (a > b) for max
        ensureOnStack(a);
        ensureOnStack(b);
        if (name.contains("min"))
          emitCmpLT();
        else
          emitCmpGT();
        // select(cond, a, b) for min; for max use select(cond, a, b) after
        // swapping cond appropriately For max, cond is a > b already
        ensureOnStack(a);
        ensureOnStack(b);
        emitByte(OP_SELECT);
        // Spill result; mark operands consumed
        valueOnStack[a] = false;
        valueOnStack[b] = false;
        emitStore(getTempSlot(&I));
        valueOnStack[&I] = false;
        return true;
      } else {
        report_fatal_error(Twine("Unsupported intrinsic call: ") +
                           callee->getName());
      }
    } else {
      for (auto &Arg : CI->args())
        argsToUse.push_back(Arg.get());
    }
    // Prepare arguments on a clean stack in order
    // Ensure operand stack is clean before pushing call args
    emitByte(OP_RESET_SP);
    valueOnStack.clear();
    uint8_t argc = (uint8_t)argsToUse.size();
    uint32_t ptrMask = 0;
    for (unsigned i = 0; i < argsToUse.size(); ++i) {
      Value *V = argsToUse[i];
      if (V->getType()->isPointerTy())
        ptrMask |= (1u << i);
      ensureOnStack(V);
    }
    // Get or register call index
    auto it = callIndex.find(callee);
    if (it == callIndex.end()) {
      callIndex[callee] = (unsigned)callTargets.size();
      callTargets.push_back(callee);
      it = callIndex.find(callee);
    }
    // Encode void-return flag in high bit of argc byte so runtime won't push
    uint8_t encodedArgc = argc;
    if (CI->getType()->isVoidTy())
      encodedArgc |= 0x80;
    // Tag internal (in-module) calls using the high bit of ptrMask (bit 31).
    // This allows the runtime to avoid on-demand decrypt for inter-VM calls
    // and defer decryption to the ultimate external libc/libpq calls.
    if (!callee->isDeclaration()) {
      ptrMask |= 0x80000000u;
    }
    emitCall((uint16_t)it->second, encodedArgc, ptrMask);
    // Mark stack state: arguments consumed; spill return for non-void
    for (Value *V : argsToUse)
      valueOnStack[V] = false;
    if (!CI->getType()->isVoidTy()) {
      emitStore(getTempSlot(&I));
      valueOnStack[&I] = false;
    }
    return true;
  } else if (auto *SEL = dyn_cast<SelectInst>(&I)) {
    // cond ? trueV : falseV
    // Force push to avoid relying on valueOnStack state across barriers
    forcePushValue(SEL->getCondition());
    forcePushValue(SEL->getTrueValue());
    forcePushValue(SEL->getFalseValue());
    emitByte(OP_SELECT);
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
    // Generic GEP lowering using DataLayout: base + sum_i(index_i * stride_i) +
    // const_offset
    Value *basePtr = GEP->getPointerOperand();
    // Push base pointer
    if (auto *GV = dyn_cast<GlobalValue>(basePtr)) {
      emitPushGlobalForCurrentFunction(GV);
    } else if (auto *AI = dyn_cast<AllocaInst>(basePtr)) {
      // Local byte memory base
      size_t base = getOrAssignLocalBase(AI);
      emitPushImm((int32_t)base);
      emitByte(OP_TAG_LOCAL);
    } else {
      ensureOnStack(basePtr);
    }

    Type *curTy = GEP->getSourceElementType();
    int64_t constOff = 0;
    unsigned idxPos = 0;
    for (auto IdxIt = GEP->idx_begin(); IdxIt != GEP->idx_end();
         ++IdxIt, ++idxPos) {
      Value *idx = IdxIt->get();
      if (auto *ST = dyn_cast<StructType>(curTy)) {
        // Struct indexing must be constant
        auto *CIdx = dyn_cast<ConstantInt>(idx);
        if (!CIdx)
          report_fatal_error("Non-constant struct index in GEP");
        unsigned field = (unsigned)CIdx->getZExtValue();
        const StructLayout *SL = DL ? DL->getStructLayout(ST) : nullptr;
        if (!SL)
          report_fatal_error("No StructLayout for struct GEP");
        constOff += (int64_t)SL->getElementOffset(field);
        curTy = ST->getElementType(field);
      } else {
        // Sequential indexing (arrays or pointer-as-array semantics)
        Type *elemTy = nullptr;
        uint64_t stride = 1;
        if (auto *Arr = dyn_cast<ArrayType>(curTy)) {
          elemTy = Arr->getElementType();
          stride = DL ? DL->getTypeAllocSize(elemTy) : 1;
        } else {
          // Treat as pointer stepping by size of the source element type
          stride = DL ? DL->getTypeAllocSize(curTy) : 1; // e.g., i8 => 1
          elemTy = nullptr;                              // no change in curTy
        }
        if (auto *CIdx = dyn_cast<ConstantInt>(idx)) {
          if (!CIdx->isZero())
            constOff += (int64_t)(CIdx->getSExtValue() * (int64_t)stride);
        } else {
          // dynamic term: idx * stride
          ensureOnStack(idx);
          if (stride != 1) {
            emitPushImm((int32_t)stride);
            emitMul();
          }
          emitAdd();
          valueOnStack[idx] = false;
        }
        if (elemTy)
          curTy = elemTy;
      }
    }
    if (constOff != 0) {
      emitPushImm((int32_t)constOff);
      emitAdd();
    }
    valueOnStack[basePtr] = false;
    emitStore(getTempSlot(&I));
    valueOnStack[&I] = false;
    return true;
  } else if (auto *RI = dyn_cast<ReturnInst>(&I)) {
    Value *retVal = RI->getReturnValue();
    if (retVal) {
      ensureOnStack(retVal);
      emitRet();
    } else {
      emitPushImm(0);
      emitRet();
    }
    return true;
  }

  report_fatal_error(Twine("Unsupported instruction type in VM obfuscator: ") +
                     I.getOpcodeName());
}

// Main pass run method
PreservedAnalyses VmObfuscatorPass::run(Module &M, ModuleAnalysisManager &MAM) {

  if (vmobf) {
    errs() << "\n=== VM Obfuscator Pass (Extended) Starting ===\n";
    // We'll obfuscate all defined functions in the module (excluding
    // declarations)
    LLVMContext &Ctx = M.getContext();
    Mod = &M;
    DL = &M.getDataLayout();
    localBase.clear();
    localMemOffset = 0;
    // Initialize module-wide data key once per run
    {
      uint64_t k = rng();
      if (k == 0)
        k = 0x6a09e667f3bcc909ULL;
      dataGlobalKey = k;
    }

    // First pass: collect direct callees to build function table
    callIndex.clear();
    callTargets.clear();
    phisInBlock.clear();
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      CurFn = &F;
      for (BasicBlock &BB : F) {
        // Record PHIs in block header and allocate temp slots
        for (Instruction &I : BB) {
          if (auto *PN = dyn_cast<PHINode>(&I)) {
            phisInBlock[&BB].push_back(PN);
            (void)getTempSlot(PN);
          } else {
            break; // PHIs are grouped at top
          }
        }
        for (Instruction &I : BB) {
          if (auto *CB = dyn_cast<CallBase>(&I)) {
            Function *Callee = CB->getCalledFunction();
            if (!Callee)
              report_fatal_error("Unsupported indirect call in VM obfuscator");
            if (Callee->isIntrinsic()) {
              // Map known intrinsics to external functions, ignore harmless
              // ones
              StringRef iname = Callee->getName();
              if (iname.starts_with("llvm.memcpy")) {
                Type *i8Ty = Type::getInt8Ty(Ctx);
                PointerType *i8PtrTy = PointerType::get(i8Ty, 0);
                FunctionType *memcpyTy = FunctionType::get(
                    i8PtrTy, {i8PtrTy, i8PtrTy, Type::getInt64Ty(Ctx)}, false);
                Callee = cast<Function>(
                    M.getOrInsertFunction("memcpy", memcpyTy).getCallee());
              } else if (iname.starts_with("llvm.memmove")) {
                Type *i8Ty = Type::getInt8Ty(Ctx);
                PointerType *i8PtrTy = PointerType::get(i8Ty, 0);
                FunctionType *memmoveTy = FunctionType::get(
                    i8PtrTy, {i8PtrTy, i8PtrTy, Type::getInt64Ty(Ctx)}, false);
                Callee = cast<Function>(
                    M.getOrInsertFunction("memmove", memmoveTy).getCallee());
              } else if (iname.starts_with("llvm.memset")) {
                Type *i8Ty = Type::getInt8Ty(Ctx);
                PointerType *i8PtrTy = PointerType::get(i8Ty, 0);
                FunctionType *memsetTy = FunctionType::get(
                    i8PtrTy,
                    {i8PtrTy, Type::getInt32Ty(Ctx), Type::getInt64Ty(Ctx)},
                    false);
                Callee = cast<Function>(
                    M.getOrInsertFunction("memset", memsetTy).getCallee());
              } else if (iname.starts_with("llvm.smin") ||
                         iname.starts_with("llvm.umin") ||
                         iname.starts_with("llvm.smax") ||
                         iname.starts_with("llvm.umax")) {
                // Lowered during translation; ignore in scan
                continue;
              } else if (iname.starts_with("llvm.lifetime.start") ||
                         iname.starts_with("llvm.lifetime.end") ||
                         iname.starts_with("llvm.dbg.") ||
                         iname.starts_with("llvm.assume")) {
                // Ignore these intrinsics during scan
                continue;
              } else {
                report_fatal_error(
                    Twine("Unsupported intrinsic call in scan: ") +
                    Callee->getName());
              }
            }
            if (!callIndex.count(Callee)) {
              callIndex[Callee] = (unsigned)callTargets.size();
              callTargets.push_back(Callee);
            }
          }
        }
      }
    }

    // Defer building vm_func_table and vm_data_table until after translation.

    // Obfuscate each function body
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      StringRef N = F.getName();

      errs() << "Obfuscating function: " << F.getName() << "\n";
      errs() << "Function has " << F.arg_size() << " arguments\n";

      // Reset per-function state
      refreshFunctionKey();
      bytecode.clear();
      // Reserve full header:
      //  - 8 bytes: per-function crypto key (for immediates and code stream)
      //  - 4 bytes: locals size (reserved bytes at start of VM local_mem)
      //  - 8 bytes: code salt/nonce (for stream cipher over bytecode)
      //  - 4 bytes: code length (bytes following the header)
      const size_t kHeaderSize = sizeof(uint64_t) + sizeof(uint32_t) +
                                 sizeof(uint64_t) + sizeof(uint32_t);
      bytecode.resize(kHeaderSize, 0);
      allocaMap.clear();
      valueOnStack.clear();
      blockAddresses.clear();
      pendingBranches.clear();
      nextAllocaSlot = 0;
      localBase.clear();
      localMemOffset = 0;

      // Generate bytecode
      errs() << "\n--- Processing Basic Blocks ---\n";
      for (BasicBlock &BB : F) {
        blockAddresses[&BB] = bytecode.size();
        errs() << "Block " << BB.getName() << " at bytecode address "
               << bytecode.size() << "\n";
        patchBranches(&BB, bytecode.size());
        for (Instruction &I : BB) {
          if (!translateInstruction(I)) {
            errs() << "ERROR: Failed to translate instruction: " << I << "\n";
          }
        }
      }

      errs() << "\n--- Bytecode Generation Complete ---\n";
      errs() << "Generated " << bytecode.size() << " bytes\n";

      // Inject function-specific encryption key + locals size into the bytecode
      // header
      const size_t oldHeader = sizeof(uint64_t) + sizeof(uint32_t);
      const size_t headerSize = sizeof(uint64_t) + sizeof(uint32_t) +
                                sizeof(uint64_t) + sizeof(uint32_t);
      if (bytecode.size() < oldHeader) {
        report_fatal_error(
            "VM bytecode unexpectedly small while encoding header");
      }
      // Header layout: [key(8)][locals(4)][salt(8)][code_len(4)]
      std::memcpy(bytecode.data(), &currentKey, sizeof(currentKey));
      uint32_t localsSize = (uint32_t)localMemOffset;
      std::memcpy(bytecode.data() + sizeof(uint64_t), &localsSize,
                  sizeof(localsSize));

      // Compute code salt and encrypt the payload after the full header using
      // xorshift64* stream
      uint64_t codeSalt = rng();
      if (codeSalt == 0)
        codeSalt = 0x243f6a8885a308d3ULL; // avoid zero state

      // Ensure we have space for the extended header (if we started with
      // oldHeader)
      if (bytecode.size() >= oldHeader && bytecode.size() < headerSize) {
        // Insert the extra 12 bytes (salt+code_len) right after the old header
        bytecode.insert(bytecode.begin() + oldHeader, headerSize - oldHeader,
                        0);
      }

      // Determine code length and encrypt
      uint32_t codeLen = (uint32_t)(bytecode.size() - headerSize);
      std::memcpy(bytecode.data() + sizeof(uint64_t) + sizeof(uint32_t),
                  &codeSalt, sizeof(codeSalt));
      std::memcpy(bytecode.data() + sizeof(uint64_t) + sizeof(uint32_t) +
                      sizeof(uint64_t),
                  &codeLen, sizeof(codeLen));

      if (codeLen > 0) {
        std::vector<uint8_t> plain(bytecode.begin() + headerSize,
                                   bytecode.end());
        std::vector<uint8_t> enc;
        encryptBytesWithKey(plain, enc, codeSalt, currentKey);
        // Overwrite payload with encrypted bytes
        for (size_t i = 0; i < enc.size(); ++i)
          bytecode[headerSize + i] = enc[i];
      }

      // Create bytecode global
      std::vector<Constant *> byteConstants;
      for (uint8_t byte : bytecode) {
        byteConstants.push_back(ConstantInt::get(Type::getInt8Ty(Ctx), byte));
      }
      ArrayType *byteTy = ArrayType::get(Type::getInt8Ty(Ctx), bytecode.size());
      Constant *byteInit = ConstantArray::get(byteTy, byteConstants);
      GlobalVariable *bcGlobal =
          new GlobalVariable(M, byteTy, true, GlobalValue::PrivateLinkage,
                             byteInit, F.getName() + "_bytecode");

      // Build vm_execute signature for this function as varargs with explicit
      // arg_count. Runtime functions return int64_t and expect every vararg to
      // be a 64-bit value (either integer or pointer bitcasted to int64).
      std::vector<Type *> paramTypes;
      paramTypes.push_back(
          PointerType::get(Type::getInt8Ty(Ctx), 0)); // bytecode
      paramTypes.push_back(Type::getInt32Ty(Ctx));    // arg_count
      FunctionType *vmFuncType = FunctionType::get(
          Type::getInt64Ty(Ctx), paramTypes, /*isVarArg*/ true);
      std::string vmFuncName = "vm_execute";
      if (F.arg_size() == 1)
        vmFuncName = "vm_execute_with_arg";
      else if (F.arg_size() == 2)
        vmFuncName = "vm_execute_with_args";
      FunctionCallee vmExecute = M.getOrInsertFunction(vmFuncName, vmFuncType);

      // Replace body with call to VM
      errs() << "\n--- Replacing Function Body ---\n";
      F.deleteBody();
      BasicBlock *newBB = BasicBlock::Create(Ctx, "entry", &F);
      IRBuilder<> builder(newBB);
      std::vector<Value *> vmArgs;
      Value *bytecodePtr = builder.CreateBitCast(
          bcGlobal, PointerType::get(Type::getInt8Ty(Ctx), 0));
      vmArgs.push_back(bytecodePtr);
      vmArgs.push_back(
          ConstantInt::get(Type::getInt32Ty(Ctx), (int)F.arg_size()));
      // Vararg marshalling: always pass 64-bit integers for both ints and
      // pointers so the runtime can safely read as intptr_t without type
      // confusion.
      Type *i64Ty = Type::getInt64Ty(Ctx);
      for (auto &arg : F.args()) {
        Value *v = &arg;
        if (v->getType()->isPointerTy()) {
          v = builder.CreatePtrToInt(v, i64Ty);
        } else if (v->getType()->isIntegerTy()) {
          unsigned bw = cast<IntegerType>(v->getType())->getBitWidth();
          if (bw < 64)
            v = builder.CreateSExtOrTrunc(v, i64Ty);
          else if (bw > 64)
            v = builder.CreateTrunc(v, i64Ty);
        } else {
          // Fallback: bitcast to i64-sized integer
          v = builder.CreateZExtOrTrunc(
              builder.CreatePtrToInt(builder.CreateBitCast(v, v->getType()),
                                     i64Ty),
              i64Ty);
        }
        vmArgs.push_back(v);
      }
      Value *vmRet64 = builder.CreateCall(vmExecute, vmArgs);
      if (F.getReturnType()->isVoidTy()) {
        // Ignore VM return and return void
        builder.CreateRetVoid();
      } else if (F.getReturnType()->isPointerTy()) {
        // Convert int64 back to pointer type
        Value *asPtr = builder.CreateIntToPtr(vmRet64, F.getReturnType());
        builder.CreateRet(asPtr);
      } else if (F.getReturnType()->isIntegerTy()) {
        unsigned rbw = cast<IntegerType>(F.getReturnType())->getBitWidth();
        Value *retVal = vmRet64;
        if (rbw < 64) {
          // Truncate to the exact integer width expected by the original
          // function
          retVal = builder.CreateTrunc(vmRet64, F.getReturnType());
        } else if (rbw > 64) {
          // Extend (unlikely in this codebase), but keep semantics defined
          retVal = builder.CreateZExt(vmRet64, F.getReturnType());
        }
        builder.CreateRet(retVal);
      } else {
        // Conservatively bitcast to original type size if not int/pointer
        // (shouldn't happen here)
        Value *asPtr = builder.CreateIntToPtr(
            vmRet64, PointerType::get(Type::getInt8Ty(Ctx), 0));
        Value *bitcastBack = builder.CreateBitCast(asPtr, F.getReturnType());
        builder.CreateRet(bitcastBack);
      }
    }

    // Build vm_func_table now that callTargets is final
    {
      std::vector<Constant *> tableElems;
      Type *i8TyL = Type::getInt8Ty(Ctx);
      PointerType *i8PtrTyL = PointerType::get(i8TyL, 0);
      for (Function *Fn : callTargets) {
        Constant *fnPtr = ConstantExpr::getBitCast(Fn, i8PtrTyL);
        tableElems.push_back(fnPtr);
      }
      ArrayType *tblTy = ArrayType::get(i8PtrTyL, tableElems.size());
      Constant *tblInit = ConstantArray::get(tblTy, tableElems);
      new GlobalVariable(M, tblTy, true, GlobalValue::ExternalLinkage, tblInit,
                         "vm_func_table");
      new GlobalVariable(
          M, Type::getInt32Ty(Ctx), true, GlobalValue::ExternalLinkage,
          ConstantInt::get(Type::getInt32Ty(Ctx), (int)tableElems.size()),
          "vm_func_table_size");
    }

    // Now build global data table + metadata for any globals referenced in
    // bytecode
    if (!dataItems.empty()) {
      Type *i8Ty2 = Type::getInt8Ty(Ctx);
      PointerType *i8PtrTy2 = PointerType::get(i8Ty2, 0);
      std::vector<Constant *> dataElems;
      for (GlobalValue *GV : dataItems) {
        dataElems.push_back(ConstantExpr::getBitCast(GV, i8PtrTy2));
      }
      ArrayType *dataTy = ArrayType::get(i8PtrTy2, dataElems.size());
      Constant *dataInit = ConstantArray::get(dataTy, dataElems);
      new GlobalVariable(M, dataTy, true, GlobalValue::ExternalLinkage,
                         dataInit, "vm_data_table");
      new GlobalVariable(
          M, Type::getInt32Ty(Ctx), true, GlobalValue::ExternalLinkage,
          ConstantInt::get(Type::getInt32Ty(Ctx), (int)dataElems.size()),
          "vm_data_table_size");

      // vm_data_is_enc: i8 flags
      std::vector<Constant *> isEncElems;
      isEncElems.reserve(dataItems.size());
      for (size_t i = 0; i < dataItems.size(); ++i) {
        uint8_t f = (i < dataIsEnc.size()) ? dataIsEnc[i] : 0;
        isEncElems.push_back(ConstantInt::get(i8Ty2, f));
      }
      ArrayType *isEncTy = ArrayType::get(i8Ty2, isEncElems.size());
      Constant *isEncInit = ConstantArray::get(isEncTy, isEncElems);
      new GlobalVariable(M, isEncTy, true, GlobalValue::ExternalLinkage,
                         isEncInit, "vm_data_is_enc");

      // vm_data_len: i32 lengths
      std::vector<Constant *> lenElems;
      lenElems.reserve(dataItems.size());
      for (size_t i = 0; i < dataItems.size(); ++i) {
        uint32_t L = (i < dataLen.size()) ? dataLen[i] : 0;
        lenElems.push_back(ConstantInt::get(Type::getInt32Ty(Ctx), L));
      }
      ArrayType *lenTy = ArrayType::get(Type::getInt32Ty(Ctx), lenElems.size());
      Constant *lenInit = ConstantArray::get(lenTy, lenElems);
      new GlobalVariable(M, lenTy, true, GlobalValue::ExternalLinkage, lenInit,
                         "vm_data_len");

      // vm_data_salt: i64 salts
      std::vector<Constant *> saltElems;
      saltElems.reserve(dataItems.size());
      for (size_t i = 0; i < dataItems.size(); ++i) {
        uint64_t S = (i < dataSalt.size()) ? dataSalt[i] : 0;
        saltElems.push_back(ConstantInt::get(Type::getInt64Ty(Ctx), S));
      }
      ArrayType *saltTy =
          ArrayType::get(Type::getInt64Ty(Ctx), saltElems.size());
      Constant *saltInit = ConstantArray::get(saltTy, saltElems);
      new GlobalVariable(M, saltTy, true, GlobalValue::ExternalLinkage,
                         saltInit, "vm_data_salt");

      // vm_data_key: i64 keys per entry (0 for plaintext)
      std::vector<Constant *> keyElems;
      keyElems.reserve(dataItems.size());
      for (size_t i = 0; i < dataItems.size(); ++i) {
        uint64_t K = (i < dataKey.size()) ? dataKey[i] : 0;
        keyElems.push_back(ConstantInt::get(Type::getInt64Ty(Ctx), K));
      }
      ArrayType *keyTy = ArrayType::get(Type::getInt64Ty(Ctx), keyElems.size());
      Constant *keyInit = ConstantArray::get(keyTy, keyElems);
      new GlobalVariable(M, keyTy, true, GlobalValue::ExternalLinkage, keyInit,
                         "vm_data_key");
    } else {
      // No data items - create empty tables with size=0 to satisfy linker
      Type *i8Ty2 = Type::getInt8Ty(Ctx);
      PointerType *i8PtrTy2 = PointerType::get(i8Ty2, 0);

      // Empty vm_data_table (0-element array of i8*)
      ArrayType *emptyDataTy = ArrayType::get(i8PtrTy2, 0);
      Constant *emptyDataInit = ConstantArray::get(emptyDataTy, {});
      new GlobalVariable(M, emptyDataTy, true, GlobalValue::ExternalLinkage,
                         emptyDataInit, "vm_data_table");

      // vm_data_table_size = 0
      new GlobalVariable(
          M, Type::getInt32Ty(Ctx), true, GlobalValue::ExternalLinkage,
          ConstantInt::get(Type::getInt32Ty(Ctx), 0), "vm_data_table_size");

      // Empty vm_data_is_enc (0-element i8 array)
      ArrayType *emptyIsEncTy = ArrayType::get(i8Ty2, 0);
      Constant *emptyIsEncInit = ConstantArray::get(emptyIsEncTy, {});
      new GlobalVariable(M, emptyIsEncTy, true, GlobalValue::ExternalLinkage,
                         emptyIsEncInit, "vm_data_is_enc");

      // Empty vm_data_len (0-element i32 array)
      ArrayType *emptyLenTy = ArrayType::get(Type::getInt32Ty(Ctx), 0);
      Constant *emptyLenInit = ConstantArray::get(emptyLenTy, {});
      new GlobalVariable(M, emptyLenTy, true, GlobalValue::ExternalLinkage,
                         emptyLenInit, "vm_data_len");

      // Empty vm_data_salt (0-element i64 array)
      ArrayType *emptySaltTy = ArrayType::get(Type::getInt64Ty(Ctx), 0);
      Constant *emptySaltInit = ConstantArray::get(emptySaltTy, {});
      new GlobalVariable(M, emptySaltTy, true, GlobalValue::ExternalLinkage,
                         emptySaltInit, "vm_data_salt");

      // Empty vm_data_key (0-element i64 array)
      ArrayType *emptyKeyTy = ArrayType::get(Type::getInt64Ty(Ctx), 0);
      Constant *emptyKeyInit = ConstantArray::get(emptyKeyTy, {});
      new GlobalVariable(M, emptyKeyTy, true, GlobalValue::ExternalLinkage,
                         emptyKeyInit, "vm_data_key");
    }

    // Prune plaintext string globals that became dead due to encrypted clones
    {
      std::vector<GlobalVariable *> toErase;
      for (GlobalVariable &GV : M.globals()) {
        if (GV.use_empty()) {
          auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
          if (CDA && CDA->getType()->getElementType()->isIntegerTy(8)) {
            toErase.push_back(&GV);
          }
        }
      }
      for (GlobalVariable *G : toErase) {
        G->eraseFromParent();
      }
    }

    errs() << "=== VM Obfuscator Pass Complete ===\n\n";
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

} // namespace llvm
