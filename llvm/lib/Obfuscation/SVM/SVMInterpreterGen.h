// SVMInterpreterGen.h - LLVM 18 adapted
// Inline VM interpreter generator using LLVM IR Builder
// Generates complete vm_exec() function at compile time

#pragma once

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/ADT/StringRef.h"

namespace svm {

// Opcodes (must match VMCodeGen.h)
enum : uint8_t {
  OP_ALLOCA   = 0x01,
  OP_LOAD     = 0x02,
  OP_STORE    = 0x03,
  OP_GEP      = 0x05,
  OP_CMP      = 0x06,
  OP_CAST     = 0x07,
  OP_BR       = 0x08,
  OP_CALL     = 0x09,
  OP_RET      = 0x0A,
  OP_ARITH    = 0x10,
  OP_PARAMMAP = 0x11,
  OP_SELECT   = 0x12,
  OP_GEP_SCALED = 0x13
};

// Value encoding
enum : uint8_t { VT_CONST = 0, VT_SLOT = 1 };
enum : uint8_t { CK_INT = 0, CK_PTR = 1, CK_F32 = 2, CK_F64 = 3 };

// Arithmetic sub-ops
enum : uint8_t {
  AR_ADD, AR_SUB, AR_MUL,
  AR_UDIV, AR_SDIV, AR_UREM, AR_SREM,
  AR_SHL, AR_LSHR, AR_ASHR,
  AR_AND, AR_OR, AR_XOR,
  AR_FADD, AR_FSUB, AR_FMUL, AR_FDIV, AR_FREM
};

// Type kinds
enum : uint8_t { TK_INT = 0, TK_FP = 1 };

// CmpInst predicates (LLVM aligned)
enum {
  FCMP_FALSE = 0, FCMP_OEQ, FCMP_OGT, FCMP_OGE, FCMP_OLT, FCMP_OLE, FCMP_ONE, FCMP_ORD,
  FCMP_UNO, FCMP_UEQ, FCMP_UGT, FCMP_UGE, FCMP_ULT, FCMP_ULE, FCMP_UNE, FCMP_TRUE,
  ICMP_EQ = 32, ICMP_NE, ICMP_UGT, ICMP_UGE, ICMP_ULT, ICMP_ULE,
  ICMP_SGT, ICMP_SGE, ICMP_SLT, ICMP_SLE
};

// Cast opcodes
enum {
  Cast_Trunc = 1, Cast_ZExt, Cast_SExt, Cast_FPToUI, Cast_FPToSI, Cast_UIToFP, Cast_SIToFP,
  Cast_FPTrunc, Cast_FPExt, Cast_PtrToInt, Cast_IntToPtr, Cast_BitCast, Cast_AddrSpaceCast
};

/// SVMInterpreterGen - Generates vm_exec interpreter function in LLVM IR
class SVMInterpreterGen {
public:
  SVMInterpreterGen(llvm::Module &M) : M(M), Ctx(M.getContext()) {
    // Cache types
    VoidTy = llvm::Type::getVoidTy(Ctx);
    I1Ty = llvm::Type::getInt1Ty(Ctx);
    I8Ty = llvm::Type::getInt8Ty(Ctx);
    I32Ty = llvm::Type::getInt32Ty(Ctx);
    I64Ty = llvm::Type::getInt64Ty(Ctx);
    F32Ty = llvm::Type::getFloatTy(Ctx);
    F64Ty = llvm::Type::getDoubleTy(Ctx);
    PtrTy = llvm::PointerType::get(Ctx, 0);
  }

  /// Generate or get vm_exec function
  /// Signature: uint64_t vm_exec(const uint8_t* code, uint32_t size, void** args, uint64_t num)
  llvm::Function* getOrCreateVMExec() {
    // Check if already exists
    if (auto *F = M.getFunction("vm_exec")) {
      if (!F->empty()) return F;  // Already has body
    }

    // Create function with InternalLinkage
    // Each translation unit has its own vm_exec + handle_call pair
    // This avoids cross-unit linkage issues with handle_call dispatch
    auto *FT = llvm::FunctionType::get(I64Ty, {PtrTy, I32Ty, PtrTy, I64Ty}, false);
    auto *F = llvm::Function::Create(FT, llvm::GlobalValue::InternalLinkage, "vm_exec", &M);
    F->setDoesNotThrow();

    // Name arguments
    auto AI = F->arg_begin();
    llvm::Argument *ArgCode = &*AI++; ArgCode->setName("code");
    llvm::Argument *ArgSize = &*AI++; ArgSize->setName("size");
    llvm::Argument *ArgArgs = &*AI++; ArgArgs->setName("args");
    llvm::Argument *ArgNum = &*AI++;  ArgNum->setName("num");

    // Generate body
    generateBody(F, ArgCode, ArgSize, ArgArgs, ArgNum);

    return F;
  }

private:
  llvm::Module &M;
  llvm::LLVMContext &Ctx;

  // Cached types
  llvm::Type *VoidTy, *I1Ty, *I8Ty, *I32Ty, *I64Ty, *F32Ty, *F64Ty, *PtrTy;

  // Runtime function declarations
  llvm::FunctionCallee getMalloc() {
    return M.getOrInsertFunction("malloc", PtrTy, I64Ty);
  }

  llvm::FunctionCallee getRealloc() {
    return M.getOrInsertFunction("realloc", PtrTy, PtrTy, I64Ty);
  }

  llvm::FunctionCallee getFree() {
    return M.getOrInsertFunction("free", VoidTy, PtrTy);
  }

  llvm::FunctionCallee getMemcpy() {
    return M.getOrInsertFunction("memcpy", PtrTy, PtrTy, PtrTy, I64Ty);
  }

  llvm::FunctionCallee getMemset() {
    return M.getOrInsertFunction("memset", PtrTy, PtrTy, I32Ty, I64Ty);
  }

  llvm::FunctionCallee getHandleCall() {
    // uint64_t handle_call(uint64_t id, void** args, uint64_t num)
    auto *FT = llvm::FunctionType::get(I64Ty, {I64Ty, PtrTy, I64Ty}, false);
    return M.getOrInsertFunction("handle_call", FT);
  }

  void generateBody(llvm::Function *F,
                    llvm::Argument *ArgCode,
                    llvm::Argument *ArgSize,
                    llvm::Argument *ArgArgs,
                    llvm::Argument *ArgNum) {
    using namespace llvm;

    // Create entry block
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> B(Entry);

    // Allocate locals
    // DataSeg: buf (ptr), sz (i32), cap (i32)
    Value *DsBuf = B.CreateAlloca(PtrTy, nullptr, "ds.buf");
    Value *DsSz = B.CreateAlloca(I32Ty, nullptr, "ds.sz");
    Value *DsCap = B.CreateAlloca(I32Ty, nullptr, "ds.cap");
    Value *RetVal = B.CreateAlloca(I64Ty, nullptr, "ret_val");

    // Pointer variables
    Value *CodePtr = B.CreateAlloca(PtrTy, nullptr, "p");
    Value *EndPtr = B.CreateAlloca(PtrTy, nullptr, "end");

    // Initialize
    B.CreateStore(ConstantPointerNull::get(cast<PointerType>(PtrTy)), DsBuf);
    B.CreateStore(ConstantInt::get(I32Ty, 0), DsSz);
    B.CreateStore(ConstantInt::get(I32Ty, 0), DsCap);
    B.CreateStore(ConstantInt::get(I64Ty, 0), RetVal);
    B.CreateStore(ArgCode, CodePtr);

    // end = code + size
    Value *End = B.CreateGEP(I8Ty, ArgCode, B.CreateZExt(ArgSize, I64Ty), "end.calc");
    B.CreateStore(End, EndPtr);

    // Main loop
    BasicBlock *LoopHeader = BasicBlock::Create(Ctx, "loop.header", F);
    BasicBlock *LoopBody = BasicBlock::Create(Ctx, "loop.body", F);
    BasicBlock *ExitBlock = BasicBlock::Create(Ctx, "exit", F);

    B.CreateBr(LoopHeader);

    // Loop header: check p < end
    B.SetInsertPoint(LoopHeader);
    Value *P = B.CreateLoad(PtrTy, CodePtr, "p.load");
    Value *E = B.CreateLoad(PtrTy, EndPtr, "end.load");
    Value *Cond = B.CreateICmpULT(P, E, "loop.cond");
    B.CreateCondBr(Cond, LoopBody, ExitBlock);

    // Loop body: read opcode and dispatch
    B.SetInsertPoint(LoopBody);

    // Read opcode
    P = B.CreateLoad(PtrTy, CodePtr, "p.cur");
    Value *Opcode = B.CreateLoad(I8Ty, P, "opcode");
    Value *PNext = B.CreateGEP(I8Ty, P, ConstantInt::get(I64Ty, 1));
    B.CreateStore(PNext, CodePtr);

    // Create switch for opcodes
    BasicBlock *DefaultBB = BasicBlock::Create(Ctx, "op.default", F);
    SwitchInst *Sw = B.CreateSwitch(Opcode, DefaultBB, 14);

    // Generate handlers for each opcode
    generateOpParamMap(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, ArgArgs, ArgNum, LoopHeader);
    generateOpAlloca(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);
    generateOpLoad(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);
    generateOpStore(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);
    generateOpGep(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);
    generateOpCmp(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);
    generateOpCast(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);
    generateOpBr(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, ArgCode, LoopHeader, ExitBlock);
    generateOpArith(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);
    generateOpCall(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);
    generateOpRet(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, RetVal, ExitBlock);
    generateOpSelect(F, Sw, CodePtr, EndPtr, DsBuf, DsSz, DsCap, LoopHeader);

    // Default: go to exit
    IRBuilder<> BD(DefaultBB);
    BD.CreateBr(ExitBlock);

    // Exit block: cleanup and return
    B.SetInsertPoint(ExitBlock);
    Value *BufToFree = B.CreateLoad(PtrTy, DsBuf);
    B.CreateCall(getFree(), {BufToFree});
    Value *Ret = B.CreateLoad(I64Ty, RetVal);
    B.CreateRet(Ret);
  }

  // Helper: read u8 from bytecode
  llvm::Value* readU8(llvm::IRBuilder<> &B, llvm::Value *CodePtr, llvm::Value *EndPtr) {
    using namespace llvm;
    Value *P = B.CreateLoad(PtrTy, CodePtr);
    Value *V = B.CreateLoad(I8Ty, P);
    Value *PNext = B.CreateGEP(I8Ty, P, ConstantInt::get(I64Ty, 1));
    B.CreateStore(PNext, CodePtr);
    return V;
  }

  // Helper: read u32 from bytecode (little endian)
  llvm::Value* readU32(llvm::IRBuilder<> &B, llvm::Value *CodePtr, llvm::Value *EndPtr) {
    using namespace llvm;
    Value *P = B.CreateLoad(PtrTy, CodePtr);
    // Read 4 bytes and combine (little endian)
    Value *B0 = B.CreateLoad(I8Ty, P);
    Value *B1 = B.CreateLoad(I8Ty, B.CreateGEP(I8Ty, P, ConstantInt::get(I64Ty, 1)));
    Value *B2 = B.CreateLoad(I8Ty, B.CreateGEP(I8Ty, P, ConstantInt::get(I64Ty, 2)));
    Value *B3 = B.CreateLoad(I8Ty, B.CreateGEP(I8Ty, P, ConstantInt::get(I64Ty, 3)));

    Value *V = B.CreateZExt(B0, I32Ty);
    V = B.CreateOr(V, B.CreateShl(B.CreateZExt(B1, I32Ty), 8));
    V = B.CreateOr(V, B.CreateShl(B.CreateZExt(B2, I32Ty), 16));
    V = B.CreateOr(V, B.CreateShl(B.CreateZExt(B3, I32Ty), 24));

    Value *PNext = B.CreateGEP(I8Ty, P, ConstantInt::get(I64Ty, 4));
    B.CreateStore(PNext, CodePtr);
    return V;
  }

  // Helper: read u64 from bytecode (little endian)
  llvm::Value* readU64(llvm::IRBuilder<> &B, llvm::Value *CodePtr, llvm::Value *EndPtr) {
    using namespace llvm;
    Value *P = B.CreateLoad(PtrTy, CodePtr);
    // Read 8 bytes
    Value *V = ConstantInt::get(I64Ty, 0);
    for (int i = 0; i < 8; i++) {
      Value *Bi = B.CreateLoad(I8Ty, B.CreateGEP(I8Ty, P, ConstantInt::get(I64Ty, i)));
      Value *Shifted = B.CreateShl(B.CreateZExt(Bi, I64Ty), i * 8);
      V = B.CreateOr(V, Shifted);
    }
    Value *PNext = B.CreateGEP(I8Ty, P, ConstantInt::get(I64Ty, 8));
    B.CreateStore(PNext, CodePtr);
    return V;
  }

  // Helper: ensure data segment capacity
  void ensureData(llvm::IRBuilder<> &B, llvm::Value *DsBuf, llvm::Value *DsSz,
                  llvm::Value *DsCap, llvm::Value *Need) {
    using namespace llvm;

    // Load current values
    Value *Cap = B.CreateLoad(I32Ty, DsCap);
    Value *NeedCmp = B.CreateICmpUGT(Need, Cap);

    // Create blocks for realloc path
    Function *F = B.GetInsertBlock()->getParent();
    BasicBlock *ReallocBB = BasicBlock::Create(Ctx, "ensure.realloc", F);
    BasicBlock *ContBB = BasicBlock::Create(Ctx, "ensure.cont", F);

    B.CreateCondBr(NeedCmp, ReallocBB, ContBB);

    // Realloc path
    B.SetInsertPoint(ReallocBB);
    // Calculate new capacity: max(4096, cap * 2) until >= need
    Value *NewCap = B.CreateSelect(
        B.CreateICmpEQ(Cap, ConstantInt::get(I32Ty, 0)),
        ConstantInt::get(I32Ty, 4096),
        B.CreateShl(Cap, 1));

    // Simple: just use need * 2 for now
    NewCap = B.CreateShl(Need, 1);
    NewCap = B.CreateSelect(
        B.CreateICmpULT(NewCap, ConstantInt::get(I32Ty, 4096)),
        ConstantInt::get(I32Ty, 4096), NewCap);

    Value *OldBuf = B.CreateLoad(PtrTy, DsBuf);
    Value *NewBuf = B.CreateCall(getRealloc(),
        {OldBuf, B.CreateZExt(NewCap, I64Ty)});

    // Memset new area
    Value *OldCap = B.CreateLoad(I32Ty, DsCap);
    Value *NewArea = B.CreateGEP(I8Ty, NewBuf, B.CreateZExt(OldCap, I64Ty));
    Value *ClearLen = B.CreateSub(NewCap, OldCap);
    B.CreateCall(getMemset(), {NewArea, ConstantInt::get(I32Ty, 0), B.CreateZExt(ClearLen, I64Ty)});

    B.CreateStore(NewBuf, DsBuf);
    B.CreateStore(NewCap, DsCap);
    B.CreateStore(Need, DsSz);
    B.CreateBr(ContBB);

    B.SetInsertPoint(ContBB);
  }

  // Helper: store u64 to data segment
  void dsStoreU64(llvm::IRBuilder<> &B, llvm::Value *DsBuf, llvm::Value *DsSz,
                  llvm::Value *DsCap, llvm::Value *Off, llvm::Value *Val) {
    using namespace llvm;
    Value *OffPlus8 = B.CreateAdd(Off, ConstantInt::get(I32Ty, 8));
    ensureData(B, DsBuf, DsSz, DsCap, OffPlus8);
    Value *Buf = B.CreateLoad(PtrTy, DsBuf);
    Value *Ptr = B.CreateGEP(I8Ty, Buf, B.CreateZExt(Off, I64Ty));
    B.CreateStore(Val, Ptr);
  }

  // Helper: load u64 from data segment
  llvm::Value* dsLoadU64(llvm::IRBuilder<> &B, llvm::Value *DsBuf, llvm::Value *DsSz,
                         llvm::Value *DsCap, llvm::Value *Off) {
    using namespace llvm;
    Value *OffPlus8 = B.CreateAdd(Off, ConstantInt::get(I32Ty, 8));
    ensureData(B, DsBuf, DsSz, DsCap, OffPlus8);
    Value *Buf = B.CreateLoad(PtrTy, DsBuf);
    Value *Ptr = B.CreateGEP(I8Ty, Buf, B.CreateZExt(Off, I64Ty));
    return B.CreateLoad(I64Ty, Ptr);
  }

  // Read encoded value from bytecode
  // Returns: {is_slot, value_u64, slot_off}
  struct EncodedValue {
    llvm::Value *IsSlot;
    llvm::Value *ValueU64;
    llvm::Value *SlotOff;
  };

  EncodedValue readValue(llvm::IRBuilder<> &B, llvm::Value *CodePtr, llvm::Value *EndPtr,
                         llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap) {
    using namespace llvm;
    EncodedValue EV;

    Value *Tag = readU8(B, CodePtr, EndPtr);
    Value *IsSlot = B.CreateICmpEQ(Tag, ConstantInt::get(I8Ty, VT_SLOT));

    Function *F = B.GetInsertBlock()->getParent();
    BasicBlock *SlotBB = BasicBlock::Create(Ctx, "val.slot", F);
    BasicBlock *ConstBB = BasicBlock::Create(Ctx, "val.const", F);
    BasicBlock *MergeBB = BasicBlock::Create(Ctx, "val.merge", F);

    B.CreateCondBr(IsSlot, SlotBB, ConstBB);

    // Slot path
    B.SetInsertPoint(SlotBB);
    Value *SlotOff = readU32(B, CodePtr, EndPtr);
    Value *SlotVal = dsLoadU64(B, DsBuf, DsSz, DsCap, SlotOff);
    B.CreateBr(MergeBB);
    BasicBlock *SlotBBEnd = B.GetInsertBlock();

    // Const path
    B.SetInsertPoint(ConstBB);
    Value *Ck = readU8(B, CodePtr, EndPtr);
    Value *Sz = readU32(B, CodePtr, EndPtr);
    // For simplicity, always read 8 bytes (handles most cases)
    Value *ConstVal = readU64(B, CodePtr, EndPtr);
    B.CreateBr(MergeBB);
    BasicBlock *ConstBBEnd = B.GetInsertBlock();

    // Merge
    B.SetInsertPoint(MergeBB);
    PHINode *ValPhi = B.CreatePHI(I64Ty, 2, "val.u64");
    ValPhi->addIncoming(SlotVal, SlotBBEnd);
    ValPhi->addIncoming(ConstVal, ConstBBEnd);

    PHINode *OffPhi = B.CreatePHI(I32Ty, 2, "val.off");
    OffPhi->addIncoming(SlotOff, SlotBBEnd);
    OffPhi->addIncoming(ConstantInt::get(I32Ty, 0), ConstBBEnd);

    PHINode *IsSlotPhi = B.CreatePHI(I1Ty, 2, "val.isslot");
    IsSlotPhi->addIncoming(ConstantInt::getTrue(Ctx), SlotBBEnd);
    IsSlotPhi->addIncoming(ConstantInt::getFalse(Ctx), ConstBBEnd);

    EV.IsSlot = IsSlotPhi;
    EV.ValueU64 = ValPhi;
    EV.SlotOff = OffPhi;

    return EV;
  }

  // OP_PARAMMAP handler
  void generateOpParamMap(llvm::Function *F, llvm::SwitchInst *Sw,
                          llvm::Value *CodePtr, llvm::Value *EndPtr,
                          llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                          llvm::Value *ArgArgs, llvm::Value *ArgNum,
                          llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.parammap", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_PARAMMAP)), BB);

    IRBuilder<> B(BB);
    Value *N = readU32(B, CodePtr, EndPtr);

    // Loop: for i = 0 to N
    BasicBlock *LoopHdr = BasicBlock::Create(Ctx, "pm.loop.hdr", F);
    BasicBlock *LoopBody = BasicBlock::Create(Ctx, "pm.loop.body", F);
    BasicBlock *LoopEnd = BasicBlock::Create(Ctx, "pm.loop.end", F);

    Value *I = B.CreateAlloca(I32Ty);
    B.CreateStore(ConstantInt::get(I32Ty, 0), I);
    B.CreateBr(LoopHdr);

    B.SetInsertPoint(LoopHdr);
    Value *Idx = B.CreateLoad(I32Ty, I);
    Value *Cond = B.CreateICmpULT(Idx, N);
    B.CreateCondBr(Cond, LoopBody, LoopEnd);

    B.SetInsertPoint(LoopBody);
    Value *Off = readU32(B, CodePtr, EndPtr);
    Value *Sz = readU32(B, CodePtr, EndPtr);

    // Ensure data segment has space
    Value *OffPlusSz = B.CreateAdd(Off, Sz);
    ensureData(B, DsBuf, DsSz, DsCap, OffPlusSz);

    // Check if i < num && args[i] != null
    Value *Idx64 = B.CreateZExt(Idx, I64Ty);
    Value *InRange = B.CreateICmpULT(Idx64, ArgNum);

    BasicBlock *CopyBB = BasicBlock::Create(Ctx, "pm.copy", F);
    BasicBlock *ZeroBB = BasicBlock::Create(Ctx, "pm.zero", F);
    BasicBlock *NextBB = BasicBlock::Create(Ctx, "pm.next", F);

    B.CreateCondBr(InRange, CopyBB, ZeroBB);

    // Copy from args[i]
    B.SetInsertPoint(CopyBB);
    Value *ArgsSlot = B.CreateGEP(PtrTy, ArgArgs, Idx64);
    Value *ArgPtr = B.CreateLoad(PtrTy, ArgsSlot);
    Value *ArgNotNull = B.CreateICmpNE(ArgPtr, ConstantPointerNull::get(cast<PointerType>(PtrTy)));

    BasicBlock *DoCopyBB = BasicBlock::Create(Ctx, "pm.docopy", F);
    B.CreateCondBr(ArgNotNull, DoCopyBB, ZeroBB);

    B.SetInsertPoint(DoCopyBB);
    Value *Buf = B.CreateLoad(PtrTy, DsBuf);
    Value *DstPtr = B.CreateGEP(I8Ty, Buf, B.CreateZExt(Off, I64Ty));
    B.CreateCall(getMemcpy(), {DstPtr, ArgPtr, B.CreateZExt(Sz, I64Ty)});
    B.CreateBr(NextBB);

    // Zero fill
    B.SetInsertPoint(ZeroBB);
    Buf = B.CreateLoad(PtrTy, DsBuf);
    DstPtr = B.CreateGEP(I8Ty, Buf, B.CreateZExt(Off, I64Ty));
    B.CreateCall(getMemset(), {DstPtr, ConstantInt::get(I32Ty, 0), B.CreateZExt(Sz, I64Ty)});
    B.CreateBr(NextBB);

    // Next iteration
    B.SetInsertPoint(NextBB);
    Value *IdxInc = B.CreateAdd(B.CreateLoad(I32Ty, I), ConstantInt::get(I32Ty, 1));
    B.CreateStore(IdxInc, I);
    B.CreateBr(LoopHdr);

    // End
    B.SetInsertPoint(LoopEnd);
    B.CreateBr(LoopHeader);
  }

  // OP_ALLOCA handler
  void generateOpAlloca(llvm::Function *F, llvm::SwitchInst *Sw,
                        llvm::Value *CodePtr, llvm::Value *EndPtr,
                        llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                        llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.alloca", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_ALLOCA)), BB);

    IRBuilder<> B(BB);
    Value *Dst = readU32(B, CodePtr, EndPtr);
    Value *Area = readU32(B, CodePtr, EndPtr);

    // malloc(area)
    Value *Mem = B.CreateCall(getMalloc(), {B.CreateZExt(Area, I64Ty)});
    Value *MemI64 = B.CreatePtrToInt(Mem, I64Ty);

    // Store to data segment
    dsStoreU64(B, DsBuf, DsSz, DsCap, Dst, MemI64);

    B.CreateBr(LoopHeader);
  }

  // OP_LOAD handler
  void generateOpLoad(llvm::Function *F, llvm::SwitchInst *Sw,
                      llvm::Value *CodePtr, llvm::Value *EndPtr,
                      llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                      llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.load", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_LOAD)), BB);

    IRBuilder<> B(BB);
    Value *Dst = readU32(B, CodePtr, EndPtr);
    EncodedValue PtrVal = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);

    // Load 8 bytes from address
    Value *Addr = B.CreateIntToPtr(PtrVal.ValueU64, PtrTy);
    Value *Val = B.CreateLoad(I64Ty, Addr);

    dsStoreU64(B, DsBuf, DsSz, DsCap, Dst, Val);
    B.CreateBr(LoopHeader);
  }

  // OP_STORE handler
  void generateOpStore(llvm::Function *F, llvm::SwitchInst *Sw,
                       llvm::Value *CodePtr, llvm::Value *EndPtr,
                       llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                       llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.store", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_STORE)), BB);

    IRBuilder<> B(BB);
    EncodedValue Val = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    EncodedValue PtrVal = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);

    Value *Addr = B.CreateIntToPtr(PtrVal.ValueU64, PtrTy);
    B.CreateStore(Val.ValueU64, Addr);

    B.CreateBr(LoopHeader);
  }

  // OP_GEP handler
  void generateOpGep(llvm::Function *F, llvm::SwitchInst *Sw,
                     llvm::Value *CodePtr, llvm::Value *EndPtr,
                     llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                     llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.gep", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_GEP)), BB);

    IRBuilder<> B(BB);
    Value *Dst = readU32(B, CodePtr, EndPtr);
    EncodedValue Base = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    Value *NIdx = readU32(B, CodePtr, EndPtr);

    // Loop to accumulate offsets
    Value *Off = B.CreateAlloca(I64Ty);
    B.CreateStore(ConstantInt::get(I64Ty, 0), Off);

    BasicBlock *LoopHdr = BasicBlock::Create(Ctx, "gep.loop.hdr", F);
    BasicBlock *LoopBody = BasicBlock::Create(Ctx, "gep.loop.body", F);
    BasicBlock *LoopEnd = BasicBlock::Create(Ctx, "gep.loop.end", F);

    Value *I = B.CreateAlloca(I32Ty);
    B.CreateStore(ConstantInt::get(I32Ty, 0), I);
    B.CreateBr(LoopHdr);

    B.SetInsertPoint(LoopHdr);
    Value *Idx = B.CreateLoad(I32Ty, I);
    Value *Cond = B.CreateICmpULT(Idx, NIdx);
    B.CreateCondBr(Cond, LoopBody, LoopEnd);

    B.SetInsertPoint(LoopBody);
    EncodedValue IdxVal = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    Value *CurOff = B.CreateLoad(I64Ty, Off);
    Value *NewOff = B.CreateAdd(CurOff, IdxVal.ValueU64);
    B.CreateStore(NewOff, Off);

    Value *IdxInc = B.CreateAdd(Idx, ConstantInt::get(I32Ty, 1));
    B.CreateStore(IdxInc, I);
    B.CreateBr(LoopHdr);

    B.SetInsertPoint(LoopEnd);
    Value *FinalOff = B.CreateLoad(I64Ty, Off);
    Value *Result = B.CreateAdd(Base.ValueU64, FinalOff);
    dsStoreU64(B, DsBuf, DsSz, DsCap, Dst, Result);
    B.CreateBr(LoopHeader);
  }

  // OP_CMP handler
  void generateOpCmp(llvm::Function *F, llvm::SwitchInst *Sw,
                     llvm::Value *CodePtr, llvm::Value *EndPtr,
                     llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                     llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.cmp", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_CMP)), BB);

    IRBuilder<> B(BB);
    Value *Pred = readU8(B, CodePtr, EndPtr);
    Value *Dst = readU32(B, CodePtr, EndPtr);
    EncodedValue L = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    EncodedValue R = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);

    // Simplified: treat as ICmp for now
    Value *IsFCmp = B.CreateICmpULT(Pred, ConstantInt::get(I8Ty, 32));

    BasicBlock *FCmpBB = BasicBlock::Create(Ctx, "cmp.fcmp", F);
    BasicBlock *ICmpBB = BasicBlock::Create(Ctx, "cmp.icmp", F);
    BasicBlock *MergeBB = BasicBlock::Create(Ctx, "cmp.merge", F);

    B.CreateCondBr(IsFCmp, FCmpBB, ICmpBB);

    // FCmp path (simplified - just do ordered comparison)
    B.SetInsertPoint(FCmpBB);
    Value *LF = B.CreateBitCast(L.ValueU64, F64Ty);
    Value *RF = B.CreateBitCast(R.ValueU64, F64Ty);
    // Default to OEQ for now
    Value *FCmpRes = B.CreateFCmpOEQ(LF, RF);
    Value *FCmpI64 = B.CreateZExt(FCmpRes, I64Ty);
    B.CreateBr(MergeBB);
    BasicBlock *FCmpEnd = B.GetInsertBlock();

    // ICmp path
    B.SetInsertPoint(ICmpBB);
    // Create switch for different predicates
    Value *Pred32 = B.CreateZExt(Pred, I32Ty);

    // Simplified: common cases
    Value *IsEQ = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_EQ));
    Value *IsNE = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_NE));
    Value *IsULT = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_ULT));
    Value *IsULE = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_ULE));
    Value *IsUGT = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_UGT));
    Value *IsUGE = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_UGE));
    Value *IsSLT = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_SLT));
    Value *IsSLE = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_SLE));
    Value *IsSGT = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_SGT));
    Value *IsSGE = B.CreateICmpEQ(Pred32, ConstantInt::get(I32Ty, ICMP_SGE));

    Value *CmpEQ = B.CreateICmpEQ(L.ValueU64, R.ValueU64);
    Value *CmpNE = B.CreateICmpNE(L.ValueU64, R.ValueU64);
    Value *CmpULT = B.CreateICmpULT(L.ValueU64, R.ValueU64);
    Value *CmpULE = B.CreateICmpULE(L.ValueU64, R.ValueU64);
    Value *CmpUGT = B.CreateICmpUGT(L.ValueU64, R.ValueU64);
    Value *CmpUGE = B.CreateICmpUGE(L.ValueU64, R.ValueU64);
    Value *CmpSLT = B.CreateICmpSLT(L.ValueU64, R.ValueU64);
    Value *CmpSLE = B.CreateICmpSLE(L.ValueU64, R.ValueU64);
    Value *CmpSGT = B.CreateICmpSGT(L.ValueU64, R.ValueU64);
    Value *CmpSGE = B.CreateICmpSGE(L.ValueU64, R.ValueU64);

    Value *Res = B.CreateSelect(IsEQ, CmpEQ,
                  B.CreateSelect(IsNE, CmpNE,
                  B.CreateSelect(IsULT, CmpULT,
                  B.CreateSelect(IsULE, CmpULE,
                  B.CreateSelect(IsUGT, CmpUGT,
                  B.CreateSelect(IsUGE, CmpUGE,
                  B.CreateSelect(IsSLT, CmpSLT,
                  B.CreateSelect(IsSLE, CmpSLE,
                  B.CreateSelect(IsSGT, CmpSGT,
                  B.CreateSelect(IsSGE, CmpSGE, ConstantInt::getFalse(Ctx)))))))))));

    Value *ICmpI64 = B.CreateZExt(Res, I64Ty);
    B.CreateBr(MergeBB);
    BasicBlock *ICmpEnd = B.GetInsertBlock();

    // Merge
    B.SetInsertPoint(MergeBB);
    PHINode *ResPhi = B.CreatePHI(I64Ty, 2);
    ResPhi->addIncoming(FCmpI64, FCmpEnd);
    ResPhi->addIncoming(ICmpI64, ICmpEnd);

    dsStoreU64(B, DsBuf, DsSz, DsCap, Dst, ResPhi);
    B.CreateBr(LoopHeader);
  }

  // OP_CAST handler
  void generateOpCast(llvm::Function *F, llvm::SwitchInst *Sw,
                      llvm::Value *CodePtr, llvm::Value *EndPtr,
                      llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                      llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.cast", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_CAST)), BB);

    IRBuilder<> B(BB);
    Value *Cop = readU8(B, CodePtr, EndPtr);
    Value *Dst = readU32(B, CodePtr, EndPtr);
    EncodedValue V = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);

    // For most casts, just pass through or do simple transform
    // This is simplified - full implementation would handle all cast types
    Value *Result = V.ValueU64;  // Default: pass through

    dsStoreU64(B, DsBuf, DsSz, DsCap, Dst, Result);
    B.CreateBr(LoopHeader);
  }

  // OP_BR handler
  void generateOpBr(llvm::Function *F, llvm::SwitchInst *Sw,
                    llvm::Value *CodePtr, llvm::Value *EndPtr,
                    llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                    llvm::Value *ArgCode,
                    llvm::BasicBlock *LoopHeader, llvm::BasicBlock *ExitBlock) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.br", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_BR)), BB);

    IRBuilder<> B(BB);
    Value *IsCond = readU8(B, CodePtr, EndPtr);
    Value *IsCondBr = B.CreateICmpNE(IsCond, ConstantInt::get(I8Ty, 0));

    BasicBlock *UncondBB = BasicBlock::Create(Ctx, "br.uncond", F);
    BasicBlock *CondBB = BasicBlock::Create(Ctx, "br.cond", F);

    B.CreateCondBr(IsCondBr, CondBB, UncondBB);

    // Unconditional branch
    B.SetInsertPoint(UncondBB);
    Value *Target = readU32(B, CodePtr, EndPtr);
    Value *NewP = B.CreateGEP(I8Ty, ArgCode, B.CreateZExt(Target, I64Ty));
    B.CreateStore(NewP, CodePtr);
    B.CreateBr(LoopHeader);

    // Conditional branch
    B.SetInsertPoint(CondBB);
    EncodedValue C = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    Value *TrueTarget = readU32(B, CodePtr, EndPtr);
    Value *FalseTarget = readU32(B, CodePtr, EndPtr);

    Value *Cond = B.CreateICmpNE(C.ValueU64, ConstantInt::get(I64Ty, 0));
    Value *TargetOff = B.CreateSelect(Cond, TrueTarget, FalseTarget);
    NewP = B.CreateGEP(I8Ty, ArgCode, B.CreateZExt(TargetOff, I64Ty));
    B.CreateStore(NewP, CodePtr);
    B.CreateBr(LoopHeader);
  }

  // OP_ARITH handler
  void generateOpArith(llvm::Function *F, llvm::SwitchInst *Sw,
                       llvm::Value *CodePtr, llvm::Value *EndPtr,
                       llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                       llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.arith", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_ARITH)), BB);

    IRBuilder<> B(BB);
    Value *Sub = readU8(B, CodePtr, EndPtr);
    Value *Tk = readU8(B, CodePtr, EndPtr);
    Value *Bits = readU8(B, CodePtr, EndPtr);
    Value *Dst = readU32(B, CodePtr, EndPtr);
    EncodedValue L = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    EncodedValue R = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);

    // Integer arithmetic
    Value *Sub32 = B.CreateZExt(Sub, I32Ty);

    Value *Add = B.CreateAdd(L.ValueU64, R.ValueU64);
    Value *SubV = B.CreateSub(L.ValueU64, R.ValueU64);
    Value *Mul = B.CreateMul(L.ValueU64, R.ValueU64);
    Value *UDiv = B.CreateUDiv(L.ValueU64, B.CreateSelect(
        B.CreateICmpEQ(R.ValueU64, ConstantInt::get(I64Ty, 0)),
        ConstantInt::get(I64Ty, 1), R.ValueU64));
    Value *SDiv = B.CreateSDiv(L.ValueU64, B.CreateSelect(
        B.CreateICmpEQ(R.ValueU64, ConstantInt::get(I64Ty, 0)),
        ConstantInt::get(I64Ty, 1), R.ValueU64));
    Value *URem = B.CreateURem(L.ValueU64, B.CreateSelect(
        B.CreateICmpEQ(R.ValueU64, ConstantInt::get(I64Ty, 0)),
        ConstantInt::get(I64Ty, 1), R.ValueU64));
    Value *SRem = B.CreateSRem(L.ValueU64, B.CreateSelect(
        B.CreateICmpEQ(R.ValueU64, ConstantInt::get(I64Ty, 0)),
        ConstantInt::get(I64Ty, 1), R.ValueU64));
    Value *Shl = B.CreateShl(L.ValueU64, B.CreateAnd(R.ValueU64, ConstantInt::get(I64Ty, 63)));
    Value *LShr = B.CreateLShr(L.ValueU64, B.CreateAnd(R.ValueU64, ConstantInt::get(I64Ty, 63)));
    Value *AShr = B.CreateAShr(L.ValueU64, B.CreateAnd(R.ValueU64, ConstantInt::get(I64Ty, 63)));
    Value *And = B.CreateAnd(L.ValueU64, R.ValueU64);
    Value *Or = B.CreateOr(L.ValueU64, R.ValueU64);
    Value *Xor = B.CreateXor(L.ValueU64, R.ValueU64);

    // FP arithmetic (f64)
    Value *LF = B.CreateBitCast(L.ValueU64, F64Ty);
    Value *RF = B.CreateBitCast(R.ValueU64, F64Ty);
    Value *FAdd = B.CreateBitCast(B.CreateFAdd(LF, RF), I64Ty);
    Value *FSub = B.CreateBitCast(B.CreateFSub(LF, RF), I64Ty);
    Value *FMul = B.CreateBitCast(B.CreateFMul(LF, RF), I64Ty);
    Value *FDiv = B.CreateBitCast(B.CreateFDiv(LF, RF), I64Ty);
    Value *FRem = B.CreateBitCast(B.CreateFRem(LF, RF), I64Ty);

    // Select result based on sub-opcode
    Value *IsAdd = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_ADD));
    Value *IsSub = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_SUB));
    Value *IsMul = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_MUL));
    Value *IsUDiv = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_UDIV));
    Value *IsSDiv = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_SDIV));
    Value *IsURem = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_UREM));
    Value *IsSRem = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_SREM));
    Value *IsShl = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_SHL));
    Value *IsLShr = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_LSHR));
    Value *IsAShr = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_ASHR));
    Value *IsAnd = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_AND));
    Value *IsOr = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_OR));
    Value *IsXor = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_XOR));
    Value *IsFAdd = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_FADD));
    Value *IsFSub = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_FSUB));
    Value *IsFMul = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_FMUL));
    Value *IsFDiv = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_FDIV));
    Value *IsFRem = B.CreateICmpEQ(Sub32, ConstantInt::get(I32Ty, AR_FREM));

    Value *Result = B.CreateSelect(IsAdd, Add,
                    B.CreateSelect(IsSub, SubV,
                    B.CreateSelect(IsMul, Mul,
                    B.CreateSelect(IsUDiv, UDiv,
                    B.CreateSelect(IsSDiv, SDiv,
                    B.CreateSelect(IsURem, URem,
                    B.CreateSelect(IsSRem, SRem,
                    B.CreateSelect(IsShl, Shl,
                    B.CreateSelect(IsLShr, LShr,
                    B.CreateSelect(IsAShr, AShr,
                    B.CreateSelect(IsAnd, And,
                    B.CreateSelect(IsOr, Or,
                    B.CreateSelect(IsXor, Xor,
                    B.CreateSelect(IsFAdd, FAdd,
                    B.CreateSelect(IsFSub, FSub,
                    B.CreateSelect(IsFMul, FMul,
                    B.CreateSelect(IsFDiv, FDiv,
                    B.CreateSelect(IsFRem, FRem, ConstantInt::get(I64Ty, 0)))))))))))))))))));

    dsStoreU64(B, DsBuf, DsSz, DsCap, Dst, Result);
    B.CreateBr(LoopHeader);
  }

  // OP_CALL handler
  void generateOpCall(llvm::Function *F, llvm::SwitchInst *Sw,
                      llvm::Value *CodePtr, llvm::Value *EndPtr,
                      llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                      llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.call", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_CALL)), BB);

    IRBuilder<> B(BB);
    Value *Id = readU64(B, CodePtr, EndPtr);
    Value *Dst = readU32(B, CodePtr, EndPtr);
    Value *DynN = readU32(B, CodePtr, EndPtr);

    // Allocate args array
    Value *DynN64 = B.CreateZExt(DynN, I64Ty);
    Value *ArgsSize = B.CreateMul(DynN64, ConstantInt::get(I64Ty, 8));
    Value *Args = B.CreateCall(getMalloc(), {ArgsSize});

    // Fill args array
    BasicBlock *LoopHdr = BasicBlock::Create(Ctx, "call.loop.hdr", F);
    BasicBlock *LoopBody = BasicBlock::Create(Ctx, "call.loop.body", F);
    BasicBlock *LoopEnd = BasicBlock::Create(Ctx, "call.loop.end", F);

    Value *I = B.CreateAlloca(I32Ty);
    B.CreateStore(ConstantInt::get(I32Ty, 0), I);
    B.CreateBr(LoopHdr);

    B.SetInsertPoint(LoopHdr);
    Value *Idx = B.CreateLoad(I32Ty, I);
    Value *Cond = B.CreateICmpULT(Idx, DynN);
    B.CreateCondBr(Cond, LoopBody, LoopEnd);

    B.SetInsertPoint(LoopBody);
    Value *Off = readU32(B, CodePtr, EndPtr);
    // Get pointer to data segment offset
    Value *OffPlus = B.CreateAdd(Off, ConstantInt::get(I32Ty, 1));
    ensureData(B, DsBuf, DsSz, DsCap, OffPlus);
    Value *Buf = B.CreateLoad(PtrTy, DsBuf);
    Value *ArgPtr = B.CreateGEP(I8Ty, Buf, B.CreateZExt(Off, I64Ty));

    // Store to args[i]
    Value *Idx64 = B.CreateZExt(Idx, I64Ty);
    Value *ArgsSlot = B.CreateGEP(PtrTy, Args, Idx64);
    B.CreateStore(ArgPtr, ArgsSlot);

    Value *IdxInc = B.CreateAdd(Idx, ConstantInt::get(I32Ty, 1));
    B.CreateStore(IdxInc, I);
    B.CreateBr(LoopHdr);

    B.SetInsertPoint(LoopEnd);
    // Call handle_call
    Value *Result = B.CreateCall(getHandleCall(), {Id, Args, DynN64});

    // Free args
    B.CreateCall(getFree(), {Args});

    // Store result if dst != 0xFFFFFFFF
    Value *HasDst = B.CreateICmpNE(Dst, ConstantInt::get(I32Ty, 0xFFFFFFFF));
    BasicBlock *StoreBB = BasicBlock::Create(Ctx, "call.store", F);
    BasicBlock *ContBB = BasicBlock::Create(Ctx, "call.cont", F);
    B.CreateCondBr(HasDst, StoreBB, ContBB);

    B.SetInsertPoint(StoreBB);
    dsStoreU64(B, DsBuf, DsSz, DsCap, Dst, Result);
    B.CreateBr(ContBB);

    B.SetInsertPoint(ContBB);
    B.CreateBr(LoopHeader);
  }

  // OP_RET handler
  void generateOpRet(llvm::Function *F, llvm::SwitchInst *Sw,
                     llvm::Value *CodePtr, llvm::Value *EndPtr,
                     llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                     llvm::Value *RetVal,
                     llvm::BasicBlock *ExitBlock) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.ret", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_RET)), BB);

    IRBuilder<> B(BB);
    EncodedValue V = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    B.CreateStore(V.ValueU64, RetVal);
    B.CreateBr(ExitBlock);
  }

  // OP_SELECT handler
  void generateOpSelect(llvm::Function *F, llvm::SwitchInst *Sw,
                        llvm::Value *CodePtr, llvm::Value *EndPtr,
                        llvm::Value *DsBuf, llvm::Value *DsSz, llvm::Value *DsCap,
                        llvm::BasicBlock *LoopHeader) {
    using namespace llvm;

    BasicBlock *BB = BasicBlock::Create(Ctx, "op.select", F);
    Sw->addCase(cast<ConstantInt>(ConstantInt::get(I8Ty, OP_SELECT)), BB);

    IRBuilder<> B(BB);
    Value *Tk = readU8(B, CodePtr, EndPtr);
    Value *Bits = readU8(B, CodePtr, EndPtr);
    Value *Dst = readU32(B, CodePtr, EndPtr);
    EncodedValue C = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    EncodedValue T = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);
    EncodedValue FV = readValue(B, CodePtr, EndPtr, DsBuf, DsSz, DsCap);

    Value *Cond = B.CreateICmpNE(C.ValueU64, ConstantInt::get(I64Ty, 0));
    Value *Result = B.CreateSelect(Cond, T.ValueU64, FV.ValueU64);

    dsStoreU64(B, DsBuf, DsSz, DsCap, Dst, Result);
    B.CreateBr(LoopHeader);
  }
};

} // namespace svm
