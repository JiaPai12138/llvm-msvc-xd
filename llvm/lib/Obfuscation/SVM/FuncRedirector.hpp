// FuncRedirector.hpp - LLVM 18 adapted (opaque pointers)
// Rewrite function to vm_exec(code, size, args, num)

#pragma once

#include <vector>
#include <string>
#include <cassert>

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/Casting.h"

#include "SVMInterpreterGen.h"
#include "GlobalInit.hpp"

namespace frx {
using namespace llvm;

// Options
struct VMExecOptions {
  std::string VMName = "vm_exec";
  bool GenerateInterpreter = true;  // Generate full interpreter if vm_exec is empty
  bool UseTailCall = false;
  bool DisallowVarArg = true;
  bool BoxPointers = true;
};

// Constant GEP for typed arrays
inline Constant* constGEP_0_0(Type* PointeeTy, Constant* Base) {
  LLVMContext& Ctx = Base->getContext();
  Constant* Z = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
  Constant* Idx[] = { Z, Z };
  return ConstantExpr::getInBoundsGetElementPtr(PointeeTy, Base,
                                                ArrayRef<Constant*>(Idx, 2));
}

// Get or create vm_exec(code, size, args, num)
// Uses SVMInterpreterGen to generate the full interpreter inline
inline Function* getOrCreateVMExec(Module& M, StringRef Name,
                                   bool GenerateInterpreter) {
  LLVMContext& Ctx = M.getContext();
  // LLVM 18: opaque pointers
  Type* PtrTy = PointerType::get(Ctx, 0);
  Type* I32  = Type::getInt32Ty(Ctx);
  IntegerType* IntPtrT = ginit::IntPtrTy(M);

  // intptr_t vm_exec(const uint8_t*, uint32_t, void** args, intptr_t num)
  auto* FT = FunctionType::get(IntPtrT, { PtrTy, I32, PtrTy, IntPtrT }, /*isVarArg=*/false);
  Function* F = cast<Function>(M.getOrInsertFunction(Name, FT).getCallee());

  if (GenerateInterpreter && F->empty()) {
    // Use SVMInterpreterGen to generate the full interpreter
    svm::SVMInterpreterGen gen(M);
    F = gen.getOrCreateVMExec();
  }
  return F;
}

/*
 * rewriteToVMExec
 *    return vm_exec(code_ptr, code_size, args_array, num_args);
 */
inline bool rewriteToVMExec(Function& F,
                            GlobalVariable* CodeGV,
                            uint32_t CodeSize,
                            const VMExecOptions& Opt = {}) {
  if (F.isDeclaration()) return false;
  if (Opt.DisallowVarArg && F.isVarArg()) return false;

  Module& M = *F.getParent();
  LLVMContext& Ctx = M.getContext();
  IRBuilder<> B(Ctx);

  // Clear function body
  while (!F.empty()) F.begin()->eraseFromParent();
  BasicBlock* Entry = BasicBlock::Create(Ctx, "entry", &F);
  B.SetInsertPoint(Entry);

  // LLVM 18: opaque pointers
  Type* PtrTy = PointerType::get(Ctx, 0);
  Type* I32  = Type::getInt32Ty(Ctx);
  IntegerType* IntPtrT = ginit::IntPtrTy(M);
  unsigned PtrBits = IntPtrT->getBitWidth();

  Function* VM = getOrCreateVMExec(M, Opt.VMName, Opt.GenerateInterpreter);

  // Code pointer / size
  Constant* CodePtrC = nullptr;
  if (!CodeGV) {
    CodePtrC = ConstantPointerNull::get(static_cast<PointerType*>(PtrTy));
    CodeSize = 0;
  } else {
    auto* ArrTy = cast<ArrayType>(CodeGV->getValueType());
    CodePtrC = constGEP_0_0(ArrTy, CodeGV);
  }
  Constant* CodeSizeC = ConstantInt::get(I32, CodeSize);

  // Args: box all arguments to stack
  const unsigned N = F.arg_size();
  Value* NumC = ConstantInt::get(IntPtrT, N);

  // Allocate ptr* args (N==0 -> allocate 1 to avoid alloca(0))
  Value* N32 = ConstantInt::get(Type::getInt32Ty(Ctx), N ? N : 1);
  AllocaInst* ArgsArr = B.CreateAlloca(PtrTy, N32, "args");

  unsigned idx = 0;
  for (Argument& A : F.args()) {
    Value* AddrPtr = nullptr;

    if (A.getType()->isPointerTy()) {
      if (Opt.BoxPointers) {
        // Store pointer value into stack slot
        AllocaInst* Box = B.CreateAlloca(A.getType(), nullptr, A.getName() + ".box.p");
        B.CreateStore(&A, Box);
        AddrPtr = Box;
      } else {
        AddrPtr = &A;
      }
    } else if (A.getType()->isIntegerTy()) {
      // VM slots are always 8 bytes, so Box must be i64
      Type* I64 = Type::getInt64Ty(Ctx);
      AllocaInst* Box = B.CreateAlloca(I64, nullptr, A.getName() + ".box.i");
      Value* V = &A;
      unsigned bw = cast<IntegerType>(A.getType())->getBitWidth();
      if (bw < 64) V = B.CreateZExt(V, I64);
      else if (bw > 64) V = B.CreateTrunc(V, I64);
      B.CreateStore(V, Box);
      AddrPtr = Box;
    } else if (A.getType()->isFloatingPointTy()) {
      // VM slots are always 8 bytes
      Type* I64 = Type::getInt64Ty(Ctx);
      if (A.getType()->isDoubleTy()) {
        // Double is 8 bytes, but store via i64 alloca for consistency
        AllocaInst* BoxD = B.CreateAlloca(I64, nullptr, A.getName() + ".box.f64");
        B.CreateStore(&A, BoxD);
        AddrPtr = BoxD;
      } else if (A.getType()->isFloatTy()) {
        // Float is 4 bytes, need 8-byte slot. Store f32 then zero-extend to i64
        AllocaInst* BoxF = B.CreateAlloca(I64, nullptr, A.getName() + ".box.f32");
        Value* AsI32 = B.CreateBitCast(&A, Type::getInt32Ty(Ctx));
        Value* AsI64 = B.CreateZExt(AsI32, I64);
        B.CreateStore(AsI64, BoxF);
        AddrPtr = BoxF;
      } else {
        // Other FP types (e.g., x86_fp80, fp128): use original type but ensure 8-byte minimum
        Type* FT = A.getType();
        AllocaInst* Box = B.CreateAlloca(FT, nullptr, A.getName() + ".box.fp");
        B.CreateStore(&A, Box);
        AddrPtr = Box;
      }
    } else {
      // Struct/array/other: allocate and store
      Type* T = A.getType();
      AllocaInst* Box = B.CreateAlloca(T, nullptr, A.getName() + ".box.any");
      B.CreateStore(&A, Box);
      AddrPtr = Box;
    }

    // args[idx] = AddrPtr (LLVM 18: opaque pointer, no bitcast needed)
    Value* Slot = B.CreateInBoundsGEP(PtrTy, ArgsArr,
                   ConstantInt::get(Type::getInt32Ty(Ctx), idx));
    B.CreateStore(AddrPtr, Slot);
    ++idx;
  }

  // Call vm_exec(code, size, args, num)
  CallInst* RetIntPtr = B.CreateCall(VM, { CodePtrC, CodeSizeC, ArgsArr, NumC });
  if (Opt.UseTailCall) RetIntPtr->setTailCallKind(CallInst::TCK_Tail);

  // Convert return value
  Type* RT = F.getReturnType();
  if (RT->isVoidTy()) {
    B.CreateRetVoid();
  } else if (RT->isIntegerTy()) {
    unsigned W = cast<IntegerType>(RT)->getBitWidth();
    Value* V = RetIntPtr;
    if (W < PtrBits) V = B.CreateTrunc(V, RT);
    else if (W > PtrBits) V = B.CreateZExt(V, RT);
    // else: W == PtrBits, no conversion needed
    B.CreateRet(V);
  } else if (RT->isPointerTy()) {
    B.CreateRet(B.CreateIntToPtr(RetIntPtr, RT));
  } else if (RT->isDoubleTy()) {
    // Double: need 64 bits, but on 32-bit we only have 32-bit return value
    // Store IntPtrTy to memory and reinterpret as double
    // WARNING: On 32-bit platforms, only low 32 bits are valid - double returns are lossy
    Type* I64 = Type::getInt64Ty(Ctx);
    AllocaInst* Box = B.CreateAlloca(I64);
    Value* Extended = B.CreateZExt(RetIntPtr, I64);
    B.CreateStore(Extended, Box);
    Value* D = B.CreateLoad(Type::getDoubleTy(Ctx), Box);
    B.CreateRet(D);
  } else if (RT->isFloatTy()) {
    // Float: reinterpret low 32 bits as float via memory
    Type* I32 = Type::getInt32Ty(Ctx);
    AllocaInst* Box = B.CreateAlloca(I32);
    Value* I32v = B.CreateTruncOrBitCast(RetIntPtr, I32);
    B.CreateStore(I32v, Box);
    Value* Fv = B.CreateLoad(Type::getFloatTy(Ctx), Box);
    B.CreateRet(Fv);
  } else {
    B.CreateRet(UndefValue::get(RT));
  }

  F.addFnAttr(Attribute::NoInline);
  return true;
}

} // namespace frx
