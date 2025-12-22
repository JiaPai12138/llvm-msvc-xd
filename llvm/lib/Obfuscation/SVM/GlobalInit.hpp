// GlobalInit.hpp - LLVM 18 adapted (opaque pointers)
#pragma once
#include <vector>
#include <string>
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Type.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Transforms/Utils/ModuleUtils.h" // appendToGlobalCtors

namespace ginit {
using namespace llvm;

// ===== Utility functions =====
inline IntegerType* IntPtrTy(Module& M) {
    return cast<IntegerType>(M.getDataLayout().getIntPtrType(M.getContext()));
}
inline Align PrefPtrAlign(Module& M) {
    return Align(M.getDataLayout().getPointerPrefAlignment(0).value());
}
inline bool isDefinableGlobal(GlobalVariable* GV) {
    return GV->getLinkage() != GlobalValue::ExternalWeakLinkage &&
           GV->getLinkage() != GlobalValue::CommonLinkage;
}

// Create a private read-only string GV and return i8* (ConstantExpr) to first element
inline Constant* makePrivateROStringPtr(Module& M, StringRef NameHint, StringRef Bytes, bool AddNull = true) {
    LLVMContext& Ctx = M.getContext();
    auto* CDA = ConstantDataArray::getString(Ctx, Bytes, AddNull);
    auto* StrGV = new GlobalVariable(
        M, CDA->getType(), /*isConst=*/true,
        GlobalValue::PrivateLinkage, CDA,
        (NameHint + ".str").str()
    );
    StrGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    StrGV->setAlignment(Align(1));

    // ConstantExpr GEP 0,0 - LLVM 18 compatible
    Type* IdxTy = Type::getInt64Ty(Ctx);
    Constant* Z = ConstantInt::get(IdxTy, 0);
    Constant* Idxs[] = { Z, Z };
    return ConstantExpr::getInBoundsGetElementPtr(StrGV->getValueType(), StrGV,
                                                  ArrayRef<Constant*>(Idxs, 2));
}

// ===== 1) Compile-time initialization (preferred) =====

inline bool setZero(GlobalVariable* GV) {
    if (!isDefinableGlobal(GV)) return false;
    GV->setInitializer(Constant::getNullValue(GV->getValueType()));
    return true;
}

inline bool setInt(GlobalVariable* GV, uint64_t Val) {
    auto* ITy = dyn_cast<IntegerType>(GV->getValueType());
    if (!ITy) return false;
    if (!isDefinableGlobal(GV)) return false;
    GV->setInitializer(ConstantInt::get(ITy, Val));
    return true;
}

inline bool setFP(GlobalVariable* GV, double Val) {
    Type* Ty = GV->getValueType();
    if (!Ty->isFloatingPointTy()) return false;
    if (!isDefinableGlobal(GV)) return false;
    GV->setInitializer(ConstantFP::get(Ty, Val));
    return true;
}

// Initialize byte array to [N x i8]
inline bool setBytes(GlobalVariable* GV, ArrayRef<uint8_t> Bytes) {
    auto* ArrTy = dyn_cast<ArrayType>(GV->getValueType());
    if (!ArrTy || !ArrTy->getElementType()->isIntegerTy(8) ||
        ArrTy->getNumElements() != Bytes.size())
        return false;
    if (!isDefinableGlobal(GV)) return false;

    auto* CDA = ConstantDataArray::get(GV->getContext(), Bytes);
    GV->setInitializer(CDA);
    GV->setAlignment(Align(1));
    return true;
}

// Set function address to GV
inline bool setFuncAddress(GlobalVariable* GV, Function* F, Module& M) {
    if (!isDefinableGlobal(GV)) return false;
    Type* Ty = GV->getValueType();
    Constant* Rhs = nullptr;
    if (Ty->isPointerTy()) {
        // LLVM 18: No bitcast needed for opaque pointers
        Rhs = F;
    } else if (auto* ITy = dyn_cast<IntegerType>(Ty)) {
        if (ITy->getBitWidth() != IntPtrTy(M)->getBitWidth()) return false;
        Rhs = ConstantExpr::getPtrToInt(F, ITy);
    } else {
        return false;
    }
    GV->setInitializer(Rhs);
    GV->setAlignment(PrefPtrAlign(M));
    return true;
}

// Set global address to GV
inline bool setGlobalAddress(GlobalVariable* GV, Constant* Target, Module& M) {
    if (!isDefinableGlobal(GV)) return false;
    Type* Ty = GV->getValueType();
    Constant* Rhs = nullptr;
    if (Ty->isPointerTy()) {
        // LLVM 18: No bitcast needed for opaque pointers
        Rhs = Target;
    } else if (auto* ITy = dyn_cast<IntegerType>(Ty)) {
        if (ITy->getBitWidth() != IntPtrTy(M)->getBitWidth()) return false;
        Rhs = ConstantExpr::getPtrToInt(Target, ITy);
    } else {
        return false;
    }
    GV->setInitializer(Rhs);
    GV->setAlignment(PrefPtrAlign(M));
    return true;
}

// ===== 2) Runtime initialization (fallback) =====
inline Function* emitCtorStore(Module& M, GlobalVariable* GV, Constant* RHS, unsigned Priority = 65535) {
    LLVMContext& Ctx = M.getContext();
    if (GV->isDeclaration() && GV->getLinkage() == GlobalValue::ExternalWeakLinkage)
        return nullptr;
    if (!GV->hasInitializer())
        GV->setInitializer(Constant::getNullValue(GV->getValueType()));

    auto* CtorFT = FunctionType::get(Type::getVoidTy(Ctx), false);
    Function* Ctor = Function::Create(CtorFT, GlobalValue::InternalLinkage,
                                      ("__ginit_ctor_" + GV->getName()).str(), &M);
    BasicBlock* BB = BasicBlock::Create(Ctx, "entry", Ctor);
    IRBuilder<> B(BB);

    Value* ToStore = RHS;
    Type* Ty = GV->getValueType();
    if (ToStore->getType() != Ty) {
        if (Ty->isPointerTy() && ToStore->getType()->isPointerTy()) {
            // LLVM 18: opaque pointers, no cast needed
            ToStore = RHS;
        } else if (Ty->isPointerTy() && ToStore->getType()->isIntegerTy()) {
            ToStore = B.CreateIntToPtr(ToStore, Ty);
        } else if (Ty->isIntegerTy() && ToStore->getType()->isPointerTy()) {
            ToStore = B.CreatePtrToInt(ToStore, Ty);
        } else if (Ty->isIntegerTy() && ToStore->getType()->isIntegerTy()) {
            unsigned SW = cast<IntegerType>(ToStore->getType())->getBitWidth();
            unsigned DW = cast<IntegerType>(Ty)->getBitWidth();
            if (SW < DW) ToStore = B.CreateZExt(ToStore, Ty);
            else if (SW > DW) ToStore = B.CreateTrunc(ToStore, Ty);
        }
    }

    B.CreateStore(ToStore, GV);
    B.CreateRetVoid();
    appendToGlobalCtors(M, Ctor, Priority);
    return Ctor;
}

// ===== 3) Helper: find/create and initialize =====

inline GlobalVariable* ensureDefinableGV(Module& M, StringRef Name, Type* Ty, Align A = Align()) {
    if (auto* GV = M.getGlobalVariable(Name))
        return GV;
    auto* GV = new GlobalVariable(M, Ty, /*isConst=*/false,
                                  GlobalValue::ExternalLinkage,
                                  /*Init=*/nullptr, Name);
    if (A.value() != 0) GV->setAlignment(A);
    return GV;
}

// Create 2D char array: @Name = [R x [W x i8]]
inline GlobalVariable* createChar2DGV(
    Module& M, StringRef Name,
    ArrayRef<StringRef> Strings,
    bool Writable = false,
    GlobalValue::LinkageTypes Linkage = GlobalValue::ExternalLinkage,
    Align alignment = Align(1)) {

    StringRef Section = Writable ? ".data.irvm" : ".rodata.irvm" ;

    LLVMContext& Ctx = M.getContext();
    Type* I8 = Type::getInt8Ty(Ctx);

    size_t W = 1;
    for (auto s : Strings) W = std::max(W, s.size() + 1);

    auto* RowTy = ArrayType::get(I8, W);

    std::vector<Constant*> Rows;
    Rows.reserve(Strings.size());
    for (auto s : Strings) {
        std::vector<uint8_t> buf(W, 0);
        const size_t copyN = std::min(s.size(), W - 1);
        if (copyN) std::memcpy(buf.data(), s.data(), copyN);
        Rows.push_back(ConstantDataArray::get(Ctx, buf));
    }

    auto* MatTy = ArrayType::get(RowTy, Rows.size());
    auto* MatC  = ConstantArray::get(MatTy, Rows);

    auto* GV = new GlobalVariable(
        M, MatTy, /*isConstant=*/!Writable, Linkage, MatC, Name);
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    if (alignment.value() != 0) GV->setAlignment(alignment);
    if (!Section.empty()) GV->setSection(Section);
    return GV;
}

inline llvm::GlobalVariable* createGlobalCStringTable(llvm::Module &M,
                                                      llvm::StringRef Name,
                                                      llvm::ArrayRef<llvm::StringRef> Items) {
    using namespace llvm;
    LLVMContext& Ctx = M.getContext();
    // LLVM 18: Use opaque pointer type
    Type* PtrTy = PointerType::get(Ctx, 0);

    std::vector<Constant*> Ptrs;
    Ptrs.reserve(Items.size());
    for (unsigned i = 0; i < Items.size(); ++i) {
        auto* CDA = ConstantDataArray::getString(Ctx, Items[i], /*AddNull=*/true);
        auto* S   = new GlobalVariable(M, CDA->getType(), /*isConst=*/true,
                                       GlobalValue::PrivateLinkage, CDA,
                                       (Name + ".str." + Twine(i)).str());
        S->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        S->setAlignment(Align(1));

        // LLVM 18: GEP 0,0 to get pointer to first element
        Constant* Z = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
        Constant* Idx[] = { Z, Z };
        Constant* P = ConstantExpr::getInBoundsGetElementPtr(
            S->getValueType(), S, ArrayRef<Constant*>(Idx, 2));
        Ptrs.push_back(P);
    }

    auto* ArrTy = ArrayType::get(PtrTy, Ptrs.size());
    auto* ArrC  = ConstantArray::get(ArrTy, Ptrs);
    auto* GV    = new GlobalVariable(M, ArrTy, /*isConst=*/true,
                                     GlobalValue::ExternalLinkage, ArrC, Name.str());
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(8));
    return GV;
}

} // namespace ginit
