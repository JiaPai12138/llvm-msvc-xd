// HandleCallTool.h - LLVM 18 adapted (opaque pointers)
// Function-level collection -> generate/rewrite handle_call(...) + const dispatch

#pragma once
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Support/raw_ostream.h"

#include <unordered_map>
#include <vector>
#include <string>
#include <cassert>

namespace vmp {

// Helper: compress type to signature key
static void dumpTypeRec(llvm::Type *T, llvm::raw_ostream &OS) {
  using namespace llvm;
  if (T->isIntegerTy()) { OS << "i" << T->getIntegerBitWidth(); return; }
  if (T->isPointerTy()) { OS << "p"; return; } // opaque: no element tracking
  if (T->isFloatTy())   { OS << "f32"; return; }
  if (T->isDoubleTy())  { OS << "f64"; return; }
  if (T->isVoidTy())    { OS << "v";   return; }
  OS << "t";
}

static inline std::string signatureKey(llvm::FunctionType *FTy) {
  using namespace llvm;
  std::string S; raw_string_ostream OS(S);
  OS << "ret:"; dumpTypeRec(FTy->getReturnType(), OS);
  OS << ";args(";
  for (unsigned i=0;i<FTy->getNumParams();++i){ dumpTypeRec(FTy->getParamType(i), OS); OS<<","; }
  OS << ")vararg=" << (FTy->isVarArg()?1:0);
  OS.flush(); return S;
}

class HandleCallTool {
public:
  HandleCallTool() = default;
  explicit HandleCallTool(llvm::Module &M) { bindModule(M); }

  void bindModule(llvm::Module &M) {
    Mod = &M;
    Ctx = &M.getContext();
    I64 = llvm::Type::getInt64Ty(*Ctx);
    I8  = llvm::Type::getInt8Ty(*Ctx);
    // LLVM 18: opaque pointer
    PtrTy = llvm::PointerType::get(*Ctx, 0);
  }

  void collectFromFunction(llvm::Function &F) {
    if (F.isDeclaration()) return;
    if (!Mod) bindModule(*F.getParent());
    else { assert(Mod == F.getParent() && "All functions must be from the same Module"); }

    for (auto &I : llvm::instructions(F)) {
      if (auto *CB = llvm::dyn_cast<llvm::CallBase>(&I)) ensureCallId(CB);
    }
  }

  // For VMCodeGen: normal call ID
  uint64_t ensureCallId(llvm::CallBase* CB) {
    if (auto it = CallIdOf.find(CB); it != CallIdOf.end()) return it->second;
    uint64_t id = 0;
    if (readIdFromMD(CB, id)) { CallIdOf[CB] = id; return id; }
    id = registerCallSite(CB);
    return id;
  }

  uint64_t getCallId(const llvm::CallBase* CB) const {
    uint64_t id = 0; bool ok = tryGetCallId(CB, id);
    assert(ok && "CallId not found. Use ensureCallId()/collectFromFunction() first.");
    return id;
  }

  bool tryGetCallId(const llvm::CallBase* CB, uint64_t &out) const {
    if (auto it = CallIdOf.find(CB); it != CallIdOf.end()) { out = it->second; return true; }
    return readIdFromMD(CB, out);
  }

  // Normalize V to constant ptr for "address-of"
  llvm::Constant* tryMakeConstPtrExpr(llvm::Value *V) {
    using namespace llvm;
    if (!Ctx) return nullptr;

    if (auto *GV = dyn_cast<GlobalValue>(V)) {
      // LLVM 18: no bitcast needed for opaque pointers
      return GV;
    }
    if (auto *CE = dyn_cast<ConstantExpr>(V)) {
      if (CE->getType()->isPointerTy())
        return CE;
      return nullptr;
    }
    if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
      Value *Base = GEP->getPointerOperand();
      if (!isa<Constant>(Base)) return nullptr;
      llvm::SmallVector<llvm::Constant*, 8> Idxs;
      for (auto &Idx : GEP->indices()) {
        if (auto *C = dyn_cast<Constant>(Idx)) Idxs.push_back(C);
        else return nullptr;
      }
      llvm::Type *SrcElemTy = GEP->getSourceElementType();
      auto *BaseC = cast<Constant>(Base);
      return ConstantExpr::getGetElementPtr(SrcElemTy, BaseC, Idxs, /*InBounds*/true);
    }
    return nullptr;
  }

  // Allocate ID for "const address" (ptr constant)
  uint64_t ensureConstAddrId(llvm::Constant *PtrConst) {
    assert(PtrConst && PtrConst->getType()->isPointerTy() && "need ptr constant");
    if (auto it = ConstIdMap.find(PtrConst); it != ConstIdMap.end()) return it->second;
    uint64_t id = NextCallId++;
    ConstEntries.push_back(ConstEntry::AddrOf(id, PtrConst));
    ConstIdMap.insert({ PtrConst, id });
    return id;
  }

  // Allocate ID for integer constant
  uint64_t ensureConstIntId(llvm::ConstantInt *CI) {
    assert(CI && "need ConstantInt");
    llvm::APInt AP = CI->getValue().zextOrTrunc(64);
    uint64_t bits = AP.getZExtValue();
    ConstIntKey key{CI->getType()->getIntegerBitWidth(), bits};
    if (auto it = ConstIntIdMap.find(key); it != ConstIntIdMap.end()) return it->second;
    uint64_t id = NextCallId++;
    ConstEntries.push_back(ConstEntry::IntBits(id, bits));
    ConstIntIdMap.emplace(key, id);
    return id;
  }

  // Allocate ID for FP constant (bitcast to i64)
  uint64_t ensureConstFPBitsId(llvm::ConstantFP *CFP) {
    assert(CFP && "need ConstantFP");
    uint64_t bits = 0;
    if (CFP->getType()->isDoubleTy()) {
      bits = CFP->getValueAPF().bitcastToAPInt().getZExtValue();
    } else if (CFP->getType()->isFloatTy()) {
      uint32_t b32 = CFP->getValueAPF().bitcastToAPInt().getZExtValue();
      bits = (uint64_t)b32;
    } else {
      assert(false && "only f32/f64 supported");
    }
    ConstFPKey key{CFP->getType()->isDoubleTy()?64u:32u, bits};
    if (auto it = ConstFPIdMap.find(key); it != ConstFPIdMap.end()) return it->second;
    uint64_t id = NextCallId++;
    ConstEntries.push_back(ConstEntry::FPBits(id, bits));
    ConstFPIdMap.emplace(key, id);
    return id;
  }

  // Generate/rewrite handle_call
  llvm::Function* materializeHandle(bool forceCreateStubIfEmpty=false) {
    ensureModuleBoundOrDerive();
    if (!Mod) { llvm::errs() << "[HandleCallTool] No Module bound.\n"; return nullptr; }
    return materializeImpl(*Mod, forceCreateStubIfEmpty);
  }

  llvm::Function* materializeHandle(llvm::Module &M, bool forceCreateStubIfEmpty=false) {
    if (!Mod) bindModule(M); else { assert(Mod==&M && "Materializing into a different Module"); }
    return materializeImpl(M, forceCreateStubIfEmpty);
  }

private:
  // Register a callsite
  uint64_t registerCallSite(llvm::CallBase *CB) {
    using namespace llvm;
    CallEntry E;
    E.callId = NextCallId++;
    E.CC = CB->getCallingConv();
    if (auto *CI = dyn_cast<CallInst>(CB)) {
      E.TCK = CI->getTailCallKind();
      E.Attrs = CI->getAttributes();
      E.DL = CI->getDebugLoc();
    }
    E.FTy = CB->getFunctionType();

    Value *CalleeOp = CB->getCalledOperand();
    Value *Stripped = CalleeOp->stripPointerCasts();
    if (auto *F = dyn_cast<Function>(Stripped)) E.DirectCallee = F;
    else if (isa<Constant>(CalleeOp))           E.ConstCallee  = cast<Constant>(CalleeOp);
    else                                        E.NeedsRuntimeFnPtr = true;

    E.methodId = getOrCreateMethodId(E.FTy,
                     E.DirectCallee ? E.DirectCallee->getName()
                                    : (E.ConstCallee ? E.ConstCallee->getName() : "<indirect>"));

    unsigned nextIdx = E.NeedsRuntimeFnPtr ? 1 : 0;
    for (unsigned i=0;i<CB->arg_size();++i) {
      Value *Op = CB->getArgOperand(i);
      ArgSpec A; A.Ty = Op->getType();
      if (isa<Constant>(Op)) { A.isConst=true; A.C=cast<Constant>(Op); }
      else { A.isConst=false; A.runtimeIndex=nextIdx++; }
      E.Args.push_back(A);
    }
    E.RetTy = CB->getType();

    Entries.push_back(std::move(E));
    CallIdOf[CB] = Entries.back().callId;
    writeIdMD(CB, Entries.back().callId);
    return Entries.back().callId;
  }

  // MD storage
  static constexpr const char* kCallIdMD = "vmp.call.id";

  bool readIdFromMD(const llvm::CallBase* CB, uint64_t &out) const {
    if (auto *N = CB->getMetadata(kCallIdMD)) {
      if (auto *CM = llvm::dyn_cast<llvm::ConstantAsMetadata>(N->getOperand(0))) {
        if (auto *CI = llvm::dyn_cast<llvm::ConstantInt>(CM->getValue())) {
          out = CI->getZExtValue(); return true;
        }
      }
    }
    return false;
  }

  void writeIdMD(llvm::CallBase* CB, uint64_t id) {
    auto &C = CB->getContext();
    auto *I64Local = llvm::Type::getInt64Ty(C);
    auto *CI = llvm::ConstantInt::get(I64Local, id);
    auto *MD = llvm::MDNode::get(C, { llvm::ConstantAsMetadata::get(CI) });
    CB->setMetadata(kCallIdMD, MD);
  }

  // methodId: signature+name
  uint64_t getOrCreateMethodId(llvm::FunctionType *FTy, llvm::StringRef key) {
    std::string k = signatureKey(FTy) + "|" + key.str();
    auto it = MethodIdMap.find(k);
    if (it != MethodIdMap.end()) return it->second;
    uint64_t id = NextMethodId++;
    MethodIdMap.emplace(std::move(k), id);
    return id;
  }

  void ensureModuleBoundOrDerive() {
    if (Mod) return;
    for (const auto &E : Entries) {
      if (E.DirectCallee) { bindModule(*E.DirectCallee->getParent()); return; }
      if (E.ConstCallee) {
        if (auto *F = llvm::dyn_cast<llvm::Function>(E.ConstCallee->stripPointerCasts())) {
          bindModule(*F->getParent()); return;
        }
      }
    }
    for (const auto &K : ConstEntries) {
      if (K.Kind == ConstEntry::K_Addr && K.AddrConst) {
        if (auto *GV = llvm::dyn_cast<llvm::GlobalValue>(K.AddrConst->stripPointerCasts())) {
          bindModule(*GV->getParent()); return;
        }
      }
    }
  }

  // Convert any return value to i64
  llvm::Value* toU64(llvm::IRBuilder<> &B, llvm::Value *V, llvm::Type *RTy) {
    using namespace llvm;
    if (RTy->isVoidTy()) return ConstantInt::get(I64, 0);
    if (RTy->isIntegerTy()) {
      unsigned bw = cast<IntegerType>(RTy)->getBitWidth();
      if (bw < 64) return B.CreateZExt(V, I64);
      if (bw > 64) return B.CreateTrunc(V, I64);
      return V;
    }
    if (RTy->isPointerTy()) return B.CreatePtrToInt(V, I64);
    if (RTy->isFloatTy() || RTy->isDoubleTy() || RTy->isFP128Ty()) return B.CreateFPToUI(V, I64);
    return llvm::ConstantInt::get(I64, 0);
  }

  // Load from args[idx] as Ty
  static llvm::Value* loadFromArgsAt(llvm::IRBuilder<> &B,
                                     llvm::Type *Ty, unsigned idx,
                                     llvm::Value *ArgArgs,
                                     llvm::Type *I64, llvm::Type *PtrTy)
  {
    using namespace llvm;
    Value *I = ConstantInt::get(I64, idx);
    Value *Slot = B.CreateGEP(PtrTy, ArgArgs, I);        // &args[idx] : (ptr*)
    Value *Elem = B.CreateLoad(PtrTy, Slot);             // ptr
    // LLVM 18: opaque pointer, load directly with target type
    return B.CreateLoad(Ty, Elem);
  }

  // Build fresh dispatch in empty handle_call
  void buildFreshDispatch(llvm::Function *HF, bool hasNumArg) {
    using namespace llvm;
    auto AI = HF->arg_begin();
    Argument *ArgId   = &*AI++; ArgId->setName("id");
    Argument *ArgArgs = &*AI++; ArgArgs->setName("args");
    if (hasNumArg) { Argument *ArgNum = &*AI++; ArgNum->setName("num"); (void)ArgNum; }

    BasicBlock *BBEntry = BasicBlock::Create(*Ctx, "entry", HF);
    BasicBlock *Cond  = BasicBlock::Create(*Ctx, "cond0", HF);
    IRBuilder<> B(BBEntry); B.CreateBr(Cond);

    BasicBlock *ChainTail = Cond;

    auto addConstCase = [&](const ConstEntry &K){
      IRBuilder<> BC(ChainTail);
      auto *Hit  = BC.CreateICmpEQ(ArgId, ConstantInt::get(I64, K.constId));
      auto *Do   = BasicBlock::Create(*Ctx, ("do_k_"+std::to_string(K.constId)), HF);
      auto *Next = BasicBlock::Create(*Ctx, ("cond_"+std::to_string(K.constId+1)), HF);
      BC.CreateCondBr(Hit, Do, Next);
      IRBuilder<> BD(Do);
      switch (K.Kind) {
        case ConstEntry::K_Addr: {
          Value *PI = BD.CreatePtrToInt(K.AddrConst, I64);
          BD.CreateRet(PI);
        } break;
        case ConstEntry::K_IntBits: {
          BD.CreateRet(ConstantInt::get(I64, K.Bits));
        } break;
        case ConstEntry::K_FPBits: {
          BD.CreateRet(ConstantInt::get(I64, K.Bits));
        } break;
      }
      ChainTail = Next;
    };

    auto addCallCase = [&](const CallEntry &E){
      IRBuilder<> BC(ChainTail);
      auto *Hit  = BC.CreateICmpEQ(ArgId, ConstantInt::get(I64, E.callId));
      auto *Do   = BasicBlock::Create(*Ctx, ("do_call_"+std::to_string(E.callId)), HF);
      auto *Next = BasicBlock::Create(*Ctx, ("cond_"+std::to_string(E.callId+1)), HF);
      BC.CreateCondBr(Hit, Do, Next);

      IRBuilder<> BD(Do);
      llvm::SmallVector<llvm::Value*, 8> CallArgs;

      for (const ArgSpec &A : E.Args) {
        if (A.isConst) CallArgs.push_back(A.C);
        else           CallArgs.push_back(loadFromArgsAt(BD, A.Ty, A.runtimeIndex, ArgArgs, I64, PtrTy));
      }

      llvm::CallInst *NewCI = nullptr;
      if (E.DirectCallee) {
        NewCI = BD.CreateCall(E.FTy, E.DirectCallee, CallArgs);
      } else if (E.ConstCallee) {
        // LLVM 18: opaque pointers, no cast needed
        NewCI = BD.CreateCall(E.FTy, E.ConstCallee, CallArgs);
      } else {
        llvm::Value *FnPtr = loadFromArgsAt(BD, PtrTy, 0, ArgArgs, I64, PtrTy);
        NewCI = BD.CreateCall(E.FTy, FnPtr, CallArgs);
      }

      NewCI->setCallingConv(E.CC);
      NewCI->setTailCallKind(E.TCK);
      NewCI->setAttributes(E.Attrs);
      NewCI->setDebugLoc(E.DL);

      BD.CreateRet(toU64(BD, NewCI, E.RetTy));
      ChainTail = Next;
    };

    for (const auto &K : ConstEntries) addConstCase(K);
    for (const auto &E : Entries)      addCallCase(E);

    IRBuilder<> BE(ChainTail);
    BE.CreateRet(ConstantInt::get(I64, 0));
  }

  // Prepend dispatch chain to existing handle_call
  void prependDispatchChain(llvm::Function *HF, bool hasNumArg) {
    using namespace llvm;
    auto AI = HF->arg_begin();
    Argument *ArgId   = &*AI++; ArgId->setName("id");
    Argument *ArgArgs = &*AI++; ArgArgs->setName("args");
    if (hasNumArg) { Argument *ArgNum = &*AI++; ArgNum->setName("num"); (void)ArgNum; }

    BasicBlock *OldEntryBB = &HF->getEntryBlock();
    BasicBlock *NewEntryBB = BasicBlock::Create(*Ctx, "entry.extend", HF, OldEntryBB);
    IRBuilder<> B(NewEntryBB);
    BasicBlock *CurCond = BasicBlock::Create(*Ctx, "cond.prepend.0", HF);
    B.CreateBr(CurCond);

    auto addConstCase = [&](const ConstEntry &K){
      IRBuilder<> BC(CurCond);
      auto *Hit  = BC.CreateICmpEQ(ArgId, ConstantInt::get(I64, K.constId));
      auto *Do   = BasicBlock::Create(*Ctx, ("do_k_"+std::to_string(K.constId)), HF);
      auto *Next = BasicBlock::Create(*Ctx, ("cond.prepend."+std::to_string(K.constId+1)), HF);
      BC.CreateCondBr(Hit, Do, Next);
      IRBuilder<> BD(Do);
      switch (K.Kind) {
        case ConstEntry::K_Addr: { BD.CreateRet(BD.CreatePtrToInt(K.AddrConst, I64)); } break;
        case ConstEntry::K_IntBits: { BD.CreateRet(ConstantInt::get(I64, K.Bits)); } break;
        case ConstEntry::K_FPBits: { BD.CreateRet(ConstantInt::get(I64, K.Bits)); } break;
      }
      CurCond = Next;
    };

    auto addCallCase = [&](const CallEntry &E){
      IRBuilder<> BC(CurCond);
      auto *Hit  = BC.CreateICmpEQ(ArgId, ConstantInt::get(I64, E.callId));
      auto *Do   = BasicBlock::Create(*Ctx, ("do_call_"+std::to_string(E.callId)), HF);
      auto *Next = BasicBlock::Create(*Ctx, ("cond.prepend."+std::to_string(E.callId+1)), HF);
      BC.CreateCondBr(Hit, Do, Next);

      IRBuilder<> BD(Do);
      llvm::SmallVector<llvm::Value*, 8> CallArgs;
      for (const ArgSpec &A : E.Args) {
        if (A.isConst) CallArgs.push_back(A.C);
        else           CallArgs.push_back(loadFromArgsAt(BD, A.Ty, A.runtimeIndex, ArgArgs, I64, PtrTy));
      }

      llvm::CallInst *NewCI = nullptr;
      if (E.DirectCallee) NewCI = BD.CreateCall(E.FTy, E.DirectCallee, CallArgs);
      else if (E.ConstCallee) {
        // LLVM 18: opaque pointers
        NewCI = BD.CreateCall(E.FTy, E.ConstCallee, CallArgs);
      } else {
        llvm::Value *FnPtr = loadFromArgsAt(BD, PtrTy, 0, ArgArgs, I64, PtrTy);
        NewCI = BD.CreateCall(E.FTy, FnPtr, CallArgs);
      }

      NewCI->setCallingConv(E.CC);
      NewCI->setTailCallKind(E.TCK);
      NewCI->setAttributes(E.Attrs);
      NewCI->setDebugLoc(E.DL);

      BD.CreateRet(toU64(BD, NewCI, E.RetTy));
      CurCond = Next;
    };

    for (const auto &K : ConstEntries) addConstCase(K);
    for (const auto &E : Entries)      addCallCase(E);

    IRBuilder<> BE(CurCond);
    BE.CreateBr(OldEntryBB);
  }

  // Main implementation
  llvm::Function* materializeImpl(llvm::Module &M, bool forceCreateStubIfEmpty) {
    using namespace llvm;

    if (!Ctx) bindModule(M);

    Function *HF = M.getFunction("handle_call");

    if (Entries.empty() && ConstEntries.empty()) {
      if (!HF) {
        if (!forceCreateStubIfEmpty) return nullptr;
        // LLVM 18: ptr instead of i8**
        // InternalLinkage: each translation unit has its own handle_call
        auto *FT = FunctionType::get(I64, { I64, PtrTy, I64 }, /*vararg*/false);
        HF = Function::Create(FT, GlobalValue::InternalLinkage, "handle_call", &M);
        IRBuilder<> B(BasicBlock::Create(*Ctx, "entry", HF));
        B.CreateRet(ConstantInt::get(I64, 0));
        return HF;
      }
      return HF;
    }

    if (!HF) {
      // InternalLinkage: each translation unit has its own handle_call
      auto *FT = FunctionType::get(I64, { I64, PtrTy, I64 }, /*vararg*/false);
      HF = Function::Create(FT, GlobalValue::InternalLinkage, "handle_call", &M);
      buildFreshDispatch(HF, /*hasNumArg=*/true);
    } else {
      auto *FTy = HF->getFunctionType();
      unsigned NP = FTy->getNumParams();
      bool hasNumArg = (NP >= 3);
      if (HF->empty()) buildFreshDispatch(HF, hasNumArg);
      else             prependDispatchChain(HF, hasNumArg);
    }

    Entries.clear();
    ConstEntries.clear();
    ConstIdMap.clear();
    ConstIntIdMap.clear();
    ConstFPIdMap.clear();
    return HF;
  }

  // Data structures
  struct ArgSpec {
    llvm::Type *Ty{}; bool isConst{}; llvm::Constant *C{}; unsigned runtimeIndex{};
  };

  struct CallEntry {
    uint64_t callId{}; uint64_t methodId{};
    llvm::FunctionType *FTy{}; llvm::Function *DirectCallee{}; llvm::Constant *ConstCallee{}; bool NeedsRuntimeFnPtr{false};
    std::vector<ArgSpec> Args; llvm::Type *RetTy{};
    llvm::CallingConv::ID CC{llvm::CallingConv::C};
    llvm::AttributeList Attrs{}; llvm::CallInst::TailCallKind TCK{llvm::CallInst::TCK_None};
    llvm::DebugLoc DL{};
  };

  struct ConstEntry {
    enum Kind { K_Addr, K_IntBits, K_FPBits } Kind{};
    uint64_t constId{};
    llvm::Constant *AddrConst{};
    uint64_t Bits{};

    static ConstEntry AddrOf(uint64_t id, llvm::Constant *C) {
      ConstEntry E; E.Kind=K_Addr; E.constId=id; E.AddrConst=C; return E;
    }
    static ConstEntry IntBits(uint64_t id, uint64_t bits) {
      ConstEntry E; E.Kind=K_IntBits; E.constId=id; E.Bits=bits; return E;
    }
    static ConstEntry FPBits(uint64_t id, uint64_t bits) {
      ConstEntry E; E.Kind=K_FPBits; E.constId=id; E.Bits=bits; return E;
    }
  };

  struct ConstIntKey {
    unsigned Width; uint64_t Bits;
    bool operator==(const ConstIntKey &o) const { return Width==o.Width && Bits==o.Bits; }
  };
  struct ConstIntKeyHash {
    std::size_t operator()(ConstIntKey const& k) const {
      return (std::size_t)k.Bits ^ ((std::size_t)k.Width<<1);
    }
  };
  struct ConstFPKey {
    unsigned Width; uint64_t Bits;
    bool operator==(const ConstFPKey &o) const { return Width==o.Width && Bits==o.Bits; }
  };
  struct ConstFPKeyHash {
    std::size_t operator()(ConstFPKey const& k) const {
      return (std::size_t)k.Bits ^ ((std::size_t)k.Width<<1);
    }
  };

  llvm::Module *Mod{nullptr};
  llvm::LLVMContext *Ctx{nullptr};
  llvm::Type *I64{nullptr};
  llvm::Type *I8{nullptr};
  llvm::Type *PtrTy{nullptr};  // LLVM 18: opaque pointer

  std::vector<CallEntry> Entries;
  std::vector<ConstEntry> ConstEntries;

  uint64_t NextMethodId{0};
  uint64_t NextCallId{0};
  std::unordered_map<std::string, uint64_t> MethodIdMap;
  llvm::DenseMap<const llvm::CallBase*, uint64_t> CallIdOf;

  llvm::DenseMap<const llvm::Constant*, uint64_t> ConstIdMap;
  std::unordered_map<ConstIntKey, uint64_t, ConstIntKeyHash> ConstIntIdMap;
  std::unordered_map<ConstFPKey,  uint64_t, ConstFPKeyHash>  ConstFPIdMap;
};

} // namespace vmp
