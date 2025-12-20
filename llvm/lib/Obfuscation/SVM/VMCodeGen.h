// VMCodeGen.h - LLVM 18 adapted (opaque pointers, std::optional)
// Function-level bytecode generator based on HandleCallTool

#pragma once
#include "SVM/HandleCallTool.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <map>
#include <unordered_set>
#include <optional>
#include <cassert>
#include <cstdint>

//#define SVM_CODEGEN_DEBUG 1

namespace vmp {

// Bytecode opcodes (aligned with VM interpreter)
enum : uint8_t {
  OP_ALLOCA = 0x01,
  OP_LOAD   = 0x02,
  OP_STORE  = 0x03,
  OP_GEP    = 0x05,
  OP_CMP    = 0x06,
  OP_CAST   = 0x07,
  OP_BR     = 0x08,
  OP_CALL   = 0x09,
  OP_RET    = 0x0A,
  OP_ARITH  = 0x10,
  OP_PARAMMAP = 0x11,
};

// Value encoding
enum : uint8_t { VT_CONST = 0, VT_SLOT = 1 };
enum : uint8_t { CK_INT=0, CK_PTR=1, CK_F32=2, CK_F64=3 };

// Arithmetic sub-ops and type classes
enum : uint8_t {
  AR_ADD, AR_SUB, AR_MUL,
  AR_UDIV, AR_SDIV, AR_UREM, AR_SREM,
  AR_SHL, AR_LSHR, AR_ASHR,
  AR_AND, AR_OR, AR_XOR,
  AR_FADD, AR_FSUB, AR_FMUL, AR_FDIV, AR_FREM,
};
enum : uint8_t { TK_INT=0, TK_FP=1 };

// Little-endian packing
static inline void p8 (std::vector<uint8_t>& out, uint8_t v)  { out.push_back(v); }
static inline void p16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(uint8_t(v      )); out.push_back(uint8_t(v>>8));
}
static inline void p32(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(uint8_t(v      )); out.push_back(uint8_t(v>>8));
  out.push_back(uint8_t(v>>16 )); out.push_back(uint8_t(v>>24));
}
static inline void p64(std::vector<uint8_t>& out, uint64_t v) {
  for (int i=0;i<8;i++) out.push_back(uint8_t(v>>(i*8)));
}

// Const-like check
static bool isConstLike(llvm::Value *V) {
  using namespace llvm;
  if (isa<Constant>(V)) return true;
  if (auto *BC = dyn_cast<BitCastInst>(V))    return isConstLike(BC->getOperand(0));
  if (auto *PTI= dyn_cast<PtrToIntInst>(V))   return isConstLike(PTI->getOperand(0));
  if (auto *ITP= dyn_cast<IntToPtrInst>(V))   return isConstLike(ITP->getOperand(0));
  if (auto *GEP= dyn_cast<GetElementPtrInst>(V)) {
    if (!isConstLike(GEP->getPointerOperand())) return false;
    for (auto Idx = GEP->idx_begin(); Idx != GEP->idx_end(); ++Idx)
      if (!isa<Constant>(*Idx)) return false;
    return true;
  }
  return false;
}

class VMCodeGen {
public:
  VMCodeGen(llvm::Function &F, vmp::HandleCallTool &tool)
  : F(F), M(*F.getParent()), C(M.getContext()), DL(M.getDataLayout()),
    Tool(tool), PtrSize(DL.getPointerSize()) {}

  void run() {
    uint64_t seed = hashName(F.getName());
    Code.clear();
    Instrs.clear();
    IpHashSet.clear();
    p64(Code, seed);

    expandConstantExprs();
    enterFunction();
    emitParamMap();
    for (auto &BB : F) {
      markBB(&BB);
      for (auto &I : BB) translateInst(I);
    }
    patchBranches();
    refreshCrcs();
    buildIpHashSet();
    encryptInstructions(seed);
  }

  const std::vector<uint8_t>& code() const { return Code; }
  void dumpHex() const {
    for (auto b: Code) { llvm::errs() << (int)b << " "; } llvm::errs() << "\n";
  }

private:
  llvm::Function &F;
  llvm::Module &M;
  llvm::LLVMContext &C;
  llvm::DataLayout DL;
  vmp::HandleCallTool &Tool;
  unsigned PtrSize;

  std::vector<uint8_t> Code;
  std::vector<uint8_t> CurInst;
  struct InstrSlice { uint32_t off; uint32_t len; };
  std::vector<InstrSlice> Instrs;
  std::unordered_set<uint32_t> IpHashSet;
  std::map<const llvm::Value*, uint32_t>       SlotOf;
  std::map<const llvm::BasicBlock*, uint32_t>  AddrOfBB;
  struct Fixup { uint32_t pos; const llvm::BasicBlock* target; };
  std::vector<Fixup> BrFixups;
  uint32_t CurrDataOffset = 0;

  struct ParamDesc { uint32_t off; uint32_t size; };
  std::vector<ParamDesc> ParamMap;

  llvm::SmallPtrSet<const llvm::Value*, 16> ConstPtrDone;

  static constexpr uint32_t kSeedBytes = 8;
  static constexpr uint32_t kLenBytes = 2;
  static constexpr uint32_t kCrcBytes = 2;
  static constexpr uint32_t kHdrBytes = kLenBytes + kCrcBytes;

  static uint32_t slotSizeForType(const llvm::DataLayout &DL, llvm::Type *Ty) {
    uint64_t sz = DL.getTypeAllocSize(Ty);
    if (sz < 8) sz = 8;
    return static_cast<uint32_t>(sz);
  }

  static uint32_t align8(uint32_t v) { return (v + 7u) & ~7u; }

  static inline uint64_t rotl64(uint64_t x, unsigned r) {
    return (x << r) | (x >> (64 - r));
  }

  static constexpr uint64_t PRIME1 = 11400714785074694791ULL;
  static constexpr uint64_t PRIME2 = 14029467366897019727ULL;
  static constexpr uint64_t PRIME3 = 1609587929392839161ULL;
  static constexpr uint64_t PRIME4 = 9650029242287828579ULL;
  static constexpr uint64_t PRIME5 = 2870177450012600261ULL;

  static inline uint64_t mixKey(uint64_t prev, uint64_t ip,
                                uint8_t opcode, uint16_t len) {
    uint64_t k = prev + PRIME1;
    k ^= ip * PRIME2;
    k ^= (uint64_t)opcode * PRIME3;
    k ^= (uint64_t)len * PRIME4;
    k = rotl64(k, 31) * PRIME1;
    k ^= k >> 33; k *= PRIME2; k ^= k >> 29; k *= PRIME3; k ^= k >> 32;
    return k;
  }

  static inline uint64_t hashSeedIp(uint64_t seed, uint64_t ip) {
    uint64_t k = seed + PRIME1;
    k ^= ip * PRIME2;
    k = rotl64(k, 31) * PRIME1;
    k ^= k >> 33; k *= PRIME2; k ^= k >> 29; k *= PRIME3; k ^= k >> 32;
    return k;
  }

  static inline uint8_t nextStreamByte(uint64_t &state) {
    state = rotl64(state + PRIME5, 17) * PRIME1;
    return static_cast<uint8_t>(state & 0xFF);
  }

  static uint16_t crc16_ccitt(const uint8_t *data, uint32_t len) {
    uint16_t crc = 0xFFFFu;
    for (uint32_t i = 0; i < len; ++i) {
      crc ^= (uint16_t)(data[i] << 8);
      for (int b = 0; b < 8; ++b) {
        crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u)
                              : (uint16_t)(crc << 1);
      }
    }
    return crc;
  }

  static uint64_t hashName(llvm::StringRef S) {
    uint64_t h = 1469598103934665603ULL;
    for (char c : S) {
      h ^= static_cast<uint8_t>(c);
      h *= 1099511628211ULL;
    }
    return h ? h : 0x9e3779b97f4a7c15ULL;
  }

  void beginInst() { CurInst.clear(); }

  void endInst() {
    uint32_t len = static_cast<uint32_t>(CurInst.size());
    assert(len <= 0xFFFF && "instruction too large for u16 length");
    uint32_t off = static_cast<uint32_t>(Code.size());
    p16(Code, static_cast<uint16_t>(len));
    uint16_t crc = crc16_ccitt(CurInst.data(), len);
    p16(Code, crc);
    Code.insert(Code.end(), CurInst.begin(), CurInst.end());
    Instrs.push_back({off, static_cast<uint32_t>(kHdrBytes + len)});
  }

  void emit8(uint8_t v)  { p8(CurInst, v); }
  void emit16(uint16_t v){ p16(CurInst, v); }
  void emit32(uint32_t v){ p32(CurInst, v); }
  void emit64(uint64_t v){ p64(CurInst, v); }

  // Expand ConstantExpr to instructions
  void expandConstantExprs() {
    for (auto &BB : F) {
      for (auto II = BB.begin(); II != BB.end(); ++II) {
        llvm::Instruction *I = &*II;
        for (unsigned oi=0; oi<I->getNumOperands(); ++oi) {
          if (auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(I->getOperand(oi))) {
            llvm::Instruction *NewI = CE->getAsInstruction();
            NewI->insertBefore(I);
            I->setOperand(oi, NewI);
          }
        }
      }
    }
  }

  // Allocate slots for return value and parameters
  void enterFunction() {
    if (!F.getReturnType()->isVoidTy())
      allocSlot(&F, F.getReturnType());

    ParamMap.clear();
    for (auto &A : F.args()) {
      uint32_t off = allocSlot(&A, A.getType());
      uint32_t sz  = slotSizeForType(DL, A.getType());
      ParamMap.push_back({off, sz});
    }
  }

  void emitParamMap() {
    beginInst();
    emit8(OP_PARAMMAP);
    emit32((uint32_t)ParamMap.size());
    for (auto &pd : ParamMap) { emit32(pd.off); emit32(pd.size); }
    endInst();
  }

  uint32_t allocSlot(const llvm::Value* V, llvm::Type* Ty) {
    if (auto it = SlotOf.find(V); it!=SlotOf.end()) return it->second;
    CurrDataOffset = align8(CurrDataOffset);
    uint32_t off = CurrDataOffset;
    uint32_t sz  = slotSizeForType(DL, Ty);
    CurrDataOffset += sz;
    SlotOf[V] = off;
    return off;
  }

  // Materialize const pointer via OP_CALL
  void materializeConstPtrIfPossible(llvm::Value *V) {
    if (!V->getType()->isPointerTy()) return;
    if (ConstPtrDone.count(V)) return;

    if (llvm::Constant *C8 = Tool.tryMakeConstPtrExpr(V)) {
      uint64_t kid = Tool.ensureConstAddrId(C8);
      uint32_t dst = allocSlot(V, V->getType());

      assert(CurInst.empty() && "materializeConstPtrIfPossible must be called before beginInst()");
      beginInst();
      emit8(OP_CALL);
      emit64(kid);
      emit32(dst);
      emit32(0);
      endInst();

      ConstPtrDone.insert(V);
    }
  }

  void encodeValue(llvm::Value* V) {
    using namespace llvm;

    if (V->getType()->isPointerTy()) {
      uint32_t off = allocSlot(V, V->getType());
      emit8(VT_SLOT); emit32(off);
      return;
    }

    if (auto *CI = dyn_cast<ConstantInt>(V)) {
      emit8(VT_CONST); emit8(CK_INT);
      uint64_t v = CI->getValue().zextOrTrunc(64).getZExtValue();
      emit32(8); emit64(v); return;
    }
    if (auto *CF = dyn_cast<ConstantFP>(V)) {
      if (CF->getType()->isDoubleTy()) {
        emit8(VT_CONST); emit8(CK_F64); emit32(8);
        uint64_t bits = CF->getValueAPF().bitcastToAPInt().getZExtValue();
        emit64(bits); return;
      } else if (CF->getType()->isFloatTy()) {
        emit8(VT_CONST); emit8(CK_F32); emit32(8);
        uint32_t bits = CF->getValueAPF().bitcastToAPInt().getZExtValue();
        emit64((uint64_t)bits); return;
      }
    }

    if (isa<Constant>(V)) {
      uint32_t off = allocSlot(V, V->getType());
      emit8(VT_SLOT); emit32(off); return;
    }

    uint32_t off = allocSlot(V, V->getType());
    emit8(VT_SLOT); emit32(off);
  }

  void markBB(const llvm::BasicBlock* BB) { AddrOfBB[BB] = (uint32_t)Code.size(); }

  void translateInst(llvm::Instruction &I) {
    using namespace llvm;
    switch (I.getOpcode()) {
      case Instruction::Alloca:  return t_allo(cast<AllocaInst>(I));
      case Instruction::Load:    return t_load(cast<LoadInst>(I));
      case Instruction::Store:   return t_store(cast<StoreInst>(I));
      case Instruction::Br:      return t_br(cast<BranchInst>(I));
      case Instruction::Ret:     return t_ret(cast<ReturnInst>(I));
      case Instruction::BitCast:
      case Instruction::PtrToInt:
      case Instruction::IntToPtr:
      case Instruction::Trunc:
      case Instruction::ZExt:
      case Instruction::SExt:
      case Instruction::FPToUI:
      case Instruction::FPToSI:
      case Instruction::UIToFP:
      case Instruction::SIToFP:
      case Instruction::FPExt:
      case Instruction::FPTrunc:
        return t_cast(cast<CastInst>(I));
      default: break;
    }
    if (auto *BO = llvm::dyn_cast<llvm::BinaryOperator>(&I)) return t_binop(*BO);
    if (auto *CI = llvm::dyn_cast<llvm::CmpInst>(&I))        return t_cmp(*CI);
    if (auto *G  = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) return t_gep(*G);
    if (auto *CB = llvm::dyn_cast<llvm::CallBase>(&I))       return t_call(*CB);

    llvm::errs() << "[VMCodeGen] unsupported inst: " << I << "\n";
  }

  void t_allo(llvm::AllocaInst &I) {
    uint32_t res_off = allocSlot(&I, I.getType());
    uint64_t area_sz = slotSizeForType(DL, I.getAllocatedType());
    beginInst();
    emit8(OP_ALLOCA); emit32(res_off); emit32((uint32_t)area_sz);
    endInst();
  }

  void t_load(llvm::LoadInst &I) {
    materializeConstPtrIfPossible(I.getPointerOperand());
    uint32_t dst = allocSlot(&I, I.getType());
    beginInst();
    emit8(OP_LOAD); emit32(dst);
    encodeValue(I.getPointerOperand());
    endInst();
  }

  void t_store(llvm::StoreInst &I) {
    if (I.getValueOperand()->getType()->isPointerTy())
      materializeConstPtrIfPossible(I.getValueOperand());
    materializeConstPtrIfPossible(I.getPointerOperand());

    beginInst();
    emit8(OP_STORE);
    encodeValue(I.getValueOperand());
    encodeValue(I.getPointerOperand());
    endInst();
  }

  struct ArithEnc { uint8_t sub; uint8_t tk; uint8_t bits; };
  std::optional<ArithEnc> mapLLVMArith(const llvm::Instruction &I) {
    using namespace llvm;
    ArithEnc E{};
    switch (I.getOpcode()) {
      case Instruction::Add:  E.sub=AR_ADD;  E.tk=TK_INT; break;
      case Instruction::Sub:  E.sub=AR_SUB;  E.tk=TK_INT; break;
      case Instruction::Mul:  E.sub=AR_MUL;  E.tk=TK_INT; break;
      case Instruction::UDiv: E.sub=AR_UDIV; E.tk=TK_INT; break;
      case Instruction::SDiv: E.sub=AR_SDIV; E.tk=TK_INT; break;
      case Instruction::URem: E.sub=AR_UREM; E.tk=TK_INT; break;
      case Instruction::SRem: E.sub=AR_SREM; E.tk=TK_INT; break;
      case Instruction::Shl:  E.sub=AR_SHL;  E.tk=TK_INT; break;
      case Instruction::LShr: E.sub=AR_LSHR; E.tk=TK_INT; break;
      case Instruction::AShr: E.sub=AR_ASHR; E.tk=TK_INT; break;
      case Instruction::And:  E.sub=AR_AND;  E.tk=TK_INT; break;
      case Instruction::Or:   E.sub=AR_OR;   E.tk=TK_INT; break;
      case Instruction::Xor:  E.sub=AR_XOR;  E.tk=TK_INT; break;
      case Instruction::FAdd: E.sub=AR_FADD; E.tk=TK_FP;  break;
      case Instruction::FSub: E.sub=AR_FSUB; E.tk=TK_FP;  break;
      case Instruction::FMul: E.sub=AR_FMUL; E.tk=TK_FP;  break;
      case Instruction::FDiv: E.sub=AR_FDIV; E.tk=TK_FP;  break;
      case Instruction::FRem: E.sub=AR_FREM; E.tk=TK_FP;  break;
      default: return std::nullopt;
    }
    if (E.tk == TK_INT) {
      if (!I.getType()->isIntegerTy()) return std::nullopt;
      unsigned bw = I.getType()->getIntegerBitWidth();
      if (bw==8||bw==16||bw==32||bw==64) E.bits = (uint8_t)bw;
      else return std::nullopt;
    } else {
      if      (I.getType()->isFloatTy())  E.bits = 32;
      else if (I.getType()->isDoubleTy()) E.bits = 64;
      else return std::nullopt;
    }
    return E;
  }

  void t_binop(llvm::BinaryOperator &I) {
    materializeConstPtrIfPossible(I.getOperand(0));
    materializeConstPtrIfPossible(I.getOperand(1));
    auto Enc = mapLLVMArith(I);
    if (!Enc) { llvm::errs() << "[VMCodeGen] unsupported binop for ARITH: " << I << "\n"; return; }
    uint32_t dst = allocSlot(&I, I.getType());
    beginInst();
    emit8(OP_ARITH); emit8(Enc->sub); emit8(Enc->tk); emit8(Enc->bits);
    emit32(dst);
    encodeValue(I.getOperand(0));
    encodeValue(I.getOperand(1));
    endInst();
  }

  void t_cmp(llvm::CmpInst &I) {
    materializeConstPtrIfPossible(I.getOperand(0));
    materializeConstPtrIfPossible(I.getOperand(1));
    uint32_t dst = allocSlot(&I, I.getType());
    beginInst();
    emit8(OP_CMP);
    emit8((uint8_t)I.getPredicate());
    emit32(dst);
    encodeValue(I.getOperand(0));
    encodeValue(I.getOperand(1));
    endInst();
  }

  void t_cast(llvm::CastInst &I) {
    materializeConstPtrIfPossible(I.getOperand(0));
    if (I.getType()->isPointerTy()) {
      materializeConstPtrIfPossible(&I);
      if (ConstPtrDone.count(&I)) return;
    }

    uint32_t dst = allocSlot(&I, I.getType());
    beginInst();
    emit8(OP_CAST);
    emit8((uint8_t)I.getOpcode());
    emit32(dst);
    encodeValue(I.getOperand(0));
    endInst();
  }

  void t_gep(llvm::GetElementPtrInst &I) {
    materializeConstPtrIfPossible(&I);
    if (ConstPtrDone.count(&I)) return;

    materializeConstPtrIfPossible(I.getPointerOperand());

    uint32_t dst = allocSlot(&I, I.getType());
    beginInst();
    emit8(OP_GEP);
    emit32(dst);
    encodeValue(I.getPointerOperand());
    unsigned n = I.getNumIndices();
    emit32(n);
    for (auto Idx = I.idx_begin(); Idx != I.idx_end(); ++Idx) encodeValue(*Idx);
    endInst();
  }

  void t_br(llvm::BranchInst &I) {
    beginInst();
    emit8(OP_BR);
    if (I.isUnconditional()) {
      emit8(0);
      uint32_t pos = (uint32_t)Code.size() + kHdrBytes + (uint32_t)CurInst.size();
      emit32(0);
      BrFixups.push_back({pos, I.getSuccessor(0)});
    } else {
      emit8(1);
      encodeValue(I.getCondition());
      uint32_t posT = (uint32_t)Code.size() + kHdrBytes + (uint32_t)CurInst.size();
      emit32(0);
      BrFixups.push_back({posT, I.getSuccessor(0)});
      uint32_t posF = (uint32_t)Code.size() + kHdrBytes + (uint32_t)CurInst.size();
      emit32(0);
      BrFixups.push_back({posF, I.getSuccessor(1)});
    }
    endInst();
  }

  void t_ret(llvm::ReturnInst &I) {
    if (I.getNumOperands() != 0)
      materializeConstPtrIfPossible(I.getReturnValue());
    beginInst();
    emit8(OP_RET);
    if (I.getNumOperands()==0) {
      emit8(VT_CONST); emit8(CK_INT); emit32(8); emit64(0);
    } else {
      encodeValue(I.getReturnValue());
    }
    endInst();
  }

  void t_call(llvm::CallBase &CB) {
    for (unsigned i=0;i<CB.arg_size();++i)
      materializeConstPtrIfPossible(CB.getArgOperand(i));
    uint64_t id = Tool.ensureCallId(&CB);
    beginInst();
    emit8(OP_CALL);
    emit64(id);

    if (!CB.getType()->isVoidTy()) {
      uint32_t dst = allocSlot(&CB, CB.getType());
      emit32(dst);
    } else {
      emit32(UINT32_C(0xFFFFFFFF));
    }

    std::vector<uint32_t> dynOffs;
    dynOffs.reserve(CB.arg_size());
    for (unsigned i=0;i<CB.arg_size();++i) {
      llvm::Value *A = CB.getArgOperand(i);
      if (isConstLike(A)) continue;
      dynOffs.push_back( allocSlot(A, A->getType()) );
    }

    emit32((uint32_t)dynOffs.size());
    for (uint32_t off : dynOffs) emit32(off);
    endInst();
  }

  void patchBranches() {
    for (auto &fx : BrFixups) {
      auto it = AddrOfBB.find(fx.target);
      assert(it != AddrOfBB.end() && "target BB not seen?");
      uint32_t addr = it->second;
      Code[fx.pos+0] = uint8_t(addr);
      Code[fx.pos+1] = uint8_t(addr>>8);
      Code[fx.pos+2] = uint8_t(addr>>16);
      Code[fx.pos+3] = uint8_t(addr>>24);
    }
  }

  void refreshCrcs() {
    for (const auto &I : Instrs) {
      uint8_t *inst = Code.data() + I.off;
      uint16_t len = (uint16_t)inst[0] | ((uint16_t)inst[1] << 8);
      if (len == 0)
        continue;
      uint16_t crc = crc16_ccitt(inst + kHdrBytes, len);
      inst[2] = (uint8_t)(crc & 0xFF);
      inst[3] = (uint8_t)((crc >> 8) & 0xFF);
    }
  }

  void buildIpHashSet() {
    IpHashSet.clear();
    const llvm::BasicBlock *Entry = &F.getEntryBlock();
    for (auto &BB : F) {
      bool UseHash = false;
      if (&BB != Entry)
        UseHash = true;
      if (UseHash) {
        auto it = AddrOfBB.find(&BB);
        if (it != AddrOfBB.end())
          IpHashSet.insert(it->second);
      }
    }
#ifdef SVM_CODEGEN_DEBUG
    llvm::errs() << "[svm.codegen] hashset.size=" << IpHashSet.size() << "\n";
    for (auto ip : IpHashSet) {
      llvm::errs() << "[svm.codegen] hash.ip=0x" << llvm::format_hex(ip, 6) << "\n";
    }
#endif
  }

  void encryptInstructions(uint64_t seed) {
    uint64_t key = seed;
    for (const auto &I : Instrs) {
      const uint8_t *plain = Code.data() + I.off;
      uint16_t len = (uint16_t)plain[0] | ((uint16_t)plain[1] << 8);
      uint8_t opcode = (I.len > kHdrBytes) ? plain[kHdrBytes] : 0;
      uint64_t ip = I.off;
      if (IpHashSet.count((uint32_t)ip)) {
        key = hashSeedIp(seed, ip);
      }
#ifdef SVM_CODEGEN_DEBUG
      llvm::errs() << "[svm.codegen] ip=" << llvm::format_hex(ip, 6)
                   << " len=" << len
                   << " op=" << llvm::format_hex((unsigned)opcode, 4)
                   << " key=" << llvm::format_hex(key, 18)
                   << " mode=" << (IpHashSet.count((uint32_t)ip) ? "hash" : "chain")
                   << "\n";
#endif
      uint64_t ks = key;
      for (uint32_t i = 0; i < I.len; ++i) {
        Code[I.off + i] = plain[i] ^ nextStreamByte(ks);
      }
      key = mixKey(key, ip, opcode, len);
    }
  }
};

} // namespace vmp
