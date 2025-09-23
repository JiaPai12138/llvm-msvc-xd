//code from https://github.com/tijme/dittobytes

#include "CodePicPass.h"
#include "CryptoUtils.h"
#include "Utils.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO/GlobalOpt.h"


#include <cstdint>
#include <iomanip>
#include <set>
#include <sstream>
#include <vector>

using namespace llvm;

static cl::opt<bool>
    RunCodePIC("x-pic", cl::init(false),
                            cl::desc("OLLVM - Code PIC force"));

static cl::opt<bool>
    ExpandMemcpy("xpic-memcpy", cl::init(false),
                            cl::desc("OLLVM - Code PIC force memcpy"));

static cl::opt<bool>
    ExpandMemset("xpic-memset", cl::init(false),
                            cl::desc("OLLVM - Code PIC force memset"));

static cl::opt<bool>
    picGlobalToStack("xpic-global", cl::init(false),
                            cl::desc("OLLVM - Code PIC force global var to stack var"));
                            
/**
 * A class to expand `memcpy` calls to manual copies.
 */
class ExpandMemcpyCallsModule {

private:

    /**
     * Whether this class modified the intermediate function.
     */
    bool modified = false;

    /**
     * Whether the module is enabled (default) or disabled.
     * 
     * @returns bool Positive if enabled.
     */
    bool moduleIsEnabled() {
        return ExpandMemcpy;
    }

public:

    /**
     * Main execution method for the ExpandMemcpyCallsModule class.
     *
     * @param Function& F The intermediate function to expand memcpy calls in.
     * @return bool Indicates if the intermediate function was modified.
     */
    bool run(Function &F) {
        // Ensure module is enabled
        if (!moduleIsEnabled()) return false;
        
        SmallVector<CallInst *, 8> MemCpyCalls;

        // Inform user that we are running this module
        dbgs() << "         Running ExpandMemcpyCalls module.\n";

        for (auto &BB : F) {
            for (auto &I : BB) {
                if (auto *CI = dyn_cast<CallInst>(&I)) {
                    if (auto *F = CI->getCalledFunction()) {
                        if (F->getName().starts_with("llvm.memcpy")) {
                            MemCpyCalls.push_back(CI);
                        }
                    }
                }
            }
        }

        for (auto *CI : MemCpyCalls) {
            // Inform user that we encountered a `memcpy` call
            dbgs() << "           Expanding a `memcpy` call.\n";

            auto *Dst = CI->getArgOperand(0);
            auto *Src = CI->getArgOperand(1);
            auto *Len = CI->getArgOperand(2);
            auto *IsVolatile = CI->getArgOperand(3);

            if (auto *ConstLen = dyn_cast<ConstantInt>(Len)) {
                uint64_t Size = ConstLen->getZExtValue();
                IRBuilder<> IRB(CI);

                for (uint64_t i = 0; i < Size; ++i) {
                    Value *Offset = IRB.getInt64(i);
                    Value *SrcGEP = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Src, Offset);
                    Value *DstGEP = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Dst, Offset);
                    LoadInst *Load = IRB.CreateLoad(IRB.getInt8Ty(), SrcGEP);
                    Load->setVolatile(cast<ConstantInt>(IsVolatile)->isOne());
                    StoreInst *Store = IRB.CreateStore(Load, DstGEP);
                    Store->setVolatile(cast<ConstantInt>(IsVolatile)->isOne());
                }

                CI->eraseFromParent();
                modified = true;
            }
        }

        return modified;
    }

};


/**
 * A class to expand `memset` calls to manual sets.
 */
class ExpandMemsetCallsModule  {

private:

    /**
     * Whether this class modified the intermediate function.
     */
    bool modified = false;

    /**
     * Whether the module is enabled (default) or disabled.
     * 
     * @returns bool Positive if enabled.
     */
    bool moduleIsEnabled() {
        return ExpandMemset;
    }

public:

    /**
     * Main execution method for the ExpandMemsetCallsModule class.
     *
     * @param Function& F The intermediate function to expand memset calls in.
     * @return bool Indicates if the intermediate function was modified.
     */
    bool run(Function &F) {
        // Ensure module is enabled
        if (!moduleIsEnabled()) return false;
        
        SmallVector<CallInst *, 8> MemSetCalls;

        // Inform user that we are running this module
        dbgs() << "         Running ExpandMemsetCalls module.\n";

        for (auto &BB : F) {
            for (auto &I : BB) {
                if (auto *CI = dyn_cast<CallInst>(&I)) {
                    if (auto *F = CI->getCalledFunction()) {
                        if (F->getName().starts_with("llvm.memset")) {
                            MemSetCalls.push_back(CI);
                        }
                    }
                }
            }
        }

        for (auto *CI : MemSetCalls) {
            // Inform user that we encountered a `memset` call
            dbgs() << "           Expanding a `memset` call.\n";

            auto *Dst = CI->getArgOperand(0);
            auto *Val = CI->getArgOperand(1);
            auto *Len = CI->getArgOperand(2);
            auto *IsVolatile = CI->getArgOperand(3);

            if (auto *ConstLen = dyn_cast<ConstantInt>(Len)) {
                uint64_t Size = ConstLen->getZExtValue();
                IRBuilder<> IRB(CI);

                // Value to be set (need to truncate/extend to i8 if not already)
                Value *ValueToSet = IRB.CreateTruncOrBitCast(Val, IRB.getInt8Ty());
                for (uint64_t i = 0; i < Size; ++i) {
                    Value *Offset = IRB.getInt64(i);
                    Value *DstGEP = IRB.CreateInBoundsGEP(IRB.getInt8Ty(), Dst, Offset);
                    StoreInst *Store = IRB.CreateStore(ValueToSet, DstGEP);
                    Store->setVolatile(cast<ConstantInt>(IsVolatile)->isOne());
                }

                CI->eraseFromParent();
                modified = true;
            }
        }

        return modified;
    }

};


/**
 * A class to move globals to the stack.
 */
class MoveGlobalsToStackModule {

private:

    /**
     * Whether the module is enabled (default) or disabled.
     * 
     * @returns bool Positive if enabled.
     */
    bool moduleIsEnabled() {
        return picGlobalToStack;
    }

public:

    /**
     * Main execution method for the MoveGlobalsToStackModule class.
     *
     * @param Module& M The intermediate module to run on.
     * @param ModuleAnalysisManager& The LLVM module analysis manager.
     * @return bool Indicates if the intermediate module was modified.
     */
    bool run(Module &M, ModuleAnalysisManager &) {
        // Ensure module is enabled
        if (!moduleIsEnabled()) return false;
        
        // Inform user that we are running this module
        dbgs() << "         Running MoveGlobalsToStackModule module.\n";

        SmallMapVector<Function *, SmallSetVector<GlobalVariable *, 4>, 4> usage;

        for (GlobalVariable &G : M.globals()) {
            if (shouldInline(G)) {
                usage[getUsingFunction(G)].insert(&G);
            }
        }

        for (auto &KV : usage) {
            inlineGlobals(M, KV.first, KV.second);
        }

        return !usage.empty();
    }

private:

    Function * getUsingFunction(Value & V) {
        Function * F = nullptr;

        SmallVector < User * , 4 > Worklist;
        SmallSet < User * , 4 > Visited;

        for (auto * U: V.users())
            Worklist.push_back(U);
        while (!Worklist.empty()) {
            auto * U = Worklist.pop_back_val();

            if (Visited.count(U))
                continue;
            else
                Visited.insert(U);

            if (isa < ConstantExpr > (U) || isa < ConstantAggregate > (U) ||
                isa < GlobalVariable > (U)) {
                if (isa < GlobalVariable > (U) &&
                    !cast < GlobalVariable > (U) -> isDiscardableIfUnused())
                    return nullptr;
                for (auto * UU: U -> users()) {
                    Worklist.push_back(UU);
                }
                continue;
            }

            auto * I = dyn_cast < Instruction > (U);
            if (!I)
                return nullptr;
            if (!F)
                F = I -> getParent() -> getParent();
            if (I -> getParent() -> getParent() != F)
                return nullptr;
        }

        return F;
    }

    bool shouldInline(GlobalVariable & G) {
        if (!G.isDiscardableIfUnused())
            return false; // Goal is to discard these; ignore if that's not possible

        if (!getUsingFunction(G))
            return false; // This isn't safe. We can only be on one function's stack.

        return true;
    }

    void inlineGlobals(Module &M, Function *F, SmallSetVector<GlobalVariable *, 4> &Vars) {
        BasicBlock &BB = F->getEntryBlock();
        Instruction *insertionPoint = &*BB.getFirstInsertionPt();
        LLVMContext &Ctx = F->getContext();

        IRBuilder<> builder(insertionPoint);

        SmallMapVector<GlobalVariable *, Value *, 4> Replacements;
        StoreInst * firstStore = nullptr;

        for (auto *G : Vars) {
            Constant *initializer = G->getInitializer();
            Type *globalType = G->getValueType();

            dbgs() << "         Found a global variable to inline.\n";

            if (!initializer) {
                dbgs() << "         Skipping global (no initializer): " << G->getName() << "\n";
                continue;
            }

            bool isString = false;

            if (auto *CA = dyn_cast<ConstantDataArray>(initializer)) {
                if (CA->isString()) {

                    isString = true;

                    // Allocate one contiguous stack buffer for the entire global
                    AllocaInst *alloca = builder.CreateAlloca(globalType, nullptr, G->getName() + ".stack");
                    Replacements[G] = alloca;

                    // Get size in bytes of the global type
                    uint64_t sizeInBytes = M.getDataLayout().getTypeAllocSize(globalType);

                    // Flatten initializer to raw bytes
                    SmallVector<uint8_t, 64> data;
                    {
                        // Use DataLayout helper to get raw bytes from constant initializer
                        // Since LLVM has no direct API, use ConstantDataSequential or ConstantAggregate parsing:
                        if (auto *CDS = dyn_cast<ConstantDataSequential>(initializer)) {
                            StringRef raw = CDS->getRawDataValues();
                            data.append(raw.bytes_begin(), raw.bytes_end());
                        } else if (auto *CI = dyn_cast<ConstantInt>(initializer)) {
                            uint64_t val = CI->getZExtValue();
                            data.resize(sizeInBytes, 0);
                            memcpy(data.data(), &val, std::min(sizeInBytes, static_cast<uint64_t>(8)));
                        } else if (auto *CA = dyn_cast<ConstantAggregate>(initializer)) {
                            // Rough fallback: serialize each element recursively (not implemented here)
                            // Just zero fill to be safe
                            data.resize(sizeInBytes, 0);
                        } else {
                            // Unsupported initializer type, zero initialize
                            data.resize(sizeInBytes, 0);
                        }
                    }

                    // Store bytes in largest chunks into alloca sequentially
                    uint64_t offset = 0;
                    while (offset < sizeInBytes) {
                        uint64_t remaining = sizeInBytes - offset;
                        Type *writeType;
                        size_t writeSize;

                        if (remaining >= 8) {
                            writeType = Type::getInt64Ty(Ctx);
                            writeSize = 8;
                        } else if (remaining >= 4) {
                            writeType = Type::getInt32Ty(Ctx);
                            writeSize = 4;
                        } else if (remaining >= 2) {
                            writeType = Type::getInt16Ty(Ctx);
                            writeSize = 2;
                        } else {
                            writeType = Type::getInt8Ty(Ctx);
                            writeSize = 1;
                        }

                        uint64_t chunk = 0;
                        memcpy(&chunk, data.data() + offset, writeSize);

                        // Compute pointer to offset bytes inside alloca
                        // Value *bytePtr = builder.CreateBitCast(alloca, Type::getInt8PtrTy(Ctx));
                        Value *bytePtr = builder.CreateBitCast(alloca, builder.getPtrTy());

                        Value *gepPtr = builder.CreateGEP(Type::getInt8Ty(Ctx), bytePtr,
                                                         ConstantInt::get(Type::getInt64Ty(Ctx), offset));
                        Value *castedPtr = builder.CreateBitCast(gepPtr, PointerType::getUnqual(writeType));

                        builder.CreateStore(ConstantInt::get(writeType, chunk), castedPtr);

                        offset += writeSize;
                    }

                }
            }

            if (!isString) {

                Instruction * inst =
                    new AllocaInst(G -> getValueType(), G -> getType() -> getAddressSpace(),
                        nullptr, G -> getAlign().valueOrOne(), "",
                        firstStore ? firstStore : insertionPoint);

                inst -> takeName(G);

                Replacements[G] = inst;

                if (G -> hasInitializer()) {
                    Constant * initializer = G -> getInitializer();
                    StoreInst * store = new StoreInst(initializer, inst, insertionPoint);
                    G -> setInitializer(nullptr);

                    extractValuesFromStore(store, Vars);

                    if (!firstStore)
                        firstStore = store;
                }



            }
            
        }

        // Replace all uses of globals with their alloca pointers
        for (auto *G : Vars) {
            if (!Replacements.count(G))
                continue;
            
            Value *replacement = Replacements[G];

            SmallVector<User *, 8> users(G->users());
            for (User *U : users) {
                if (auto *CE = dyn_cast<ConstantExpr>(U)) {
                    // For constant expr users, replace their uses recursively
                    SmallVector<User *, 8> CEUsers(CE->users());
                    for (User *CEUser : CEUsers) {
                        if (Instruction *I = dyn_cast<Instruction>(CEUser)) {
                            IRBuilder<> ib(I);
                            Value *replacementVal = CE;
                            if (CE->getOpcode() == Instruction::BitCast) {
                                replacementVal = ib.CreateBitCast(replacement, CE->getType());
                            }
                            I->replaceUsesOfWith(CE, replacementVal);
                        }
                    }
                } else if (Instruction *I = dyn_cast<Instruction>(U)) {
                    I->replaceUsesOfWith(G, replacement);
                }
            }

            G->eraseFromParent();
        }
    }




    // Copied from GlobalOpt.cpp
    void makeAllConstantUsesInstructions(Constant * C) {
        SmallVector < ConstantExpr * , 4 > Users;
        for (auto * U: C -> users()) {
            if (auto * CE = dyn_cast < ConstantExpr > (U))
                Users.push_back(CE);
            else
                // We should never get here; allNonInstructionUsersCanBeMadeInstructions
                // should not have returned true for C.
                assert(
                    isa < Instruction > (U) &&
                    "Can't transform non-constantexpr non-instruction to instruction!");
        }

        SmallVector < Instruction * , 4 > CEUsers;
        for (auto * U: Users) {
            // DFS DAG traversal of U to eliminate ConstantExprs recursively
            ConstantExpr * CE = nullptr;

            do {
                CE = U; // Start by trying to destroy the root

                CEUsers.clear();
                auto it = CE -> user_begin();
                while (it != CE -> user_end()) {
                    if (isa < ConstantExpr > ( * it)) {
                        // Recursive ConstantExpr found; switch to it
                        CEUsers.clear();
                        CE = cast < ConstantExpr > ( * it);
                        it = CE -> user_begin();
                    } else {
                        // Function; add to UUsers
                        CEUsers.push_back(cast < Instruction > ( * it));
                        it++;
                    }
                }

                // All users of CE are instructions; replace CE with an instruction for
                // each
                for (auto * CEU: CEUsers) {
                    Instruction * NewU = CE -> getAsInstruction();
                    NewU -> insertBefore(CEU);
                    CEU -> replaceUsesOfWith(CE, NewU);
                }

                // We've replaced all the uses, so destroy the constant. (destroyConstant
                // will update value handles and metadata.)
                CE -> destroyConstant();
            } while (CE != U); // Continue until U is destroyed
        }
    }



    void disaggregateVars(
        Instruction * After, Value * Ptr, SmallVectorImpl < Value * > & Idx,
        ConstantAggregate & C, SmallSetVector < GlobalVariable * , 4 > & Vars) {
        SmallSetVector < Value * , 4 > ToUndefine;

        Constant * C2;
        for (unsigned i = 0;
            (C2 = C.getAggregateElement(i)); i++) {
            Idx.push_back(ConstantInt::get(
                Type::getInt32Ty(After -> getParent() -> getContext()), i));

            if (isa < ConstantAggregate > (C2)) {
                disaggregateVars(After, Ptr, Idx, cast < ConstantAggregate > ( * C2), Vars);

            } else if (isa < ConstantExpr > (C2) ||
                (isa < GlobalVariable > (C2) &&
                    Vars.count(cast < GlobalVariable > (C2)))) {
                GetElementPtrInst * GEP =
                    GetElementPtrInst::CreateInBounds(C.getType(), Ptr, Idx);
                GEP -> insertAfter(After);

                ToUndefine.insert(C2);

                new StoreInst(C2, GEP, GEP -> getNextNode());
            }

            Idx.pop_back();
        }

        for (auto * V: ToUndefine)
            C.handleOperandChange(V, UndefValue::get(V -> getType()));
    }

    void extractValuesFromStore(
        StoreInst * inst, SmallSetVector < GlobalVariable * , 4 > & Vars) {
        Value * V = inst -> getValueOperand();
        if (!isa < ConstantAggregate > (V))
            return;

        SmallVector < Value * , 4 > Idx;
        Idx.push_back(
            ConstantInt::get(Type::getInt32Ty(inst -> getParent() -> getContext()), 0));

        disaggregateVars(inst, inst -> getPointerOperand(), Idx,
            cast < ConstantAggregate > ( * V), Vars);
    }

};


PreservedAnalyses CodePicPass::run(Function &F, FunctionAnalysisManager &FM){
    if (RunCodePIC) {
        bool modified = false;
        // Module 1: Expand `memcpy` calls
        modified = ExpandMemcpyCallsModule().run(F) || modified;

        // Module 2: Expand `memset` calls
        modified = ExpandMemsetCallsModule().run(F) || modified;

        return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
    return PreservedAnalyses::all();
}

PreservedAnalyses CodePicPass::run(Module &M, ModuleAnalysisManager &AM) {

    if (RunCodePIC) {
        bool modified = false;

        // Module 1: Move global variables to the stack
        modified = MoveGlobalsToStackModule().run(M, AM) || modified;

        return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
     return PreservedAnalyses::all();
}

CodePicPass::CodePicPass() {}

