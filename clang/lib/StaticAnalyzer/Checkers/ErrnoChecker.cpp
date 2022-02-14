//=== NoReturnFunctionChecker.cpp -------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This defines ErrnoChecker, which .....
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/StoreRef.h"
#include "llvm/ADT/STLExtras.h"
#include "Errno.h"

using namespace clang;
using namespace ento;

namespace {

class ErrnoChecker : public Checker<check::BeginFunction, eval::Call> {
public:
  void checkBeginFunction(CheckerContext &C) const;
  bool evalCall(const CallEvent &Call, CheckerContext &C) const;
};

}

REGISTER_TRAIT_WITH_PROGRAMSTATE(ErrnoRegion, const void *)

void ErrnoChecker::checkBeginFunction(CheckerContext &C) const {
  if (!C.inTopFrame())
    return;

  ASTContext &ACtx = C.getASTContext();
  IdentifierInfo &II = ACtx.Idents.get("errno");
  auto LookupRes = ACtx.getTranslationUnitDecl()->lookup(&II);
  if (LookupRes.empty())
    return;
  
  auto Found = llvm::find_if(LookupRes, [&ACtx](const Decl *D) {
    if (auto *VD = dyn_cast<VarDecl>(D))
      return VD->hasExternalStorage() && VD->getType().getCanonicalType() == ACtx.IntTy;
    return false;
  });
  if (Found == LookupRes.end())
    return;
 
  ProgramStateRef State = C.getState();
  const VarDecl *ErrnoVar = cast<VarDecl>(*Found);
  const MemRegion *ErrnoR = State->getRegion(ErrnoVar, C.getLocationContext());
  assert(ErrnoR && "Memory region should exist for the 'errno' variable.");
  State = State->set<ErrnoRegion>(reinterpret_cast<const void *>(ErrnoR));
  C.addTransition(State);
}

bool ErrnoChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  if (CallDescription{{"__errno_location"}}.matches(Call)) {
    const LocationContext *LCtx = C.getLocationContext();
    ProgramStateRef State = C.getState();
    SValBuilder &SVB = C.getSValBuilder();
    ASTContext &ACtx = C.getASTContext();

    const auto *ErrnoR = reinterpret_cast<const MemRegion *>(State->get<ErrnoRegion>());
    if (!ErrnoR) {
      MemRegionManager &RMgr = C.getStateManager().getRegionManager();
      const MemSpaceRegion *GlobalSystemSpace = RMgr.getGlobalsRegion(MemRegion::GlobalSystemSpaceRegionKind);
      assert(Call.getOriginExpr() && "Not an errno-like call?");
      const SymbolConjured *Sym = SVB.conjureSymbol(Call.getOriginExpr(), C.getLocationContext(), 1);
      assert(Sym);
      //ErrnoR = RMgr.getElementRegion(
      //  ACtx.IntTy, SVB.makeZeroArrayIndex(),
      //  RMgr.getSymbolicRegion(Sym, GlobalSystemSpace), C.getASTContext());
      ErrnoR = RMgr.getSymbolicRegion(Sym, GlobalSystemSpace);
      assert(ErrnoR);
      State = State->set<ErrnoRegion>(ErrnoR);
    }

    State = State->BindExpr(Call.getOriginExpr(), LCtx,
                            loc::MemRegionVal{ErrnoR});
    C.addTransition(State);
    return true;
  }
  if (CallDescription{{"setErrno"}}.matches(Call)) {
    const LocationContext *LCtx = C.getLocationContext();
    ProgramStateRef State = C.getState();
    SValBuilder &SVB = C.getSValBuilder();
    ASTContext &ACtx = C.getASTContext();
    State->dump();

    ProgramStateRef SuccessState = State->BindExpr(
        Call.getOriginExpr(), LCtx, SVB.makeIntVal(0, Call.getResultType()));
    SuccessState = errno_check::setErrnoValue(
        SuccessState, LCtx, SVB.makeIntVal(42, ACtx.IntTy).castAs<NonLoc>());
  
    ProgramStateRef FailureState = State->BindExpr(
        Call.getOriginExpr(), LCtx, SVB.makeIntVal(11, Call.getResultType()));
    FailureState = errno_check::setErrnoValue(
        FailureState, LCtx, SVB.makeIntVal(22, ACtx.IntTy).castAs<NonLoc>());
    FailureState->dump();

    C.addTransition(SuccessState);
    C.addTransition(FailureState);

    return true;
  }

  if (CallDescription{{"setErrno1"}}.matches(Call)) {
    const LocationContext *LCtx = C.getLocationContext();
    ProgramStateRef State = C.getState();
    SValBuilder &SVB = C.getSValBuilder();
    ASTContext &ACtx = C.getASTContext();

    ProgramStateRef SuccessState = State->BindExpr(
        Call.getOriginExpr(), LCtx, SVB.makeIntVal(0, Call.getResultType()));
    C.addTransition(SuccessState);
  
    ProgramStateRef FailureState = State->BindExpr(
        Call.getOriginExpr(), LCtx, SVB.makeIntVal(-1, Call.getResultType()));

    const auto *ErrnoR = reinterpret_cast<const MemRegion *>(FailureState->get<ErrnoRegion>());
    assert(ErrnoR && "Errno should exist for now.");
    QualType IntTy = ACtx.IntTy;
    SVal ErrnoVal = errno_check::getErrnoValue(FailureState);
    ErrnoVal.dump();
    auto ErrnoValDef = ErrnoVal.getAs<DefinedOrUnknownSVal>();
    if (!ErrnoValDef)
      return false;
    FailureState = FailureState->assume(*ErrnoValDef, true);
    //FailureState = errno_check::setErrnoValue(
    //    FailureState, LCtx, *ErrnoValDef);
    FailureState->dump();

    C.addTransition(FailureState);

    return true;
  }

  return false;
}

namespace clang {
namespace ento {
namespace errno_check {

SVal getErrnoValue(ProgramStateRef State) {
  const auto *ErrnoR = reinterpret_cast<const MemRegion *>(State->get<ErrnoRegion>());
  assert(ErrnoR && "Errno should exist for now.");
  QualType IntTy = State->getAnalysisManager().getASTContext().IntTy;
  return State->getSVal(ErrnoR, IntTy);
}

ProgramStateRef setErrnoValue(ProgramStateRef State,
                              const LocationContext *LCtx, SVal Value) {
  const auto *ErrnoR = reinterpret_cast<const MemRegion *>(State->get<ErrnoRegion>());
  assert(ErrnoR && "Errno should exist for now.");
  return State->bindLoc(loc::MemRegionVal{ErrnoR}, Value, LCtx);
}

} // namespace errno_check
} // namespace ento
} // namespace clang

void ento::registerErrnoChecker(CheckerManager &mgr) {
  mgr.registerChecker<ErrnoChecker>();
}

bool ento::shouldRegisterErrnoChecker(const CheckerManager &mgr) {
  return true;
}
