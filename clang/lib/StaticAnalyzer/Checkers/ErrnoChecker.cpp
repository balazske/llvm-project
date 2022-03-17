//=== ErrnoChecker.cpp ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//
//===----------------------------------------------------------------------===//

#include "ErrnoModeling.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/ADT/STLExtras.h"

using namespace clang;
using namespace ento;
using namespace errno_modeling;

namespace {

class ErrnoChecker : public Checker<check::BeginFunction, check::Location,
                                    check::RegionChanges> {
public:
  void checkBeginFunction(CheckerContext &C) const;
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                     CheckerContext &) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const;
  ProgramStateRef
  checkRegionChanges(ProgramStateRef State,
                     const InvalidatedSymbols *Invalidated,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *> Regions,
                     const LocationContext *LCtx, const CallEvent *Call) const;

private:
  mutable bool ErrnoInitialized = false;
  mutable Optional<Loc> ErrnoLoc;
  mutable const MemRegion *ErrnoRegion = nullptr;

  void initErrno(CheckerContext &C) const;

  BugType BT_InvalidErrnoRead{this, "Value of 'errno' could be undefined",
                              "Error handling"};
  BugType BT_ErrnoNotChecked{this, "Value of 'errno' was not checked",
                             "Error handling"};
};

} // namespace

void ErrnoChecker::initErrno(CheckerContext &C) const {
  if (ErrnoInitialized)
    return;

  ErrnoLoc = getErrnoLoc(C.getState());
  if (ErrnoLoc) {
    ErrnoRegion = ErrnoLoc->getAsRegion();
    assert(ErrnoRegion && "The 'errno' location should be a memory region.");
  }
  ErrnoInitialized = true;
}

void ErrnoChecker::checkBeginFunction(CheckerContext &C) const {
  // The errno location must be refreshed at every new function.
  ErrnoInitialized = false;
}

void ErrnoChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                                 CheckerContext &C) const {
  initErrno(C);
  if (!ErrnoLoc)
    return;

  if (auto L = Loc.getAs<ento::Loc>()) {
    if (*ErrnoLoc != *L)
      return;

    ProgramStateRef State = C.getState();
    ErrnoCheckState EState = getErrnoState(State);

    if (IsLoad) {
      switch (EState) {
      case Errno_MustNotBeChecked:
        // Read of 'errno' when it may have undefined value.
        if (ExplodedNode *N = C.generateErrorNode()) {
          C.emitReport(std::make_unique<PathSensitiveBugReport>(
              BT_InvalidErrnoRead,
              "Value of 'errno' could be undefined after a call to a function "
              "that does not promise to not change 'errno'.",
              N));
        }
        break;
      case Errno_MustBeChecked:
        // 'errno' has to be checked. A load is required for this, with no more
        // information we can assume that it is checked somehow.
        // After this place 'errno' is allowed to be read and written.
        State = setErrnoStateIrrelevant(State);
        C.addTransition(State);
        break;
      default:
        break;
      }
    } else {
      switch (EState) {
      case Errno_MustBeChecked:
        // 'errno' is overwritten without a read before but it should have been
        // checked.
        if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
          C.emitReport(std::make_unique<PathSensitiveBugReport>(
              BT_ErrnoNotChecked,
              "Value of 'errno' was not checked after a call to a function "
              "that possibly failed and indicates failure only by value of "
              "'errno'",
              N));
        }
        break;
      case Errno_MustNotBeChecked:
        // Write to 'errno' when it is not allowed to be read.
        // After this place 'errno' is allowed to be read and written.
        State = setErrnoStateIrrelevant(State);
        C.addTransition(State);
        break;
      default:
        break;
      }
    }
  }
}

ProgramStateRef ErrnoChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *Invalidated,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *Call) const {
  // If 'errno' is invalidated we can not know if it is checked or written into,
  // allow read and write without bug reports.
  if (llvm::find(Regions, ErrnoRegion) != Regions.end())
    return setErrnoStateIrrelevant(State);

  // Always reset errno state when the system memory space is invalidated.
  // The ErrnoRegion is not always found in the list in this case.
  const MemSpaceRegion *GlobalSystemSpace =
      State->getStateManager().getRegionManager().getGlobalsRegion(
          MemRegion::GlobalSystemSpaceRegionKind);
  if (llvm::find(Regions, GlobalSystemSpace) != Regions.end())
    return setErrnoStateIrrelevant(State);

  return State;
}

void ento::registerErrnoChecker(CheckerManager &mgr) {
  mgr.registerChecker<ErrnoChecker>();
}

bool ento::shouldRegisterErrnoChecker(const CheckerManager &mgr) {
  return true;
}
