//=== ErrnoModeling.h - Tracking value of 'errno'. -----------------*- C++ -*-//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Defines inter-checker API for using the system value 'errno'.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_ERRNOMODELING_H
#define LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_ERRNOMODELING_H

#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"

namespace clang {
namespace ento {
namespace errno_modeling {

enum ErrnoCheckState : unsigned {
  Errno_Irrelevant = 0,
  Errno_MustBeChecked = 1,
  Errno_MustNotBeChecked = 2
};

/// Returns the value of 'errno', if 'errno' was found in the AST.
llvm::Optional<SVal> getErrnoValue(ProgramStateRef State);

ErrnoCheckState getErrnoState(ProgramStateRef State);

llvm::Optional<Loc> getErrnoLoc(ProgramStateRef State);

/// Set value of 'errno' to any SVal, if possible.
ProgramStateRef setErrnoValue(ProgramStateRef State,
                              const LocationContext *LCtx, SVal Value,
                              ErrnoCheckState EState);

/// Set value of 'errno' to a concrete (signed) integer, if possible.
ProgramStateRef setErrnoValue(ProgramStateRef State, CheckerContext &C,
                              uint64_t Value, ErrnoCheckState EState);

ProgramStateRef setErrnoStateIrrelevant(ProgramStateRef State);

} // namespace errno_modeling
} // namespace ento
} // namespace clang

#endif // LLVM_CLANG_LIB_STATICANALYZER_CHECKERS_ERRNOMODELING_H
