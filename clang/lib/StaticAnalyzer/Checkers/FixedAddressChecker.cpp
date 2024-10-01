//=== FixedAddressChecker.cpp - Fixed address usage checker ----*- C++ -*--===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This files defines FixedAddressChecker, a builtin checker that checks for
// assignment of a fixed address to a pointer.
// Using a fixed address is not portable because that address will probably
// not be valid in all environments or platforms.
// This check corresponds to CWE-587.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class FixedAddressChecker
    : public Checker<check::PreStmt<BinaryOperator>, check::PreStmt<DeclStmt>,
                     check::PreStmt<CallExpr>> {
  const BugType BT{this, "Use fixed address"};

  void checkUseOfFixedAddress(QualType DstType, const Expr *SrcExpr,
                              CheckerContext &C) const;

public:
  void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;
  void checkPreStmt(const DeclStmt *D, CheckerContext &C) const;
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;
};
}

void FixedAddressChecker::checkUseOfFixedAddress(QualType DstType,
                                                 const Expr *SrcExpr,
                                                 CheckerContext &C) const {
  if (!DstType->isPointerType())
    return;

  // Omit warning if the assigned expression has already pointer type.
  // The value may come from a variable and is candidate for a previous warning
  // from the checker.
  if (SrcExpr->IgnoreParenCasts()->getType()->isPointerType())
    return;

  SVal RV = C.getSVal(SrcExpr);

  if (!RV.isConstant() || RV.isZeroConstant())
    return;

  // -1 is often used as special value in pointers when a warning would be a
  // false positive.
  if (const llvm::APSInt *I = RV.getAsInteger(); I && I->getSExtValue() == -1)
    return;

  if (C.getSourceManager().isInSystemMacro(SrcExpr->getBeginLoc()))
    return;

  if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
    // FIXME: improve grammar in the following strings:
    constexpr llvm::StringLiteral Msg =
        "Using a fixed address is not portable because that address will "
        "probably not be valid in all environments or platforms.";
    auto R = std::make_unique<PathSensitiveBugReport>(BT, Msg, N);
    R->addRange(SrcExpr->getSourceRange());
    bugreporter::trackExpressionValue(N, SrcExpr, *R);
    C.emitReport(std::move(R));
  }
}

void FixedAddressChecker::checkPreStmt(const BinaryOperator *B,
                                       CheckerContext &C) const {
  if (B->getOpcode() != BO_Assign)
    return;

  checkUseOfFixedAddress(B->getType(), B->getRHS(), C);
}

void FixedAddressChecker::checkPreStmt(const DeclStmt *D,
                                       CheckerContext &C) const {
  for (const auto *D1 : D->decls()) {
    if (const auto *VD1 = dyn_cast<VarDecl>(D1)) {
      if (VD1->hasInit()) {
        checkUseOfFixedAddress(VD1->getType(), VD1->getInit(), C);
      }
    }
  }
}

void FixedAddressChecker::checkPreStmt(const CallExpr *CE,
                                       CheckerContext &C) const {
  // Using a fixed address is not portable because that address will probably
  // not be valid in all environments or platforms.

  const FunctionDecl *Callee = CE->getDirectCallee();
  if (!Callee)
    return;
  if (CE->getNumArgs() != Callee->getNumParams())
    return;

  for (auto [Arg, Param] : zip_equal(CE->arguments(), Callee->parameters())) {
    checkUseOfFixedAddress(Param->getType(), Arg, C);
  }
}

void ento::registerFixedAddressChecker(CheckerManager &mgr) {
  mgr.registerChecker<FixedAddressChecker>();
}

bool ento::shouldRegisterFixedAddressChecker(const CheckerManager &mgr) {
  return true;
}
