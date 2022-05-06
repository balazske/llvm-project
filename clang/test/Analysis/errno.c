// XFAIL:*
// RUN: %clang_analyze_cc1 -verify %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=apiModeling.Errno \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-checker=debug.ErrnoTest \
// RUN:   -analyzer-checker=alpha.unix.Errno \
// RUN:   -DERRNO_VAR

// RUN: %clang_analyze_cc1 -verify %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=apiModeling.Errno \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-checker=debug.ErrnoTest \
// RUN:   -analyzer-checker=alpha.unix.Errno \
// RUN:   -DERRNO_FUNC

#include "Inputs/system-header-simulator.h"
#ifdef ERRNO_VAR
#include "Inputs/errno_var.h"
#endif
#ifdef ERRNO_FUNC
#include "Inputs/errno_func.h"
#endif

void clang_analyzer_eval(int);
void ErrnoTesterChecker_setErrno(int);
int ErrnoTesterChecker_getErrno();
int ErrnoTesterChecker_setErrnoIfError();
int ErrnoTesterChecker_setErrnoIfErrorRange();

// This function simulates the following:
// * Return 0 and leave 'errno' with undefined value.
// This is the case of a successful standard function call.
// For example if 'ftell' returns not -1.
// * Return 1 and sets 'errno' to a specific error code (1).
// This is the case of a failed standard function call.
// The function indicates the failure by a special return value
// that is returned only at failure.
// 'errno' can be checked but it is not required.
// For example if 'ftell' returns -1.
// * Return 2 and may set errno to a value (actually it does not set it).
// This is the case of a standard function call where the failure can only be
// checked by reading from 'errno'. The value of 'errno' is changed by the
// function only at failure, the user should set 'errno' to 0 before the call
// (ErrnoChecker does not check for this rule).
// 'strtol' is an example of this case, if it returns LONG_MIN (or LONG_MAX)
// This case applies only if LONG_MIN or LONG_MAX is returned,
// otherwise the first case in this list applies.
int ErrnoTesterChecker_setErrnoCheckState();

void something();

void test() {
  // Test if errno is initialized.
  clang_analyzer_eval(errno == 0); // expected-warning{{TRUE}}

  ErrnoTesterChecker_setErrno(1);
  // Test if errno was recognized and changed.
  clang_analyzer_eval(errno == 1);                         // expected-warning{{TRUE}}
  clang_analyzer_eval(ErrnoTesterChecker_getErrno() == 1); // expected-warning{{TRUE}}

  something();

  // Test if errno was invalidated.
  clang_analyzer_eval(errno);                         // expected-warning{{UNKNOWN}}
  clang_analyzer_eval(ErrnoTesterChecker_getErrno()); // expected-warning{{UNKNOWN}}
}

void testRange(int X) {
  if (X > 0) {
    ErrnoTesterChecker_setErrno(X);
    clang_analyzer_eval(errno > 0); // expected-warning{{TRUE}}
  }
}

void testIfError() {
  if (ErrnoTesterChecker_setErrnoIfError())
    clang_analyzer_eval(errno == 11); // expected-warning{{TRUE}}
}

void testIfErrorRange() {
  if (ErrnoTesterChecker_setErrnoIfErrorRange()) {
    clang_analyzer_eval(errno != 0); // expected-warning{{TRUE}}
    clang_analyzer_eval(errno == 1); // expected-warning{{FALSE}} expected-warning{{TRUE}}
  }
}

void testErrnoCheck0() {
  // If the function returns a success result code, value of 'errno'
  // is unspecified and it is unsafe to make any decision with it.
  // The function did not promise to not change 'errno' if no failure happens.
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    if (errno) { // expected-warning{{An undefined value may be read from 'errno' [alpha.unix.Errno]}}
    }
    if (errno) { // no warning for second time (analysis stops at the first warning)
    }
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    if (errno) { // expected-warning{{An undefined value may be read from 'errno' [alpha.unix.Errno]}}
    }
    errno = 0;
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    errno = 0;
    if (errno) { // no warning after overwritten 'errno'
    }
  }
}

void testErrnoCheck1() {
  // If the function returns error result code that is out-of-band (not a valid
  // non-error return value) the value of 'errno' can be checked but it is not
  // required to do so.
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 1) {
    if (errno) { // no warning
    }
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 1) {
    errno = 0; // no warning
  }
}

void testErrnoCheck2() {
  // If the function returns an in-band error result the value of 'errno' is
  // required to be checked to verify if error happened.
  // The same applies to other functions that can indicate failure only by
  // change of 'errno'.
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    if (errno) {
    }
    errno = 0; // no warning after 'errno' was read
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    errno = 0; // expected-warning{{Value of 'errno' was not checked and is overwritten here [alpha.unix.Errno]}}
    errno = 0;
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    errno = 0; // expected-warning{{Value of 'errno' was not checked and is overwritten here [alpha.unix.Errno]}}
    if (errno) {
    }
  }
}

void testErrnoCheckUndefinedLoad() {
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    int Y = errno; // expected-warning{{An undefined value may be read from 'errno' [alpha.unix.Errno]}}
  }
}

void testErrnoNotCheckedAtSystemCall() {
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    printf("%i", 1); // expected-warning{{Value of 'errno' was not checked and may be overwritten by function 'printf' [alpha.unix.Errno]}}
    printf("%i", 1); // no warning ('printf' does not change errno state)
  }
}

void testErrnoCheckStateInvalidate() {
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    something();
    if (errno) { // no warning after an invalidating function call
    }
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    printf("%i", 1);
    if (errno) { // no warning after an invalidating standard function call
    }
  }
}

void testErrnoCheckStateInvalidate1() {
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    clang_analyzer_eval(errno); // expected-warning{{TRUE}}
    something();
    clang_analyzer_eval(errno); // expected-warning{{UNKNOWN}}
    errno = 0;                  // no warning after invalidation
  }
}
