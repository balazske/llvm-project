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
    if (errno) {
    } // expected-warning{{Value of 'errno' could be undefined after a call to a function that does not promise to not change 'errno' [alpha.unix.Errno]}}
    if (errno) {
    }
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    if (errno) {
    } // expected-warning{{Value of 'errno' could be undefined after a call to a function that does not promise to not change 'errno' [alpha.unix.Errno]}}
    errno = 0;
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    errno = 0;
    if (errno) {
    }
  }
}

void testErrnoCheck1() {
  // If the function returns error result code that is out-of-band (not a valid
  // non-error return value) the value of 'errno' can be checked but it is not
  // required to do so.
  // The same applies if the function has an in-band error result code but not
  // the error result code was returned.
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 1) {
    if (errno) {
    }
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 1) {
    errno = 0;
  }
}

void testErrnoCheck2() {
  // If the function returns an in-band error result the value of 'errno' is
  // required to be checked to verify if error happened or not.
  // The same applies to other functions that can indicate failure only by
  // change of 'errno'.
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    if (errno) {
    }
    errno = 0;
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    errno = 0; // expected-warning{{Value of 'errno' was not checked after a call to a function that possibly failed and indicates failure only by value of 'errno' [alpha.unix.Errno]}}
    errno = 0;
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    errno = 0; // expected-warning{{Value of 'errno' was not checked after a call to a function that possibly failed and indicates failure only by value of 'errno' [alpha.unix.Errno]}}
    if (errno) {
    }
  }
}

void testErrnoCheck() {
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    int Y = errno; // expected-warning{{Value of 'errno' could be undefined after a call to a function that does not promise to not change 'errno' [alpha.unix.Errno]}}
  }
}

void testErrnoCheckStateInvalidate() {
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    something();
    if (errno) {
    }
  }
  X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 0) {
    printf("%i", 1);
    if (errno) {
    }
  }
}

void testErrnoCheckStateInvalidate1() {
  int X = ErrnoTesterChecker_setErrnoCheckState();
  if (X == 2) {
    clang_analyzer_eval(errno); // expected-warning{{TRUE}}
    something();
    clang_analyzer_eval(errno); // expected-warning{{UNKNOWN}}
  }
}
