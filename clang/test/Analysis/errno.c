// RUN: %clang_analyze_cc1 -verify %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.unix.Errno

#include "Inputs/system-header-simulator.h"
//int *__errno_location();
//#define errno (*__errno_location())

void clang_analyzer_eval(int);
void clang_analyzer_dump(int);
int setErrno();
int setErrno1();

void t1() {
  /*if (setErrno() == 0) {
    clang_analyzer_eval(errno == 42); // expected-warning{{TRUE}}
  } else {
    clang_analyzer_eval(errno == 22); // expected-warning{{TRUE}}
  }*/
  //clang_analyzer_dump(errno);
  //clang_analyzer_dump(__errno_location());
  //clang_analyzer_dump(*__errno_location());
  int e = errno;

  if (setErrno()) {
    clang_analyzer_eval(errno != 0);
    clang_analyzer_dump(errno);
    //clang_analyzer_eval(__errno_location() != 0);
  }

  //clang_analyzer_dump(__errno_location());
  //clang_analyzer_dump(*__errno_location());
  //clang_analyzer_dump(errno);
  //clang_analyzer_eval(errno); // expected-warning{{TRUE}}

  //FILE *F = fopen("/a/b", "r");

  //clang_analyzer_dump(errno);
}
