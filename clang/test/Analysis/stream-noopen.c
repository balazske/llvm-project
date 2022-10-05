// RUN: %clang_analyze_cc1 -verify %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=alpha.unix.Errno \
// RUN:   -analyzer-checker=alpha.unix.Stream \
// RUN:   -analyzer-checker=apiModeling.StdCLibraryFunctions \
// RUN:   -analyzer-config apiModeling.StdCLibraryFunctions:ModelPOSIX=true \
// RUN:   -analyzer-checker=debug.ExprInspection

// enable only StdCLibraryFunctions checker
// RUN: %clang_analyze_cc1 -verify %s \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=alpha.unix.Errno \
// RUN:   -analyzer-checker=apiModeling.StdCLibraryFunctions \
// RUN:   -analyzer-config apiModeling.StdCLibraryFunctions:ModelPOSIX=true \
// RUN:   -analyzer-checker=debug.ExprInspection

#include "Inputs/system-header-simulator.h"
#include "Inputs/errno_var.h"

void clang_analyzer_eval(int);

const char *WBuf = "123456789";
char RBuf[10];

void test_freopen(FILE *F) {
  F = freopen("xxx", "w", F);
  if (F) {
    if (errno) {} // expected-warning{{undefined}}
  } else {
    clang_analyzer_eval(errno != 0); // expected-warning {{TRUE}}
  }
}

void test_fread(FILE *F) {
  size_t Ret = fread(RBuf, 1, 10, F);
  if (Ret == 10) {
    if (errno) {} // expected-warning{{undefined}}
  } else {
    clang_analyzer_eval(errno != 0); // expected-warning {{TRUE}}
  }
  clang_analyzer_eval(feof(F)); // expected-warning {{UNKNOWN}}
  clang_analyzer_eval(ferror(F)); // expected-warning {{UNKNOWN}}
}

void test_fwrite(FILE *F) {
  size_t Ret = fwrite(WBuf, 1, 10, F);
  if (Ret == 10) {
    if (errno) {} // expected-warning{{undefined}}
  } else {
    clang_analyzer_eval(errno != 0); // expected-warning {{TRUE}}
  }
  clang_analyzer_eval(feof(F)); // expected-warning {{UNKNOWN}}
  clang_analyzer_eval(ferror(F)); // expected-warning {{UNKNOWN}}
}

void test_fclose(FILE *F) {
  int Ret = fclose(F);
  if (Ret == 0) {
    if (errno) {} // expected-warning{{undefined}}
  } else {
    clang_analyzer_eval(Ret == EOF); // expected-warning {{TRUE}}
    clang_analyzer_eval(errno != 0); // expected-warning {{TRUE}}
  }
  clang_analyzer_eval(feof(F)); // expected-warning {{UNKNOWN}}
  clang_analyzer_eval(ferror(F)); // expected-warning {{UNKNOWN}}
}

void test_fseek(FILE *F) {
  int Ret = fseek(F, SEEK_SET, 1);
  if (Ret == 0) {
    if (errno) {} // expected-warning{{undefined}}
  } else {
    clang_analyzer_eval(Ret == -1); // expected-warning {{TRUE}}
    clang_analyzer_eval(errno != 0); // expected-warning {{TRUE}}
  }
  clang_analyzer_eval(feof(F)); // expected-warning {{UNKNOWN}}
  clang_analyzer_eval(ferror(F)); // expected-warning {{UNKNOWN}}
}

void freadwrite_zerosize(FILE *F) {
  fwrite(WBuf, 1, 0, F);
  clang_analyzer_eval(feof(F)); // expected-warning {{UNKNOWN}}
  clang_analyzer_eval(ferror(F)); // expected-warning {{UNKNOWN}}
  if (errno) {} // no-warning
  fwrite(WBuf, 0, 1, F);
  clang_analyzer_eval(feof(F)); // expected-warning {{UNKNOWN}}
  clang_analyzer_eval(ferror(F)); // expected-warning {{UNKNOWN}}
  if (errno) {} // no-warning
  fread(RBuf, 1, 0, F);
  clang_analyzer_eval(feof(F)); // expected-warning {{UNKNOWN}}
  clang_analyzer_eval(ferror(F)); // expected-warning {{UNKNOWN}}
  if (errno) {} // no-warning
  fread(RBuf, 0, 1, F);
  clang_analyzer_eval(feof(F)); // expected-warning {{UNKNOWN}}
  clang_analyzer_eval(ferror(F)); // expected-warning {{UNKNOWN}}
  if (errno) {} // no-warning
}
