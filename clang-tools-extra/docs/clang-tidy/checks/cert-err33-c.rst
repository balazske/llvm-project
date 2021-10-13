.. title:: clang-tidy - cert-err33-c

cert-err33-c
============

Warns on unused function return values.
This check corresponds to (a part of) CERT C Coding Standard rule `ERR33-C.
Detect and handle standard library errors
<https://wiki.sei.cmu.edu/confluence/display/c/ERR33-C.+Detect+and+handle+standard+library+errors>`_.
The list of checked functions is the same as specified in the rule, with following exceptions:

* These are safe if called with NULL argument::
  
    mblen; mbrlen; mbrtowc; mbtowc; wctomb; wctomb_s

* Check of return value from these functions is often omitted and is at many
  uses safe to omit it. If included, these would generate excessive amount of
  false positive results::
  
    fprintf

If a custom list of checked functions is needed the check `bugprone-unused-return-value` can be used instead.
