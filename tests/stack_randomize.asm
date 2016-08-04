%macro _PATCH 1
global patch_%1
extern back_%1
patch_%1:
%endmacro
%define PATCH(x) _PATCH x
%define BACK(x) back_ %+ x

    [BITS 32]
    section .text

PATCH(08048606)
    jmp BACK(08048606)
