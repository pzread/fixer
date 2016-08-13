Fixer
=====

Requirements
------------
+ capstone with python3 binding
+ nasm
+ as
+ objdump
+ libcgcef

Usage
-----
See the tests.

`jmp BACK` will resume at the patched address.

`jmp SKIP` will resume at the next instruction of the patched address.

The patch memory is readonly.
