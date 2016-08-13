Fixer
=====

Requirements
------------
+ python3
+ capstone with python3 binding
+ nasm
+ binutils
+ libcgcef

Usage
-----
See the tests.

`jmp BACK` will resume at the patched address.

`jmp SKIP` will resume at the next instruction of the patched address.

The memory space of your patch is readonly.

The jmp instruction needs 5 bytes at the patched address. Although the Fixer will recover overwritten instructions, be careful not to overlap the head of the next basic block. This tool can't handle this stitution.
