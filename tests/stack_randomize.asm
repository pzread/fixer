%include "src/macros.mac"

    [BITS 32]
    section .text

PATCH(08048601)
    jmp BACK
END_PATCH
