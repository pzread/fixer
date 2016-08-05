%include "src/macros.mac"

    [BITS 32]
    section .text

PATCH(08048601)
    mov eax, 7
    int 0x80
    jmp BACK
END
