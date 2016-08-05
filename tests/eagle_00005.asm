%include "src/macros.mac"

    [BITS 32]
    section .text

PATCH(0x080482E7)
    mov DWORD [esp + 4], 32
    jmp SKIP
END

PATCH(0x08048388)
    push format_string
    call 0x8049000
    add esp, 4
    jmp SKIP
END

format_string:
    db "%s", 0
