%include "macros.mac"

    [BITS 32]
    section .text

PATCH(ENTRY)
    mov edi, ecx
    mov edx, 0
    mov ecx, 4
    mov ebx, esp
    mov eax, 7
    int 0x80
    mov ecx, edi
    mov edi, DWORD [ebx]
    mov DWORD [esp], 0
    and edi, 0xFFFFC
    sub esp, edi

    xor edi, edi
    jmp BACK
END
