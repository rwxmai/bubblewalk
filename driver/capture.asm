; nmi: Spill callback-entry GPRs before the C call
;
; Seed diagnostic RIP/RSP before PUSHFQ. Recover interrupted GPRs from
; the pinned Ki/Kx save slots; callback GPRs belong to the NMI dispatcher.
option casemap:none
EXTERN NuCapture:PROC
PUBLIC NuNmiEntry
PUBLIC NuReadTables
.code
NuNmiEntry PROC FRAME
    pushfq
    .allocstack 8
    sub rsp, 0C0h
    .allocstack 0C0h
    .endprolog
    ; abi: Place the 0xA0-byte spill block above 0x20 bytes of home space
    mov [rsp+020h], rax
    mov [rsp+028h], rcx
    mov [rsp+030h], rdx
    mov [rsp+038h], rbx
    lea rax, [rsp+0C8h]
    mov [rsp+040h], rax
    mov [rsp+048h], rbp
    mov [rsp+050h], rsi
    mov [rsp+058h], rdi
    mov [rsp+060h], r8
    mov [rsp+068h], r9
    mov [rsp+070h], r10
    mov [rsp+078h], r11
    mov [rsp+080h], r12
    mov [rsp+088h], r13
    mov [rsp+090h], r14
    mov [rsp+098h], r15
    lea rax, NuNmiEntry
    mov [rsp+0A0h], rax
    ; x64: Recover pre-SUB RFLAGS from the PUSHFQ slot
    mov rax, [rsp+0C0h]
    mov [rsp+0A8h], rax
    mov ax, cs
    movzx rax, ax
    mov [rsp+0B0h], rax
    mov ax, ss
    movzx rax, ax
    mov [rsp+0B8h], rax
    lea r8, [rsp+020h]
    ; abi: Preserve Context in RCX and Handled in DL; pass NU_REGS in R8
    call NuCapture
    add rsp, 0C8h
    ret
NuNmiEntry ENDP

; x64: Sample IDTR, GDTR, and TR with SIDT, SGDT, and STR
;
; SIDT/SGDT emit 10 bytes. NU_TABLES places each DTR in a 16-byte slot
; and the 2-byte task-register selector at offset 0x20.
NuReadTables PROC
    sidt fword ptr [rcx]
    sgdt fword ptr [rcx+16]
    str ax
    mov word ptr [rcx+32], ax
    ret
NuReadTables ENDP
END
