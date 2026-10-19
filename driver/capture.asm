; nmi: Spill callback-entry GPRs before the C call
;
; Seed diagnostic RIP/RSP before PUSHFQ. Recover interrupted GPRs from
; the pinned Ki/Kx save slots; callback GPRs belong to the NMI dispatcher.
option casemap:none
include capture_abi.inc
EXTERN NuCapture:PROC
PUBLIC NuNmiEntry
PUBLIC NuReadTables
PUBLIC NuCopyBytes
.code
NuNmiEntry PROC FRAME
    pushfq
    .allocstack 8
    sub rsp, NU_ABI_ALLOCATION
    .allocstack NU_ABI_ALLOCATION
    .endprolog
    ; abi: Place the 0xA0-byte spill block above 0x20 bytes of home space
    mov [rsp+NU_ABI_RAX], rax
    mov [rsp+NU_ABI_RCX], rcx
    mov [rsp+NU_ABI_RDX], rdx
    mov [rsp+NU_ABI_RBX], rbx
    lea rax, [rsp+NU_ABI_ENTRY_RSP]
    mov [rsp+NU_ABI_RSP], rax
    mov [rsp+NU_ABI_RBP], rbp
    mov [rsp+NU_ABI_RSI], rsi
    mov [rsp+NU_ABI_RDI], rdi
    mov [rsp+NU_ABI_R8], r8
    mov [rsp+NU_ABI_R9], r9
    mov [rsp+NU_ABI_R10], r10
    mov [rsp+NU_ABI_R11], r11
    mov [rsp+NU_ABI_R12], r12
    mov [rsp+NU_ABI_R13], r13
    mov [rsp+NU_ABI_R14], r14
    mov [rsp+NU_ABI_R15], r15
    lea rax, NuNmiEntry
    mov [rsp+NU_ABI_RIP], rax
    ; x64: Recover pre-SUB RFLAGS from the PUSHFQ slot
    mov rax, [rsp+NU_ABI_SAVED_FLAGS]
    mov [rsp+NU_ABI_RFLAGS], rax
    mov ax, cs
    movzx rax, ax
    mov [rsp+NU_ABI_CS], rax
    mov ax, ss
    movzx rax, ax
    mov [rsp+NU_ABI_SS], rax
    lea r8, [rsp+NU_ABI_HOME]
    ; abi: Preserve Context in RCX and Handled in DL; pass NU_REGS in R8
    call NuCapture
    add rsp, NU_ABI_ENTRY_RSP
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
; nmi: Copy resident snapshots without SIMD, allocation or CRT calls
; RSI/RDI retain their ABI values. REP MOVSB copies exactly R8 bytes;
; the C capture path proves source bounds before entering this routine.
NuCopyBytes PROC FRAME
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog
    mov rdi, rcx
    mov rsi, rdx
    mov rcx, r8
    cld
    rep movsb
    pop rdi
    pop rsi
    ret
NuCopyBytes ENDP
END
