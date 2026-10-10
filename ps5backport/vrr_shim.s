# VideoOut VRR shims for Type B titles on firmware that only knows Type A.
# Linked with --defsym for: add_event, get_vrr, unpeg, aware_flag, peg_flag.
# Type B titles never call sceVideoOutVrrUnpegFromFixedRate, so the output stays
# pegged at its maximum rate; both shims unpeg it for VRR-aware apps.
    .intel_syntax noprefix
    .text
    .globl add_event_shim, get_vrr_shim

# int AddVrrActiveStatusEvent(SceKernelEqueue eq, int handle, void *udata)
add_event_shim:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    mov r12d, esi
    call add_event
    mov ebx, eax
    test ebx, ebx
    jnz 1f
    cmp byte ptr [rip + aware_flag], 1
    jne 1f
    # Unpeg is one-shot per process; clear its state so it always reaches the driver.
    mov byte ptr [rip + peg_flag], 0
    mov edi, r12d
    call unpeg
1:  mov eax, ebx
    pop r12
    pop rbx
    pop rbp
    ret

# int GetOutputStatusWithVrr(int handle, void *out)
get_vrr_shim:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    mov r12d, edi
    mov r13, rsi
    call get_vrr
    mov ebx, eax
    test ebx, ebx
    jnz 1f
    test byte ptr [r13 + 0x10], 0x10
    jz 1f
    cmp byte ptr [rip + aware_flag], 1
    jne 1f
    mov byte ptr [rip + peg_flag], 0
    mov edi, r12d
    call unpeg
1:  mov eax, ebx
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
