[SECTION .text]
global InvokeIndirectSyscall

InvokeIndirectSyscall:
    mov r10, rcx                ; Move first argument to r10 (standard syscall convention)
    mov eax, [rsp + 40]         ; Move SSN (passed as 5th argument) into eax
    jmp qword [rsp + 48]        ; Jump to the address of the 'syscall' instruction in ntdll
    ret
