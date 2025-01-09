#include <windows.h>
#include <iostream>
#include <intrin.h>
#include <chrono>
#include <string>
#include <stdexcept>
#include <memory>
#include <filesystem>
#include <thread>
#include <random>
#include <fstream>
#include <vector>

// Custom exception class for VM and debug detection errors
class AntiVMException : public std::runtime_error {
public:
    AntiVMException(const std::string& message, int errorCode) 
        : std::runtime_error(message), errorCode_(errorCode) {}

    int getErrorCode() const { return errorCode_; }

private:
    int errorCode_;
};

// Timing-based detection with microsecond precision
bool isTimingAnomaly(const std::chrono::high_resolution_clock::time_point& start, const std::chrono::high_resolution_clock::time_point& end) {
    using namespace std::chrono;
    auto duration = duration_cast<microseconds>(end - start).count();
    return duration > 1500; // 1.5 milliseconds threshold to avoid detection
}

// Advanced timing detection with randomized harmless workload
bool timingDetection() {
    auto start = std::chrono::high_resolution_clock::now();

    // Randomized harmless task (keeps the code flow irregular)
    for (int i = 0; i < 5000; i++) {
        int x = (i * 3) ^ 0xA5; // XOR operation for randomness
    }

    auto end = std::chrono::high_resolution_clock::now();
    return isTimingAnomaly(start, end);
}

// Advanced CPUID check (to detect hypervisors or virtualization technology)
bool cpuidCheck() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    
    // Check if CPUID returns virtualization info (specific to hypervisors)
    if ((cpuInfo[2] & (1 << 31)) != 0) {
        return true; // VM or hypervisor detected
    }
    return false;
}

// Advanced check for abnormal processor features (stealthy hardware check)
bool processorFeatureCheck() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x80000001); // Feature-specific CPUID leaf for extended info

    // Detect specific hardware virtualization-related flags (hypervisor-related)
    if (cpuInfo[2] & (1 << 31)) {
        return true; // Hypervisor present
    }
    return false;
}

// Anti-debug detection by checking for specific debugger hooks in memory
bool debugDetection() {
    PVOID pNtGlobalFlag = (PVOID)0x7FFE0300;  // NtGlobalFlag address
    unsigned char* flagPtr = (unsigned char*)pNtGlobalFlag;
    
    // Check if debugger flag is set (the system's global debug flag)
    if (*flagPtr & 0x70) {
        return true;
    }

    // Check for other anomalies (Irregular stack traces, modifications)
    if (IsDebuggerPresent()) {
        return true;
    }

    return false;
}

// Check if debugger is present using the GetThreadContext API
bool checkForDebuggerUsingThreadContext() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        // If any debug registers are set, it's likely under debugger control
        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
    }
    return false;
}

// Virtual Machine detection based on system-specific configurations
bool systemInformationCheck() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    // Check for unusual number of processors or abnormal memory configurations
    if (sysInfo.dwNumberOfProcessors < 2 || sysInfo.lpMinimumApplicationAddress == nullptr) {
        return true; // Suspicious VM-like behavior detected
    }

    // Check for specific VM-like BIOS data (e.g., VMware or VirtualBox often have signatures)
    char biosInfo[256];
    if (GetSystemFirmwareTable('RSMB', 0, &biosInfo, sizeof(biosInfo))) {
        if (strstr(biosInfo, "VMware") || strstr(biosInfo, "VirtualBox")) {
            return true; // Common VM signatures found
        }
    }

    return false;
}

// Anti-VM detection using virtualization introspection (Stealthy)
bool virtualizationDetection() {
    // Hypervisor detection using a subtle method with an obscure check
    int reg[4] = {0};
    __cpuid(reg, 0x40000000); // This leaf returns virtualization info on some CPUs
    if (reg[0] >= 0x40000001) {
        __cpuid(reg, 0x40000001);
        if (reg[1] == 0x756e6547) {
            return true; // Indicates hypervisor presence
        }
    }
    return false;
}

// Combined anti-debug and anti-VM detection
bool combinedDetection() {
    if (timingDetection()) {
        throw AntiVMException("Timing anomaly detected, possible VM or debugger.", 101);
    }

    if (cpuidCheck() || processorFeatureCheck()) {
        throw AntiVMException("Hypervisor or VM detected via CPUID.", 102);
    }

    if (debugDetection() || checkForDebuggerUsingThreadContext()) {
        throw AntiVMException("Debugger detected through memory or context check.", 103);
    }

    if (systemInformationCheck()) {
        throw AntiVMException("Suspicious system configuration detected, possible VM.", 104);
    }

    if (virtualizationDetection()) {
        throw AntiVMException("Virtualization or hypervisor detected.", 105);
    }

    return true;
}

void secureDeleteFile(const std::string& path) {
    // Use a cryptographically secure random number generator
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    // Open the file in binary mode
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file for deletion: " << path << std::endl;
        return;
    }

    // Get the file size
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(path, ec);
    if (ec) {
        std::cerr << "Failed to get file size: " << ec.message() << std::endl;
        return;
    }

    // Overwrite the file with random data multiple times
    for (int i = 0; i < 3; ++i) {
        std::vector<char> buffer(fileSize);
        for (char& c : buffer) {
            c = static_cast<char>(dist(mt));
        }
        file.write(buffer.data(), buffer.size());
    }

    file.close();

    // Wait for the file to be flushed from the disk cache
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Attempt to delete the file multiple times
    const int maxAttempts = 3;
    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        std::error_code ec;
        if (std::filesystem::remove(path, ec)) {
            std::cout << "File successfully deleted: " << path << std::endl;
            return;
        } else {
            std::cerr << "Failed to delete file (attempt " << attempt + 1 << "): " << path << std::endl;
            std::cerr << "Error code: " << ec.message() << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // If all attempts fail, print an error message
    std::cerr << "Failed to delete file after " << maxAttempts << " attempts: " << path << std::endl;
}

void self_destruct() {
    // Get the full path of the current executable
    std::string path = std::filesystem::current_path().string() + "\\" + std::filesystem::path(__FILE__).filename().string();
    
    // Ensure the file exists before attempting to delete
    if (std::filesystem::exists(path)) {
        std::cout << "Initiating self-destruct sequence..." << std::endl;

        // Securely overwrite the file to minimize recovery chances
        secureDeleteFile(path);

        // Sleep for a short period before attempting to terminate the process (if required)
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Attempt to terminate the process
        if (TerminateProcess(GetCurrentProcess(), 0)) {
            std::cout << "Self-destruct successful." << std::endl;
        } else {
            std::cerr << "Failed to terminate process: " << GetLastError() << std::endl;
        }
    } else {
        std::cerr << "File not found, skipping self-destruction." << std::endl;
    }

    exit(0);
}

void anti() {
    try {
        if (combinedDetection()) {
            std::cout << "No anomalies detected." << std::endl;
        } else {
            std::cerr << "Anomalies detected, initiating self-destruct sequence." << std::endl;
            self_destruct();
        }
    } catch (const AntiVMException& e) {
        std::cerr << "AntiVM Exception: " << e.what() << std::endl;
        self_destruct();
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
    }
}
