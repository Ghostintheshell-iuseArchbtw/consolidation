#ifndef ADVANCED_ANTI_ANALYSIS_H
#define ADVANCED_ANTI_ANALYSIS_H

#include <iostream>
#include <chrono>
#include <thread>
#include <random>
#include <cmath>
#include <functional>
#include <vector>
#include <bitset>
#include <Windows.h>
#include <intrin.h>
#include <string>
#include <stdexcept>
#include <sstream>
#include <memory>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iterator>

#define RANDOM_DELAY_MAX 300 // Random delay up to 300ms
#define MAX_MEMORY_ALLOC 2048

class AntiVMException : public std::runtime_error {
public:
    AntiVMException(const std::string& message, int errorCode)
        : std::runtime_error(message), errorCode_(errorCode) {}

    int getErrorCode() const { return errorCode_; }

private:
    int errorCode_;
};

// Helper function to generate pseudo-random primes
inline bool is_prime(int n) {
    if (n <= 1) return false;
    for (int i = 2; i <= std::sqrt(n); ++i) {
        if (n % i == 0) return false;
    }
    return true;
}

inline int generate_prime() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(10000, 99999);

    int candidate = dis(gen);
    while (!is_prime(candidate)) {
        candidate = dis(gen);
    }
    return candidate;
}

// Advanced timing-based anomaly detection with variable delay
inline void advanced_timing_detection() {
    auto start = std::chrono::high_resolution_clock::now();

    // Intentional non-linear delay with obfuscated computation
    volatile int dummy = 1;
    for (int i = 0; i < 1000; ++i) {
        dummy ^= (i * i) % 17;
    }

    // Variable delay to thwart timing attacks
    std::this_thread::sleep_for(std::chrono::milliseconds(150 + (dummy % RANDOM_DELAY_MAX)));

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // Opaque predicate to detect anomalies
    if (((duration * duration) % 19 + duration) % 23 != 0) {
        volatile int x = duration; // Artificially complex logic
        if ((x % 7 + x * 3) % 11 == 0) {
            std::exit(EXIT_FAILURE);
        }
    }
}

// Advanced Anti-VM detection using system-specific BIOS checks
inline bool advanced_vm_detection() {
    // Check for system BIOS signs of virtual machines
    std::string bios_info = "Unknown";
    char buffer[128];
    FILE* fp = popen("wmic bios get manufacturer, version", "r");
    if (fp != nullptr) {
        while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
            bios_info = std::string(buffer);
        }
        fclose(fp);
    }

    // Check for VMware or VirtualBox BIOS strings
    if (bios_info.find("VMware") != std::string::npos || bios_info.find("VirtualBox") != std::string::npos) {
        return true;
    }

    return false;
}

// Advanced debugger detection
inline bool advanced_debugger_detection() {
    // Using Windows-specific API for debugger detection
    if (IsDebuggerPresent()) {
        return true;
    }

    // Check for debugger-related windows
    HWND hwnd = FindWindowA("DbgCtrlWnd", NULL);
    if (hwnd) {
        return true;
    }

    // Inspect thread attributes for debugger presence
    CONTEXT context;
    ZeroMemory(&context, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &context)) {
        // Check debug registers for specific patterns
        if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3) {
            return true;
        }
    }

    return false;
}

// Self-modifying polymorphic code
inline void self_modifying_code() {
    unsigned char code[] = {
        0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp, rsp
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x5D, 0xC3              // pop rbp; ret
    };

    // Dynamically allocate memory for self-modifying code
    volatile unsigned char* executable_memory = (volatile unsigned char*)VirtualAlloc(
        NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );

    if (executable_memory) {
        memcpy((void*)executable_memory, code, sizeof(code));

        // Modify code at runtime to confuse static analysis
        executable_memory[4] ^= 0xFF; // Randomly alter the opcode

        // Execute the modified code
        ((void(*)())executable_memory)();

        // Free the allocated memory
        VirtualFree((void*)executable_memory, 0, MEM_RELEASE);
    }
}

// Introduce noise into stack and memory to confuse analysis
inline void stack_memory_noise() {
    volatile std::array<int, 256> noise;
    for (size_t i = 0; i < noise.size(); ++i) {
        noise[i] = (i * i + 37) % 255;
    }

    // Random computations
    if (std::accumulate(noise.begin(), noise.end(), 0) % 13 == 0) {
        volatile int dummy = noise[0];
    }
}

// Memory scrambling with runtime modification
inline void memory_scrambling() {
    volatile char* buffer = new char[MAX_MEMORY_ALLOC];
    std::memset((void*)buffer, 0xAA, MAX_MEMORY_ALLOC);

    // Randomize buffer values
    for (int i = 0; i < MAX_MEMORY_ALLOC; ++i) {
        buffer[i] = rand() % 256;
    }

    delete[] buffer;
}

// Secure file deletion with multiple overwrites and random delays
inline void secure_delete_file(const std::string& path) {
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    // Multiple overwrites with random values before deletion
    for (int i = 0; i < 5; ++i) {
        std::ofstream file(path, std::ios::binary);
        for (int j = 0; j < 1024; ++j) {
            file.put(dist(mt));
        }
        file.close();

        // Random delay to confuse detection
        std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));
    }

    if (std::filesystem::exists(path)) {
        std::filesystem::remove(path);
    }
}

// Comprehensive environment check: VM, Debugger, Timing
inline bool comprehensive_detection() {
    if (advanced_vm_detection()) {
        throw AntiVMException("VM or hypervisor detected via advanced BIOS and system checks.", 105);
    }

    if (advanced_debugger_detection()) {
        throw AntiVMException("Debugger detected via system checks.", 106);
    }

    return true;
}

// Function to delay execution in random intervals to avoid analysis
inline void random_delay() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100, RANDOM_DELAY_MAX);

    int delay = dis(gen);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
}

// Anti-analysis function that calls all sub-functions
inline void anti() {
    advanced_timing_detection();
    if (comprehensive_detection()) {
        random_delay();
        self_modifying_code();
        stack_memory_noise();
        memory_scrambling();
    }
}

#endif // ADVANCED_ANTI_ANALYSIS_H

