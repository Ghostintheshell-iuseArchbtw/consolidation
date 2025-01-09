#include <Windows.h>
#include <iostream>
#include <intrin.h>

// Custom exception class
class AntiVMException : public std::runtime_error {
public:
    AntiVMException(const char* message, int errorCode) 
        : std::runtime_error(message), errorCode_(errorCode) {}

    int getErrorCode() const { return errorCode_; }

private:
    int errorCode_;
};

// Timing-based detection
bool timingDetection() {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    // Perform innocuous task
    for (int i = 0; i < 10000; i++) {
        int x = i * 2;
    }
    QueryPerformanceCounter(&end);
    // Check time difference
    return (end.QuadPart - start.QuadPart) * 1000 / freq.QuadPart > 5;
}

// Multi-timing detection
bool multiTimingDetection() {
    int anomalies = 0;
    for (int i = 0; i < 5; i++) {
        if (timingDetection()) {
            anomalies++;
        }
    }
    return anomalies >= 3;
}

// Math-based detection
bool mathDetection() {
    int result = 0;
    for (int i = 0; i < 10000; i++) {
        result += i * 3 + i * i;
    }
    // Check result
    return result != 299990000;
}

// Multi-math detection
bool multiMathDetection() {
    int anomalies = 0;
    for (int i = 0; i < 5; i++) {
        if (mathDetection()) {
            anomalies++;
        }
    }
    return anomalies >= 3;
}

// TLB flush detection
bool tlbFlushDetection() {
    int* ptr = new int;
    *ptr = 0x12345678;
    // Flush TLB
    FlushProcessWriteBuffers();
    // Check if TLB flush was successful
    return *ptr != 0x12345678;
}

// Hardware Breakpoints detection
bool detectHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
    }
    return false;
}

// Detection threshold
constexpr int DETECTION_THRESHOLD = 1;

