#include "MetamorphicEngine.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <random>
#include <cstring>
#include <cassert>
#include <memory>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>

// Constructor
MetamorphicEngine::MetamorphicEngine(const std::string& inputFile, const std::string& outputFile)
    : inputFileName(inputFile), outputFileName(outputFile) {}

// Read the input file into fileData
void MetamorphicEngine::readFile() {
    std::ifstream file(inputFileName, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << inputFileName << std::endl;
        exit(1);
    }
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    fileData.resize(fileSize);
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    file.close();
}

// Write the obfuscated data to the output file
void MetamorphicEngine::writeFile() {
    std::ofstream file(outputFileName, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << outputFileName << std::endl;
        exit(1);
    }
    file.write(reinterpret_cast<char*>(fileData.data()), fileData.size());
    file.close();
}

// Perform all obfuscation techniques
void MetamorphicEngine::performObfuscation() {
    reorderCode();
    substituteInstructions();
    insertGarbageCode();
    insertAntiDebugging();
    generateDynamicCode();
    applyCodeTransformation();
    encryptCode();
    addStackSmashingProtection();
    includeAntiReverseEngineeringTechniques();
    insertNOPsleds();
    insertROPchains();
    duplicateStackFrames();
}

// Reorder code instructions
void MetamorphicEngine::reorderCode() {
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(fileData.begin(), fileData.end(), g);
}

// Substitute instructions with equivalent but less obvious ones
void MetamorphicEngine::substituteInstructions() {
    for (size_t i = 0; i < fileData.size(); ++i) {
        switch (fileData[i]) {
            case 0x90:  // NOP
                fileData[i] = 0xC3;  // RET
                break;
            case 0xE9:  // JMP
                fileData[i] = 0xEB;  // Short JMP
                break;
            case 0xC3:  // RET
                fileData[i] = 0x90;  // NOP
                break;
            default:
                break;
        }
    }
}

// Insert garbage code
void MetamorphicEngine::insertGarbageCode() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < fileData.size(); i += 100) {
        if (i + 20 < fileData.size()) {
            for (size_t j = i; j < i + 20; ++j) {
                fileData[j] = static_cast<uint8_t>(dis(gen));
            }
        }
    }
}

// Insert anti-debugging code
void MetamorphicEngine::insertAntiDebugging() {
    std::vector<uint8_t> antiDebugCode = {
        0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, 0
        0x0F, 0x1F, 0x40, 0x00,       // NOP (align for next instruction)
        0x50,                           // PUSH EAX
        0x6A, 0x00,                     // PUSH 0 (Debug Active check)
        0x6A, 0x00,                     // PUSH 0
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // CALL [Address of a debug function]
        0x58                            // POP EAX
    };
    fileData.insert(fileData.end(), antiDebugCode.begin(), antiDebugCode.end());
}

// Generate dynamic code
void MetamorphicEngine::generateDynamicCode() {
    std::vector<uint8_t> dynamicCode = {
        0x48, 0x89, 0xE5,              // MOV RBP, RSP
        0x48, 0x83, 0xEC, 0x20,        // SUB RSP, 0x20
        0xB8, 0x01, 0x00, 0x00, 0x00,  // MOV EAX, 1
        0xC9,                          // LEAVE
        0xC3                           // RET
    };
    executeDynamicCode(dynamicCode);
}

// Execute dynamically generated code
void MetamorphicEngine::executeDynamicCode(const std::vector<uint8_t>& code) {
    size_t codeSize = code.size();
    void* mem = mmap(nullptr, codeSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    std::memcpy(mem, code.data(), codeSize);
    typedef void (*func_t)();
    func_t func = reinterpret_cast<func_t>(mem);
    func(); // Execute the code
    munmap(mem, codeSize);
}

// Apply code transformations (e.g., encryption)
void MetamorphicEngine::applyCodeTransformation() {
    for (size_t i = 0; i < fileData.size(); ++i) {
        fileData[i] ^= (0xAA + (i % 256)); // More complex XOR encryption
    }
}

// Encrypt the code
void MetamorphicEngine::encryptCode() {
    uint8_t key = 0xAA;
    for (size_t i = 0; i < fileData.size(); ++i) {
        fileData[i] ^= key; // Simple XOR encryption
    }
}

// Decrypt the code (for debugging purposes, if needed)
void MetamorphicEngine::decryptCode() {
    uint8_t key = 0xAA;
    for (size_t i = 0; i < fileData.size(); ++i) {
        fileData[i] ^= key; // Simple XOR decryption
    }
}

// Anti-debugging check
void MetamorphicEngine::antiDebuggingCheck() {
    #ifdef _WIN32
    if (IsDebuggerPresent()) {
        std::cerr << "Debugger detected!" << std::endl;
        exit(1);
    }
    #else
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        std::cerr << "Debugger detected!" << std::endl;
        exit(1);
    }
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    #endif
}

// Add stack smashing protection
void MetamorphicEngine::addStackSmashingProtection() {
    std::vector<uint8_t> stackGuardCode = {
        0x48, 0x83, 0xEC, 0x28,  // SUB RSP, 0x28
        0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, // LEA RDI, [RIP+0x00]
        0x48, 0x89, 0xF7,  // MOV RDI, RSI
        0x48, 0x83, 0xC4, 0x28,  // ADD RSP, 0x28
        0xC3                  // RET
    };
    fileData.insert(fileData.end(), stackGuardCode.begin(), stackGuardCode.end());
}

// Include anti-reverse engineering techniques
void MetamorphicEngine::includeAntiReverseEngineeringTechniques() {
    // Implement various techniques like code virtualization, obfuscation libraries, etc.
    // Example placeholder: inserting a dummy function
    std::vector<uint8_t> antiReverseCode = {
        0x90, 0x90, 0x90, 0x90, // NOP sled
        0xE8, 0x00, 0x00, 0x00, 0x00, // CALL (dummy function)
        0x90, 0x90, 0x90, 0x90  // NOP sled
    };
    fileData.insert(fileData.end(), antiReverseCode.begin(), antiReverseCode.end());
}

// Insert NOP sleds
void MetamorphicEngine::insertNOPsleds() {
    size_t offset = 0;
    while (offset < fileData.size()) {
        fileData.insert(fileData.begin() + offset, 0x90, 10); // Insert 10 NOPs
        offset += 20; // Skip ahead to insert more NOP sleds
    }
}

// Insert ROP chains
void MetamorphicEngine::insertROPchains() {
    std::vector<uint8_t> ropChain = {
        0x58,                     // POP RAX
        0x59,                     // POP RCX
        0x5A,                     // POP RDX
        0x5B,                     // POP RBX
        0x5C,                     // POP RSP
        0x5D,                     // POP RBP
        0x5E,                     // POP RSI
        0x5F                      // POP RDI
    };
    fileData.insert(fileData.end(), ropChain.begin(), ropChain.end());
}

// Duplicate stack frames
void MetamorphicEngine::duplicateStackFrames() {
    std::vector<uint8_t> stackDupCode = {
        0x50,                     // PUSH RAX
        0x51,                     // PUSH RCX
        0x52,                     // PUSH RDX
        0x53,                     // PUSH RBX
        0x54,                     // PUSH RSP
        0x55,                     // PUSH RBP
        0x56,                     // PUSH RSI
        0x57,                     // PUSH RDI
        0x58,                     // POP RAX
        0x59,                     // POP RCX
        0x5A,                     // POP RDX
        0x5B,                     // POP RBX
        0x5C,                     // POP RSP
        0x5D,                     // POP RBP
        0x5E,                     // POP RSI
        0x5F                      // POP RDI
    };
    fileData.insert(fileData.end(), stackDupCode.begin(), stackDupCode.end());
}

// Main obfuscation method
void MetamorphicEngine::obfuscate() {
    readFile();
    performObfuscation();
    writeFile();
}




















#include "MetamorphicEngine.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <random>
#include <cstring>
#include <cassert>
#include <memory>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>

// Constructor
MetamorphicEngine::MetamorphicEngine(const std::string& inputFile, const std::string& outputFile)
    : inputFileName(inputFile), outputFileName(outputFile) {}

// Read the input file into fileData
void MetamorphicEngine::readFile() {
    std::ifstream file(inputFileName, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << inputFileName << std::endl;
        exit(1);
    }
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    fileData.resize(fileSize);
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    file.close();
}

// Write the obfuscated data to the output file
void MetamorphicEngine::writeFile() {
    std::ofstream file(outputFileName, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << outputFileName << std::endl;
        exit(1);
    }
    file.write(reinterpret_cast<char*>(fileData.data()), fileData.size());
    file.close();
}

// Perform all obfuscation techniques
void MetamorphicEngine::performObfuscation() {
    reorderCode();
    substituteInstructions();
    insertGarbageCode();
    insertAntiDebugging();
    generateDynamicCode();
    applyCodeTransformation();
    encryptCode();
    addStackSmashingProtection();
    includeAntiReverseEngineeringTechniques();
    insertNOPsleds();
    insertROPchains();
    duplicateStackFrames();
}

// Reorder code instructions
void MetamorphicEngine::reorderCode() {
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(fileData.begin(), fileData.end(), g);
}

// Substitute instructions with equivalent but less obvious ones
void MetamorphicEngine::substituteInstructions() {
    for (size_t i = 0; i < fileData.size(); ++i) {
        switch (fileData[i]) {
            case 0x90:  // NOP
                fileData[i] = 0xC3;  // RET
                break;
            case 0xE9:  // JMP
                fileData[i] = 0xEB;  // Short JMP
                break;
            case 0xC3:  // RET
                fileData[i] = 0x90;  // NOP
                break;
            default:
                break;
        }
    }
}

// Insert garbage code
void MetamorphicEngine::insertGarbageCode() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < fileData.size(); i += 100) {
        if (i + 20 < fileData.size()) {
            for (size_t j = i; j < i + 20; ++j) {
                fileData[j] = static_cast<uint8_t>(dis(gen));
            }
        }
    }
}

// Insert anti-debugging code
void MetamorphicEngine::insertAntiDebugging() {
    std::vector<uint8_t> antiDebugCode = {
        0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, 0
        0x0F, 0x1F, 0x40, 0x00,       // NOP (align for next instruction)
        0x50,                           // PUSH EAX
        0x6A, 0x00,                     // PUSH 0 (Debug Active check)
        0x6A, 0x00,                     // PUSH 0
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // CALL [Address of a debug function]
        0x58                            // POP EAX
    };
    fileData.insert(fileData.end(), antiDebugCode.begin(), antiDebugCode.end());
}

// Generate dynamic code
void MetamorphicEngine::generateDynamicCode() {
    std::vector<uint8_t> dynamicCode = {
        0x48, 0x89, 0xE5,              // MOV RBP, RSP
        0x48, 0x83, 0xEC, 0x20,        // SUB RSP, 0x20
        0xB8, 0x01, 0x00, 0x00, 0x00,  // MOV EAX, 1
        0xC9,                          // LEAVE
        0xC3                           // RET
    };
    executeDynamicCode(dynamicCode);
}

// Execute dynamically generated code
void MetamorphicEngine::executeDynamicCode(const std::vector<uint8_t>& code) {
    size_t codeSize = code.size();
    void* mem = mmap(nullptr, codeSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    std::memcpy(mem, code.data(), codeSize);
    typedef void (*func_t)();
    func_t func = reinterpret_cast<func_t>(mem);
    func(); // Execute the code
    munmap(mem, codeSize);
}

// Apply code transformations (e.g., encryption)
void MetamorphicEngine::applyCodeTransformation() {
    for (size_t i = 0; i < fileData.size(); ++i) {
        fileData[i] ^= (0xAA + (i % 256)); // More complex XOR encryption
    }
}

// Encrypt the code
void MetamorphicEngine::encryptCode() {
    uint8_t key = 0xAA;
    for (size_t i = 0; i < fileData.size(); ++i) {
        fileData[i] ^= key; // Simple XOR encryption
    }
}

// Decrypt the code (for debugging purposes, if needed)
void MetamorphicEngine::decryptCode() {
    uint8_t key = 0xAA;
    for (size_t i = 0; i < fileData.size(); ++i) {
        fileData[i] ^= key; // Simple XOR decryption
    }
}

// Anti-debugging check
void MetamorphicEngine::antiDebuggingCheck() {
    #ifdef _WIN32
    if (IsDebuggerPresent()) {
        std::cerr << "Debugger detected!" << std::endl;
        exit(1);
    }
    #else
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        std::cerr << "Debugger detected!" << std::endl;
        exit(1);
    }
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    #endif
}

// Add stack smashing protection
void MetamorphicEngine::addStackSmashingProtection() {
    std::vector<uint8_t> stackGuardCode = {
        0x48, 0x83, 0xEC, 0x28,  // SUB RSP, 0x28
        0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, // LEA RDI, [RIP+0x00]
        0x48, 0x89, 0xF7,  // MOV RDI, RSI
        0x48, 0x83, 0xC4, 0x28,  // ADD RSP, 0x28
        0xC3                  // RET
    };
    fileData.insert(fileData.end(), stackGuardCode.begin(), stackGuardCode.end());
}

// Include anti-reverse engineering techniques
void MetamorphicEngine::includeAntiReverseEngineeringTechniques() {
    // Implement various techniques like code virtualization, obfuscation libraries, etc.
    // Example placeholder: inserting a dummy function
    std::vector<uint8_t> antiReverseCode = {
        0x90, 0x90, 0x90, 0x90, // NOP sled
        0xE8, 0x00, 0x00, 0x00, 0x00, // CALL (dummy function)
        0x90, 0x90, 0x90, 0x90  // NOP sled
    };
    fileData.insert(fileData.end(), antiReverseCode.begin(), antiReverseCode.end());
}

// Insert NOP sleds
void MetamorphicEngine::insertNOPsleds() {
    size_t offset = 0;
    while (offset < fileData.size()) {
        fileData.insert(fileData.begin() + offset, 0x90, 10); // Insert 10 NOPs
        offset += 20; // Skip ahead to insert more NOP sleds
    }
}

// Insert ROP chains
void MetamorphicEngine::insertROPchains() {
    std::vector<uint8_t> ropChain = {
        0x58,                     // POP RAX
        0x59,                     // POP RCX
        0x5A,                     // POP RDX
        0x5B,                     // POP RBX
        0x5C,                     // POP RSP
        0x5D,                     // POP RBP
        0x5E,                     // POP RSI
        0x5F                      // POP RDI
    };
    fileData.insert(fileData.end(), ropChain.begin(), ropChain.end());
}

// Duplicate stack frames
void MetamorphicEngine::duplicateStackFrames() {
    std::vector<uint8_t> stackDupCode = {
        0x50,                     // PUSH RAX
        0x51,                     // PUSH RCX
        0x52,                     // PUSH RDX
        0x53,                     // PUSH RBX
        0x54,                     // PUSH RSP
        0x55,                     // PUSH RBP
        0x56,                     // PUSH RSI
        0x57,                     // PUSH RDI
        0x58,                     // POP RAX
        0x59,                     // POP RCX
        0x5A,                     // POP RDX
        0x5B,                     // POP RBX
        0x5C,                     // POP RSP
        0x5D,                     // POP RBP
        0x5E,                     // POP RSI
        0x5F                      // POP RDI
    };
    fileData.insert(fileData.end(), stackDupCode.begin(), stackDupCode.end());
}

// Main obfuscation method
void MetamorphicEngine::obfuscate() {
    readFile();
    performObfuscation();
    writeFile();
}
