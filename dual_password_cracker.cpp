#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif

// Essential PoDoFo headers
#include "podofo/podofo.h"
#include "podofo/main/PdfError.h"
#include "podofo/main/PdfMemDocument.h"

using namespace std;
using namespace PoDoFo;

atomic<int> totalCount(0);
atomic<bool> userPasswordFound(false);
atomic<bool> ownerPasswordFound(false);
mutex coutMutex;
string foundUserPassword;
string foundOwnerPassword;
chrono::steady_clock::time_point globalStartTime;

void setConsoleColor(int color) {
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
#endif
}

void resetConsoleColor() {
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 7);
#endif
}

// Function to detect password type by testing permissions
void detectPasswordType(const string& pdfFile, const string& password) {
    try {
        // Test 1: Try to open with password
        PdfMemDocument document;
        document.Load(pdfFile.c_str(), password.c_str());
        
        // If we get here, it's at least a user password
        if (!userPasswordFound) {
            userPasswordFound = true;
            foundUserPassword = password;
            
            lock_guard<mutex> lock(coutMutex);
            setConsoleColor(10); // Green
            cout << "\r🎉 USER Password found: " << password << endl;
            resetConsoleColor();
        }
        
        // Test 2: Try to modify (check if it's also owner password)
        try {
            // Try to perform an operation that requires owner permissions
                // DON'T do this: PoDoFo::PdfString a(u8"Test Modification");  // char8_t
                PoDoFo::PdfString a(std::string("Test Modification"));  // OK: std::string (UTF-8)
                document.GetMetadata().SetAuthor(a);


            
            if (!ownerPasswordFound) {
                ownerPasswordFound = true;
                foundOwnerPassword = password;
                
                lock_guard<mutex> lock(coutMutex);
                setConsoleColor(11); // Cyan
                cout << "\r🔓 OWNER Password found: " << password << endl;
                resetConsoleColor();
            }
        }
        catch (...) {
            // Modification failed - password is user-only
        }
    }
    catch (const PdfError& e) {
        // Wrong password - continue silently
    }
    catch (const exception& e) {
        // Other errors
        if (totalCount % 10000 == 0) {
            lock_guard<mutex> lock(coutMutex);
            cerr << "Error: " << e.what() << endl;
        }
    }
}

// ULTRA-FAST PoDoFo password checking for both password types
bool tryPasswordDual(const string& pdfFile, const string& password, int count) {
    // If both passwords already found, stop
    if (userPasswordFound && ownerPasswordFound) {
        return true;
    }
    
    detectPasswordType(pdfFile, password);
    
    // Progress update
    if (count % 1000 == 0) {
        lock_guard<mutex> lock(coutMutex);
        auto currentTime = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(currentTime - globalStartTime);
        if (elapsed.count() > 0) {
            double speed = (totalCount * 1000.0) / elapsed.count();
            string status;
            if (userPasswordFound && ownerPasswordFound) status = "✅ BOTH";
            else if (userPasswordFound) status = "✅ USER";
            else if (ownerPasswordFound) status = "✅ OWNER";
            else status = "❌ NONE";
            
            cout << "\rAttempts: " << count << " | Speed: " << int(speed) << "/s | Status: " << status << " | Current: " << password << "          " << flush;
        }
    }
    
    return (userPasswordFound && ownerPasswordFound);
}

// Count total lines in file
size_t countLines(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) return 0;
    
    size_t count = 0;
    string line;
    while (getline(file, line)) {
        if (!line.empty()) count++;
    }
    file.close();
    return count;
}

// Process a chunk of the file
void processFileChunk(const string& pdfFile, const string& passwordFile, size_t startLine, size_t endLine, int threadId) {
    ifstream file(passwordFile);
    if (!file.is_open()) return;
    
    string password;
    size_t currentLine = 0;
    
    // Skip to start line
    while (currentLine < startLine && getline(file, password)) {
        currentLine++;
    }
    
    // Process assigned chunk
    while (currentLine <= endLine && getline(file, password)) {
        // Stop if both passwords found
        if (userPasswordFound && ownerPasswordFound) break;
        if (password.empty()) continue;
        
        int count = ++totalCount;
        if (tryPasswordDual(pdfFile, password, count)) {
            break;
        }
        currentLine++;
    }
    file.close();
}

int main(int argc, char** argv) {
    if (argc != 3) {
        cout << "Usage: dual_password_cracker.exe passwordlist.txt document.pdf" << endl;
        cout << "Finds both USER (open) and OWNER (edit) passwords" << endl;
        return 1;
    }
    
    string passwordFile = argv[1];
    string pdfFile = argv[2];
    
    // Count lines
    cout << "Counting passwords..." << endl;
    size_t totalLines = countLines(passwordFile);
    if (totalLines == 0) {
        cerr << "Error: Password file is empty!" << endl;
        return 1;
    }
    
    cout << "============================================" << endl;
    cout << "      DUAL PASSWORD PDF CRACKER" << endl;
    cout << "============================================" << endl;
    cout << "Password file: " << passwordFile << endl;
    cout << "Target PDF: " << pdfFile << endl;
    cout << "Total passwords: " << totalLines << endl;
    cout << "Looking for: USER (open) + OWNER (edit) passwords" << endl;
    cout << "============================================" << endl;
    
    globalStartTime = chrono::steady_clock::now();
    
    // Multi-threading
    const int numThreads = thread::hardware_concurrency();
    vector<thread> threads;
    size_t chunkSize = totalLines / numThreads;
    
    cout << "Using " << numThreads << " threads" << endl;
    cout << "Starting crack process..." << endl;
    cout << "============================================" << endl;
    
    for (int i = 0; i < numThreads; ++i) {
        size_t start = i * chunkSize;
        size_t end = (i == numThreads - 1) ? totalLines : start + chunkSize;
        threads.emplace_back(processFileChunk, pdfFile, passwordFile, start, end, i);
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    auto endTime = chrono::steady_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - globalStartTime);
    double totalSeconds = duration.count() / 1000.0;
    double avgSpeed = (totalCount * 1000.0) / duration.count();
    
    cout << "\n============================================" << endl;
    cout << "               FINAL RESULTS" << endl;
    cout << "============================================" << endl;
    
    if (userPasswordFound) {
        setConsoleColor(10);
        cout << "✅ USER Password (opens PDF): " << foundUserPassword << endl;
        resetConsoleColor();
    } else {
        setConsoleColor(12);
        cout << "❌ User password not found" << endl;
        resetConsoleColor();
    }
    
    if (ownerPasswordFound) {
        setConsoleColor(11);
        cout << "🔓 OWNER Password (edits PDF): " << foundOwnerPassword << endl;
        resetConsoleColor();
    } else {
        setConsoleColor(12);
        cout << "❌ Owner password not found" << endl;
        resetConsoleColor();
    }
    
    cout << "============================================" << endl;
    cout << "Total attempts: " << totalCount << endl;
    cout << "Total time: " << totalSeconds << " seconds" << endl;
    cout << "Average speed: " << int(avgSpeed) << " passwords/second" << endl;
    
    if (userPasswordFound || ownerPasswordFound) {
        setConsoleColor(10);
        cout << "🎉 SUCCESS: Password(s) found!" << endl;
        resetConsoleColor();
    } else {
        setConsoleColor(12);
        cout << "💥 FAILURE: No passwords found" << endl;
        resetConsoleColor();
    }
    
    cout << "============================================" << endl;
    
    return (userPasswordFound || ownerPasswordFound) ? 0 : 1;
}