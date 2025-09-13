// Cross-platform PDF unlocking helper.
//
// On non-Windows platforms the program uses std::filesystem which is
// available in C++17 and later.  Older Windows GCC/MinGW setups often do not
// provide the C++17 filesystem library by default which results in linker
// errors like the ones reported in the issue.  To make the program build out of
// the box on those systems we avoid std::filesystem on Windows and instead use
// the Win32 API to locate a PDF file in the current directory.

#include <cctype>
#include <cstdlib>
#include <iostream>
#include <string>

using namespace std;

#ifdef _WIN32
#include <windows.h>
#else
#include <filesystem>
namespace fs = std::filesystem;
#endif

int main() {
    string pdfFile;

#ifdef _WIN32
    // Use Win32 directory enumeration to find the first PDF file.
    WIN32_FIND_DATAA data;
    HANDLE hFind = FindFirstFileA("*.pdf", &data);
    if (hFind == INVALID_HANDLE_VALUE) {
        cerr << "No pdf file found in this folder, please put your pdf in the same folder where the .cpp is" << endl;
        return 1;
    }
    pdfFile = data.cFileName;
    FindClose(hFind);
#else
    // Fallback for platforms with <filesystem> support.
    bool found = false;
    for (const auto &entry : fs::directory_iterator(fs::current_path())) {
        if (fs::is_regular_file(entry.path())) {
            auto ext = entry.path().extension().string();
            for (auto &c : ext)
                c = tolower(static_cast<unsigned char>(c));
            if (ext == ".pdf") {
                pdfFile = entry.path();
                found = true;
                break;
            }
        }
    }
    if (!found) {
        cerr << "No pdf file found in this folder, please put your pdf in the same folder where the .cpp is" << endl;
        return 1;
    }
#endif
    
    string password;
    cout << "Enter password (leave empty if none): ";
    getline(cin, password);

    string command = "qpdf --password=" + password + " --decrypt \"" + pdfFile + "\" output.pdf";
    int result = system(command.c_str());

    if (result != 0) {
        cerr << "Failed to decrypt PDF" << endl;
        return result;
    }

    cout << "Unlocked PDF saved to output.pdf" << endl;
    return 0;
}
