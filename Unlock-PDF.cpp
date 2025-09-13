#include <cstdlib>
#include <iostream>
#include <string>
#include <cctype>

// Compile with: g++ -std=c++17 Unlock-PDF.cpp -o Unlock-PDF
// For older libstdc++ where <filesystem> lives in <experimental/...>, add -lstdc++fs

using namespace std;

#if __has_include(<filesystem>) && __cplusplus >= 201703L
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#error "Neither <filesystem> nor <experimental/filesystem> is available"
#endif

int main() {
    fs::path pdfFile;
    bool found = false;
    for (const auto& entry : fs::directory_iterator(fs::current_path())) {
        if (fs::is_regular_file(entry.path())) {
            auto ext = entry.path().extension().string();
            for (auto& c : ext) c = tolower(static_cast<unsigned char>(c));
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

    string password;
    cout << "Enter password (leave empty if none): ";
    getline(cin, password);

    string command = "qpdf --password=" + password + " --decrypt \"" + pdfFile.string() + "\" output.pdf";
    int result = system(command.c_str());

    if (result != 0) {
        cerr << "Failed to decrypt PDF" << endl;
        return result;
    }

    cout << "Unlocked PDF saved to output.pdf" << endl;
    return 0;
}
