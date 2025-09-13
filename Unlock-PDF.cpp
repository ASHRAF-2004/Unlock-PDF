#include <cstdlib>
#include <iostream>
#include <string>
#include <cctype>

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
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            for (auto& c : ext) c = std::tolower(static_cast<unsigned char>(c));
            if (ext == ".pdf") {
                pdfFile = entry.path();
                found = true;
                break;
            }
        }
    }

    if (!found) {
        std::cerr << "No pdf file found in this folder, please put your pdf in the same folder where the .cpp is" << std::endl;
        return 1;
    }

    std::string password;
    std::cout << "Enter password (leave empty if none): ";
    std::getline(std::cin, password);

    std::string command = "qpdf --password=" + password + " --decrypt \"" + pdfFile.string() + "\" output.pdf";
    int result = std::system(command.c_str());

    if (result != 0) {
        std::cerr << "Failed to decrypt PDF" << std::endl;
        return result;
    }

    std::cout << "Unlocked PDF saved to output.pdf" << std::endl;
    return 0;
}
