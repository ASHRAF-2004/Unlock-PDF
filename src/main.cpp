#include <codecvt>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "pdf/pdf_cracker.h"
#include "util/wordlist_generator.h"

namespace {

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n\n"
              << "PDF Password Retriever options:\n"
              << "  --pdf <path>                Path to the encrypted PDF file\n"
              << "  --wordlist <path>           Path to a password wordlist file\n"
              << "  --threads <n>               Number of worker threads (default: auto)\n\n"
              << "Wordlist generation options:\n"
              << "  --generate-wordlist <path>  Generate a wordlist at the given path\n"
              << "  --min-length <n>            Minimum password length (default: 6)\n"
              << "  --max-length <n>            Maximum password length (default: 6)\n"
              << "  --include-uppercase         Include uppercase letters\n"
              << "  --exclude-uppercase         Exclude uppercase letters\n"
              << "  --include-lowercase         Include lowercase letters\n"
              << "  --exclude-lowercase         Exclude lowercase letters\n"
              << "  --include-digits            Include digits\n"
              << "  --exclude-digits            Exclude digits\n"
              << "  --include-special           Include special characters\n"
              << "  --exclude-special           Exclude special characters\n"
              << "  --custom-chars <chars>      Use the provided characters\n"
              << "  --use-custom-only           Only use the provided custom characters\n\n"
              << "You can combine generation and cracking in one run.\n"
              << "Example: " << program
              << " --generate-wordlist passwords.txt --min-length 4 --max-length 4 --include-digits\n"
              << "         " << program << " --pdf file.pdf --wordlist passwords.txt --threads 4\n";
}

std::vector<std::string> load_wordlist(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("unable to open wordlist: " + path);
    }

    std::vector<char> raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::string file_contents;

    if (raw.size() >= 2) {
        unsigned char b0 = static_cast<unsigned char>(raw[0]);
        unsigned char b1 = static_cast<unsigned char>(raw[1]);

        if (raw.size() >= 2 && b0 == 0xFF && b1 == 0xFE) {
            std::u16string utf16;
            utf16.reserve((raw.size() - 2) / 2);
            for (std::size_t i = 2; i + 1 < raw.size(); i += 2) {
                char16_t code = static_cast<unsigned char>(raw[i]) |
                                (static_cast<char16_t>(static_cast<unsigned char>(raw[i + 1])) << 8);
                utf16.push_back(code);
            }
            std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
            file_contents = converter.to_bytes(utf16);
        } else if (raw.size() >= 2 && b0 == 0xFE && b1 == 0xFF) {
            std::u16string utf16;
            utf16.reserve((raw.size() - 2) / 2);
            for (std::size_t i = 2; i + 1 < raw.size(); i += 2) {
                char16_t code = (static_cast<char16_t>(static_cast<unsigned char>(raw[i])) << 8) |
                                static_cast<unsigned char>(raw[i + 1]);
                utf16.push_back(code);
            }
            std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
            file_contents = converter.to_bytes(utf16);
        } else {
            file_contents.assign(raw.begin(), raw.end());
        }
    } else {
        file_contents.assign(raw.begin(), raw.end());
    }

    std::vector<std::string> passwords;
    std::istringstream pass_stream(file_contents);
    std::string line;
    bool first_line = true;
    while (std::getline(pass_stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (first_line) {
            first_line = false;
            if (line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB && static_cast<unsigned char>(line[2]) == 0xBF) {
                line.erase(0, 3);
            }
        }

        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }

        if (!line.empty()) {
            passwords.push_back(line);
        }
    }

    return passwords;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 1) {
        print_usage(argv[0]);
        return 0;
    }

    unlock_pdf::util::WordlistOptions word_options;
    word_options.min_length = 6;
    word_options.max_length = 6;

    std::string pdf_path;
    std::string wordlist_path;
    std::string generation_path;
    unsigned int thread_count = 0;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto require_value = [&](const std::string& option) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error("missing value for option: " + option);
            }
            return argv[++i];
        };

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--pdf") {
            pdf_path = require_value(arg);
        } else if (arg == "--wordlist") {
            wordlist_path = require_value(arg);
        } else if (arg == "--generate-wordlist") {
            generation_path = require_value(arg);
        } else if (arg == "--min-length") {
            word_options.min_length = static_cast<std::size_t>(std::stoul(require_value(arg)));
        } else if (arg == "--max-length") {
            word_options.max_length = static_cast<std::size_t>(std::stoul(require_value(arg)));
        } else if (arg == "--include-uppercase") {
            word_options.include_uppercase = true;
        } else if (arg == "--exclude-uppercase") {
            word_options.include_uppercase = false;
        } else if (arg == "--include-lowercase") {
            word_options.include_lowercase = true;
        } else if (arg == "--exclude-lowercase") {
            word_options.include_lowercase = false;
        } else if (arg == "--include-digits") {
            word_options.include_digits = true;
        } else if (arg == "--exclude-digits") {
            word_options.include_digits = false;
        } else if (arg == "--include-special") {
            word_options.include_special = true;
        } else if (arg == "--exclude-special") {
            word_options.include_special = false;
        } else if (arg == "--custom-chars") {
            word_options.custom_characters = require_value(arg);
            word_options.use_custom_characters = true;
        } else if (arg == "--use-custom-only") {
            word_options.use_custom_characters = true;
            word_options.include_uppercase = false;
            word_options.include_lowercase = false;
            word_options.include_digits = false;
            word_options.include_special = false;
        } else if (arg == "--threads") {
            thread_count = static_cast<unsigned int>(std::stoul(require_value(arg)));
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }

    try {
        if (!generation_path.empty()) {
            auto summary = unlock_pdf::util::generate_wordlist(word_options, generation_path);
            std::cout << "Wordlist written to " << generation_path << " (" << summary.total_passwords
                      << " passwords)" << std::endl;
            if (wordlist_path.empty()) {
                wordlist_path = generation_path;
            }
        }

        if (!pdf_path.empty()) {
            if (wordlist_path.empty()) {
                throw std::runtime_error("no wordlist specified for cracking");
            }

            std::cout << "Reading password list..." << std::endl;
            std::vector<std::string> passwords = load_wordlist(wordlist_path);
            std::cout << "Loaded " << passwords.size() << " passwords" << std::endl;

            unlock_pdf::pdf::CrackResult result;
            if (!unlock_pdf::pdf::crack_pdf(passwords, pdf_path, result, thread_count)) {
                return 1;
            }

            if (!result.success) {
                return 2;
            }
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}