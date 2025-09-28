#include <iostream>
#include <stdexcept>
#include <string>

#include "pdf/pdf_cracker.h"
#include "pdf/pdf_parser.h"
#include "util/wordlist_generator.h"

namespace {

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n\n"
              << "PDF Password Retriever options:\n"
              << "  --info <path>              Print PDF encryption details and exit\n"
              << "  --pdf <path>                Path to the encrypted PDF file\n"
              << "  --wordlist <path>           Path to a password wordlist file (streamed on demand)\n"
              << "  --threads <n>               Number of worker threads (default: auto)\n\n"
              << "Brute-force configuration:\n"
              << "  --min-length <n>            Minimum password length (default: 6)\n"
              << "  --max-length <n>            Maximum password length (default: 32)\n"
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
              << "Passwords are generated and tested on the fly, so even extremely large wordlists\n"
                 "can be processed without exhausting system memory.\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 1) {
        print_usage(argv[0]);
        return 0;
    }

    unlock_pdf::util::WordlistOptions word_options;
    word_options.min_length = 6;
    word_options.max_length = 32;

    std::string pdf_path;
    bool info_only = false;
    std::string wordlist_path;
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
        } else if (arg == "--info") {
            pdf_path = require_value(arg);
            info_only = true;
        } else if (arg == "--pdf") {
            pdf_path = require_value(arg);
        } else if (arg == "--wordlist") {
            wordlist_path = require_value(arg);
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
        if (info_only) {
            if (pdf_path.empty()) {
                std::cerr << "Error: no PDF path provided for --info" << std::endl;
                return 1;
            }
            unlock_pdf::pdf::PDFEncryptInfo info;
            if (!unlock_pdf::pdf::read_pdf_encrypt_info(pdf_path, info)) {
                return 1;
            }
            return 0;
        }

        if (!pdf_path.empty()) {
            unlock_pdf::pdf::CrackResult result;
            if (wordlist_path.empty()) {
                if (!unlock_pdf::pdf::crack_pdf_bruteforce(word_options, pdf_path, result, thread_count)) {
                    return 1;
                }
            } else {
                std::cout << "Streaming password list from '" << wordlist_path << "'" << std::endl;
                if (!unlock_pdf::pdf::crack_pdf_from_file(wordlist_path, pdf_path, result, thread_count)) {
                    return 1;
                }
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
