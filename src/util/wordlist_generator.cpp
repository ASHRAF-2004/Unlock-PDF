#include "util/wordlist_generator.h"

#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace unlock_pdf::util {
namespace {

std::size_t safe_pow(std::size_t base, std::size_t exp) {
    if (exp == 0) {
        return 1;
    }
    std::size_t result = 1;
    for (std::size_t i = 0; i < exp; ++i) {
        if (result > std::numeric_limits<std::size_t>::max() / base) {
            throw std::overflow_error("wordlist size overflow");
        }
        result *= base;
    }
    return result;
}

void generate_length(std::size_t length,
                     const std::string& alphabet,
                     std::string& current,
                     std::ofstream& output,
                     std::vector<std::string>* generated,
                     std::size_t& generated_count) {
    if (current.size() == length) {
        output << current << '\n';
        if (generated) {
            generated->push_back(current);
        }
        ++generated_count;
        if (generated_count % 100000 == 0) {
            std::cout << "Generated " << generated_count << " passwords..." << std::endl;
        }
        return;
    }

    for (char ch : alphabet) {
        current.push_back(ch);
        generate_length(length, alphabet, current, output, generated, generated_count);
        current.pop_back();
    }
}

}  // namespace

WordlistSummary generate_wordlist(const WordlistOptions& options,
                                  const std::string& output_path,
                                  std::vector<std::string>* generated) {
    if (options.min_length == 0 || options.max_length < options.min_length) {
        throw std::invalid_argument("invalid wordlist length range");
    }

    std::string alphabet;
    if (options.use_custom_characters) {
        if (options.custom_characters.empty()) {
            throw std::invalid_argument("custom characters must not be empty");
        }
        alphabet = options.custom_characters;
    } else {
        if (options.include_uppercase) {
            alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        }
        if (options.include_lowercase) {
            alphabet += "abcdefghijklmnopqrstuvwxyz";
        }
        if (options.include_digits) {
            alphabet += "0123456789";
        }
        if (options.include_special) {
            alphabet += "!@#$%^&*()_+={}[]|:;<>,.?/~";
        }
    }

    if (alphabet.empty()) {
        throw std::invalid_argument("character set is empty");
    }

    WordlistSummary summary{};
    for (std::size_t length = options.min_length; length <= options.max_length; ++length) {
        summary.total_passwords += safe_pow(alphabet.size(), length);
    }

    std::ofstream output(output_path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("failed to open wordlist file for writing");
    }

    std::cout << "Generating wordlist with " << alphabet.size() << " characters ("
              << summary.total_passwords << " combinations)" << std::endl;

    std::string current;
    std::size_t generated_count = 0;
    for (std::size_t length = options.min_length; length <= options.max_length; ++length) {
        current.clear();
        current.reserve(length);
        generate_length(length, alphabet, current, output, generated, generated_count);
    }

    std::cout << "Wordlist generation complete. Total passwords: " << generated_count << std::endl;
    return summary;
}

}  // namespace unlock_pdf::util