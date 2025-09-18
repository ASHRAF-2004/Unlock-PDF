#ifndef UNLOCK_PDF_UTIL_WORDLIST_GENERATOR_H
#define UNLOCK_PDF_UTIL_WORDLIST_GENERATOR_H

#include <cstddef>
#include <string>
#include <vector>

namespace unlock_pdf::util {

struct WordlistOptions {
    std::size_t min_length = 10;
    std::size_t max_length = 10;
    bool include_uppercase = true;
    bool include_lowercase = true;
    bool include_digits = true;
    bool include_special = true;
    bool use_custom_characters = false;
    std::string custom_characters;
};

struct WordlistSummary {
    std::size_t total_passwords = 0;
    bool overflowed = false;
    std::string total_passwords_text;
};

WordlistSummary generate_wordlist(const WordlistOptions& options,
                                  const std::string& output_path,
                                  std::vector<std::string>* generated = nullptr);

}  // namespace unlock_pdf::util

#endif  // UNLOCK_PDF_UTIL_WORDLIST_GENERATOR_H