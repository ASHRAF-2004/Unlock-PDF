#ifndef UNLOCK_PDF_UTIL_WORDLIST_GENERATOR_H
#define UNLOCK_PDF_UTIL_WORDLIST_GENERATOR_H

#include <cstddef>
#include <string>

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

}  // namespace unlock_pdf::util

#endif  // UNLOCK_PDF_UTIL_WORDLIST_GENERATOR_H
