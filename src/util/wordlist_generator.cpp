#include "util/wordlist_generator.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace unlock_pdf::util {
namespace {

std::string add_decimal_strings(const std::string& a, const std::string& b) {
    std::string result;
    result.reserve(std::max(a.size(), b.size()) + 1);

    int carry = 0;
    auto it_a = a.rbegin();
    auto it_b = b.rbegin();
    while (it_a != a.rend() || it_b != b.rend() || carry != 0) {
        int digit_a = (it_a != a.rend()) ? (*it_a++ - '0') : 0;
        int digit_b = (it_b != b.rend()) ? (*it_b++ - '0') : 0;
        int sum = digit_a + digit_b + carry;
        carry = sum / 10;
        result.push_back(static_cast<char>('0' + (sum % 10)));
    }
    std::reverse(result.begin(), result.end());
    return result;
}

std::string multiply_decimal_string(std::string value, std::size_t multiplier) {
    if (value == "0" || multiplier == 0) {
        return "0";
    }

    std::string result;
    result.reserve(value.size() + 20);

    std::size_t carry = 0;
    for (auto it = value.rbegin(); it != value.rend(); ++it) {
        std::size_t digit = static_cast<std::size_t>(*it - '0');
        std::size_t product = digit * multiplier + carry;
        result.push_back(static_cast<char>('0' + (product % 10)));
        carry = product / 10;
    }

    while (carry > 0) {
        result.push_back(static_cast<char>('0' + (carry % 10)));
        carry /= 10;
    }

    while (result.size() > 1 && result.back() == '0') {
        result.pop_back();
    }

    std::reverse(result.begin(), result.end());
    return result;
}

std::string pow_decimal_string(std::size_t base, std::size_t exp) {
    std::string result = "1";
    for (std::size_t i = 0; i < exp; ++i) {
        result = multiply_decimal_string(result, base);
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
    std::size_t total_passwords = 0;
    std::string total_passwords_text = "0";
    for (std::size_t length = options.min_length; length <= options.max_length; ++length) {
        const std::string count_text = pow_decimal_string(alphabet.size(), length);
        total_passwords_text = add_decimal_strings(total_passwords_text, count_text);

        bool count_overflowed = false;
        std::size_t count = 1;
        for (std::size_t i = 0; i < length; ++i) {
            if (count > std::numeric_limits<std::size_t>::max() / alphabet.size()) {
                count_overflowed = true;
                break;
            }
            count *= alphabet.size();
        }

        if (!count_overflowed && !summary.overflowed) {
            if (total_passwords > std::numeric_limits<std::size_t>::max() - count) {
                summary.overflowed = true;
                total_passwords = std::numeric_limits<std::size_t>::max();
            } else {
                total_passwords += count;
            }
        } else {
            summary.overflowed = true;
            total_passwords = std::numeric_limits<std::size_t>::max();
        }
    }

    summary.total_passwords_text = total_passwords_text;
    summary.total_passwords = summary.overflowed ? std::numeric_limits<std::size_t>::max() : total_passwords;

    std::ofstream output(output_path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("failed to open wordlist file for writing");
    }

    std::cout << "Generating wordlist with " << alphabet.size() << " characters ("
              << summary.total_passwords_text << " combinations";
    if (summary.overflowed) {
        std::cout << ", exceeds 64-bit counter";
    }
    std::cout << ")" << std::endl;


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