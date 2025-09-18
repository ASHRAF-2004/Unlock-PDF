#include "pdf/pdf_cracker.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <cstdint>
#include <functional>

#include "crypto/aes.h"
#include "crypto/md5.h"
#include "crypto/rc4.h"
#include "crypto/sha2.h"
#include "pdf/pdf_parser.h"

namespace unlock_pdf::pdf {
namespace {

struct ByteView {
    const unsigned char* data = nullptr;
    std::size_t size = 0;

    ByteView() = default;
    ByteView(const unsigned char* ptr, std::size_t length) : data(ptr), size(length) {}
};

std::vector<unsigned char> compute_hash_v5(const std::string& password,
                                           ByteView salt,
                                           ByteView user_data,
                                           int revision) {
    using unlock_pdf::crypto::aes128_cbc_encrypt;
    using unlock_pdf::crypto::sha256_bytes;
    using unlock_pdf::crypto::sha2_hash;

    std::vector<unsigned char> input;
    input.reserve(password.size() + salt.size + user_data.size);
    input.insert(input.end(), password.begin(), password.end());
    if (salt.size > 0 && salt.data != nullptr) {
        input.insert(input.end(), salt.data, salt.data + salt.size);
    }
    if (user_data.size > 0 && user_data.data != nullptr) {
        input.insert(input.end(), user_data.data, user_data.data + user_data.size);
    }

    std::vector<unsigned char> current = sha256_bytes(input);
    if (revision < 6) {
        return current;
    }

    std::vector<unsigned char> k1;
    std::vector<unsigned char> repeated;
    std::vector<unsigned char> encrypted;
    std::vector<unsigned char> key(16);
    std::vector<unsigned char> iv(16);

    int round = 0;
    while (true) {
        ++round;
        std::size_t combined_length = password.size() + current.size() + user_data.size;
        k1.resize(combined_length);

        auto k1_it = k1.begin();
        k1_it = std::copy(password.begin(), password.end(), k1_it);
        k1_it = std::copy(current.begin(), current.end(), k1_it);
        if (user_data.size > 0 && user_data.data != nullptr) {
            k1_it = std::copy(user_data.data, user_data.data + user_data.size, k1_it);
        }

        repeated.resize(combined_length * 64);
        auto repeat_it = repeated.begin();
        for (int i = 0; i < 64; ++i) {
            repeat_it = std::copy(k1.begin(), k1.end(), repeat_it);
        }

        if (current.size() < 32) {
            return {};
        }

        std::copy(current.begin(), current.begin() + 16, key.begin());
        std::copy(current.begin() + 16, current.begin() + 32, iv.begin());

        encrypted.resize(repeated.size());
        if (!aes128_cbc_encrypt(key, iv, repeated, encrypted)) {
            return {};
        }

        int sum = 0;
        for (std::size_t i = 0; i < 16 && i < encrypted.size(); ++i) {
            sum += encrypted[i];
        }
        int mod = sum % 3;
        std::size_t next_bits = (mod == 0) ? 256 : (mod == 1 ? 384 : 512);

        current = sha2_hash(encrypted, next_bits);
        if (current.empty()) {
            return {};
        }

        if (round >= 64) {
            unsigned char last = encrypted.back();
            if (last <= static_cast<unsigned char>(round - 32)) {
                break;
            }
        }
    }

    if (current.size() > 32) {
        current.resize(32);
    }
    return current;
}

bool try_user_password(const std::string& password, const PDFEncryptInfo& info, int revision) {
    using unlock_pdf::crypto::aes256_cbc_decrypt;

    if (info.u_string.size() < 48 || info.ue_string.size() < 32) {
        return false;
    }

    std::string truncated = password;
    if (truncated.size() > 127) {
        truncated.resize(127);
    }

    const unsigned char* u_data = info.u_string.data();
    ByteView validation_salt(u_data + 32, 8);
    ByteView key_salt(u_data + 40, 8);
    ByteView empty_user_data(nullptr, 0);

    std::vector<unsigned char> hash = compute_hash_v5(truncated, validation_salt, empty_user_data, revision);
    if (hash.size() < 32 || !std::equal(u_data, u_data + 32, hash.begin())) {
        return false;
    }

    std::vector<unsigned char> key = compute_hash_v5(truncated, key_salt, empty_user_data, revision);
    if (key.size() < 32) {
        return false;
    }

    std::vector<unsigned char> iv(16, 0);
    std::vector<unsigned char> file_key;
    return aes256_cbc_decrypt(key, iv, info.ue_string, file_key, false) && file_key.size() >= 32;
}

bool try_owner_password(const std::string& password, const PDFEncryptInfo& info, int revision) {
    using unlock_pdf::crypto::aes256_cbc_decrypt;

    if (info.o_string.size() < 48 || info.oe_string.size() < 32 || info.u_string.size() < 48) {
        return false;
    }

    std::string truncated = password;
    if (truncated.size() > 127) {
        truncated.resize(127);
    }

    const unsigned char* o_data = info.o_string.data();
    ByteView validation_salt(o_data + 32, 8);
    ByteView key_salt(o_data + 40, 8);
    std::size_t user_entry_len = std::min<std::size_t>(48, info.u_string.size());
    ByteView user_entry(user_entry_len == 0 ? nullptr : info.u_string.data(), user_entry_len);

    std::vector<unsigned char> hash = compute_hash_v5(truncated, validation_salt, user_entry, revision);
    if (hash.size() < 32 || !std::equal(o_data, o_data + 32, hash.begin())) {
        return false;
    }

    std::vector<unsigned char> key = compute_hash_v5(truncated, key_salt, user_entry, revision);
    if (key.size() < 32) {
        return false;
    }

    std::vector<unsigned char> iv(16, 0);
    std::vector<unsigned char> file_key;
    return aes256_cbc_decrypt(key, iv, info.oe_string, file_key, false) && file_key.size() >= 32;
}

bool check_password_variants(const std::string& password,
                             const PDFEncryptInfo& info,
                             std::string& matched_variant) {
    auto format_variant = [](const char* role, int revision) {
        return std::string(role) + " R" + std::to_string(revision);
    };

    if (info.revision >= 6) {
        if (try_user_password(password, info, info.revision)) {
            matched_variant = format_variant("user", info.revision);
            return true;
        }
        if (try_owner_password(password, info, info.revision)) {
            matched_variant = format_variant("owner", info.revision);
            return true;
        }
    }

    if (info.revision >= 5) {
        if (try_user_password(password, info, 5)) {
            matched_variant = format_variant("user", 5);
            return true;
        }
        if (try_owner_password(password, info, 5)) {
            matched_variant = format_variant("owner", 5);
            return true;
        }
    }

    return false;
}

void print_progress(std::size_t tried, std::size_t total) {
    if (total == 0) {
        std::cout << "\rPasswords tried: " << tried << std::flush;
        return;
    }
    double progress = static_cast<double>(tried) / static_cast<double>(total) * 100.0;
    std::cout << "\rTrying passwords... " << std::fixed << std::setprecision(2) << progress << "% (" << tried << "/"
              << total << ")" << std::flush;
}

}  // namespace

bool crack_pdf(const std::vector<std::string>& passwords,
               const std::string& pdf_path,
               CrackResult& result,
               unsigned int thread_count) {
    result = CrackResult{};
    result.total_passwords = passwords.size();

    PDFEncryptInfo encrypt_info;
    if (!read_pdf_encrypt_info(pdf_path, encrypt_info)) {
        return false;
    }

    if (encrypt_info.revision < 5) {
        std::cerr << "Error: Only AES-256 (Revision 5/6) PDFs are supported by this retriever." << std::endl;
        return false;
    }

    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) {
            thread_count = 2;
        }
    }
    thread_count = std::min<unsigned int>(thread_count, 16);
    if (thread_count > passwords.size()) {
        thread_count = static_cast<unsigned int>(passwords.size());
        thread_count = std::max(thread_count, 1u);
    }

    std::cout << "\nStarting password cracking with " << thread_count << " threads" << std::endl;

    std::atomic<bool> password_found{false};
    std::atomic<std::size_t> passwords_tried{0};
    std::mutex result_mutex;
    std::string found_password;
    std::string found_variant;

    auto start_time = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    std::size_t per_thread = passwords.size() / thread_count;
    std::size_t remainder = passwords.size() % thread_count;
    std::size_t current_start = 0;

    auto worker = [&](std::size_t start, std::size_t end) {
        for (std::size_t i = start; i < end && !password_found.load(); ++i) {
            std::string variant;
            if (check_password_variants(passwords[i], encrypt_info, variant)) {
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!password_found) {
                    password_found = true;
                    found_password = passwords[i];
                    found_variant = variant;
                    std::cout << "\nPASSWORD FOUND [" << variant << "]: " << passwords[i] << std::endl;
                }
                return;
            }

            std::size_t tried = ++passwords_tried;
            if (tried % 100 == 0) {
                print_progress(tried, passwords.size());
            }
        }
    };

    for (unsigned int i = 0; i < thread_count; ++i) {
        std::size_t count = per_thread + (i < remainder ? 1 : 0);
        std::size_t end = current_start + count;
        threads.emplace_back(worker, current_start, end);
        current_start = end;
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    std::cout << "\n\nFinished in " << duration.count() << " seconds" << std::endl;

    result.passwords_tried = passwords_tried.load();
    result.success = password_found.load();
    if (result.success) {
        result.password = found_password;
        result.variant = found_variant;
        std::cout << "Password found: " << found_password << std::endl;
    } else {
        std::cout << "Password not found in the provided list" << std::endl;
    }

    return true;
}

bool crack_pdf_bruteforce(const unlock_pdf::util::WordlistOptions& options,
                          const std::string& pdf_path,
                          CrackResult& result,
                          unsigned int thread_count) {
    result = CrackResult{};

    if (options.min_length == 0 || options.max_length < options.min_length) {
        std::cerr << "Error: invalid password length range" << std::endl;
        return false;
    }

    std::string alphabet;
    if (options.use_custom_characters) {
        if (options.custom_characters.empty()) {
            std::cerr << "Error: custom characters must not be empty" << std::endl;
            return false;
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
        std::cerr << "Error: character set is empty" << std::endl;
        return false;
    }

    PDFEncryptInfo encrypt_info;
    if (!read_pdf_encrypt_info(pdf_path, encrypt_info)) {
        return false;
    }

    if (encrypt_info.revision < 5) {
        std::cerr << "Error: Only AES-256 (Revision 5/6) PDFs are supported by this retriever." << std::endl;
        return false;
    }

    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) {
            thread_count = 2;
        }
    }
    thread_count = std::min<unsigned int>(thread_count, 16);
    thread_count = std::max(thread_count, 1u);

    std::cout << "\nStarting brute-force password search with " << thread_count << " threads" << std::endl;

    struct Task {
        std::string prefix;
        std::size_t target_length = 0;
    };

    std::vector<Task> tasks;
    std::size_t base_prefix_length = std::min<std::size_t>(options.min_length, static_cast<std::size_t>(2));
    if (base_prefix_length == 0) {
        base_prefix_length = 1;
    }

    std::string current_prefix;
    auto add_tasks_for_length = [&](std::size_t length) {
        std::size_t prefix_length = std::min<std::size_t>(length, base_prefix_length);
        current_prefix.clear();
        current_prefix.reserve(prefix_length);
        if (prefix_length == 0) {
            tasks.push_back(Task{std::string(), length});
            return;
        }

        std::function<void(std::size_t)> dfs = [&](std::size_t depth) {
            if (depth == prefix_length) {
                tasks.push_back(Task{current_prefix, length});
                return;
            }
            for (char ch : alphabet) {
                current_prefix.push_back(ch);
                dfs(depth + 1);
                current_prefix.pop_back();
            }
        };
        dfs(0);
    };

    for (std::size_t length = options.min_length; length <= options.max_length; ++length) {
        add_tasks_for_length(length);
    }

    std::atomic<bool> password_found{false};
    std::atomic<std::uint64_t> passwords_tried{0};
    std::mutex result_mutex;
    std::string found_password;
    std::string found_variant;

    auto start_time = std::chrono::steady_clock::now();

    std::atomic<std::size_t> next_task{0};

    auto attempt_password = [&](const std::string& candidate) -> bool {
        if (password_found.load()) {
            return true;
        }

        std::string variant;
        if (check_password_variants(candidate, encrypt_info, variant)) {
            std::lock_guard<std::mutex> lock(result_mutex);
            if (!password_found.load()) {
                password_found = true;
                found_password = candidate;
                found_variant = variant;
                std::cout << "\nPASSWORD FOUND [" << variant << "]: " << candidate << std::endl;
            }
            return true;
        }

        std::uint64_t tried = ++passwords_tried;
        if (tried % 1000 == 0) {
            print_progress(static_cast<std::size_t>(tried), 0);
        }
        return false;
    };

    auto extend_password = [&](auto& self, std::string& current, std::size_t target_length) -> bool {
        if (password_found.load()) {
            return true;
        }

        if (current.size() == target_length) {
            return attempt_password(current);
        }

        for (char ch : alphabet) {
            current.push_back(ch);
            if (self(self, current, target_length)) {
                current.pop_back();
                return true;
            }
            current.pop_back();
            if (password_found.load()) {
                return true;
            }
        }
        return false;
    };

    auto worker = [&]() {
        while (!password_found.load()) {
            std::size_t index = next_task.fetch_add(1);
            if (index >= tasks.size()) {
                break;
            }

            const Task& task = tasks[index];
            std::string current = task.prefix;
            if (current.size() > task.target_length) {
                continue;
            }
            extend_password(extend_password, current, task.target_length);
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (unsigned int i = 0; i < thread_count; ++i) {
        threads.emplace_back(worker);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    std::cout << "\n\nFinished in " << duration.count() << " seconds" << std::endl;

    result.passwords_tried = static_cast<std::size_t>(passwords_tried.load());
    result.total_passwords = 0;
    result.success = password_found.load();
    if (result.success) {
        result.password = found_password;
        result.variant = found_variant;
        std::cout << "Password found: " << found_password << std::endl;
    } else {
        std::cout << "Password not found in generated range" << std::endl;
    }

    return true;
}

}  // namespace unlock_pdf::pdf
