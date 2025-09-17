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

}  // namespace unlock_pdf::pdf