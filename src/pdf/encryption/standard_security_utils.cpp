#include "pdf/encryption/standard_security_utils.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "crypto/md5.h"
#include "crypto/rc4.h"

namespace unlock_pdf::pdf::standard_security {
namespace {

constexpr std::array<unsigned char, 32> kPasswordPadding = {
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A};

std::vector<unsigned char> md5_hash(const std::vector<unsigned char>& data) {
    return unlock_pdf::crypto::md5_bytes(data);
}

std::vector<unsigned char> md5_hash_truncated(const std::vector<unsigned char>& data, std::size_t length) {
    std::vector<unsigned char> truncated(data.begin(), data.begin() + std::min(length, data.size()));
    return unlock_pdf::crypto::md5_bytes(truncated);
}

}  // namespace

std::vector<unsigned char> pad_password(const std::string& password) {
    std::vector<unsigned char> padded(32, 0);
    std::size_t length = std::min<std::size_t>(password.size(), 32);
    std::copy(password.begin(), password.begin() + length, padded.begin());
    if (length < 32) {
        std::copy(kPasswordPadding.begin(), kPasswordPadding.begin() + (32 - length), padded.begin() + length);
    }
    return padded;
}

std::string unpad_password(const std::vector<unsigned char>& padded) {
    if (padded.empty()) {
        return {};
    }
    std::size_t max_length = std::min<std::size_t>(padded.size(), kPasswordPadding.size());
    for (std::size_t n = 0; n <= max_length; ++n) {
        bool matches = true;
        for (std::size_t j = 0; j + n < max_length; ++j) {
            if (padded[n + j] != kPasswordPadding[j]) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return std::string(reinterpret_cast<const char*>(padded.data()), n);
        }
    }
    return std::string(reinterpret_cast<const char*>(padded.data()), max_length);
}

std::vector<unsigned char> compute_encryption_key(const std::string& password,
                                                  const PDFEncryptInfo& info,
                                                  int revision,
                                                  int key_length_bits) {
    if (key_length_bits <= 0) {
        return {};
    }
    std::vector<unsigned char> padded = pad_password(password);
    std::vector<unsigned char> data = padded;
    data.insert(data.end(), info.o_string.begin(), info.o_string.end());

    int permissions = info.permissions;
    std::uint32_t perms = static_cast<std::uint32_t>(permissions);
    unsigned char perms_bytes[4] = {
        static_cast<unsigned char>(perms & 0xFFu),
        static_cast<unsigned char>((perms >> 8) & 0xFFu),
        static_cast<unsigned char>((perms >> 16) & 0xFFu),
        static_cast<unsigned char>((perms >> 24) & 0xFFu)};
    data.insert(data.end(), std::begin(perms_bytes), std::end(perms_bytes));

    if (!info.id.empty()) {
        data.insert(data.end(), info.id.begin(), info.id.end());
    }

    if (revision >= 4 && !info.encrypt_metadata) {
        const unsigned char metadata[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        data.insert(data.end(), std::begin(metadata), std::end(metadata));
    }

    std::vector<unsigned char> hash = md5_hash(data);
    std::size_t key_length_bytes = static_cast<std::size_t>(key_length_bits / 8);
    if (revision >= 3) {
        for (int i = 0; i < 50; ++i) {
            hash = md5_hash_truncated(hash, key_length_bytes);
        }
    }
    if (hash.size() < key_length_bytes) {
        return {};
    }
    return std::vector<unsigned char>(hash.begin(), hash.begin() + key_length_bytes);
}

bool check_user_password(const std::string& password,
                         const PDFEncryptInfo& info,
                         int revision,
                         int key_length_bits) {
    if (info.u_string.empty()) {
        return false;
    }
    std::vector<unsigned char> key = compute_encryption_key(password, info, revision, key_length_bits);
    if (key.empty()) {
        return false;
    }

    unlock_pdf::crypto::RC4 rc4(key);

    if (revision <= 2) {
        std::array<unsigned char, 32> buffer = kPasswordPadding;
        rc4.crypt(buffer.data(), buffer.data(), buffer.size());
        if (info.u_string.size() < buffer.size()) {
            return false;
        }
        return std::equal(buffer.begin(), buffer.end(), info.u_string.begin());
    }

    std::vector<unsigned char> input(kPasswordPadding.begin(), kPasswordPadding.end());
    if (!info.id.empty()) {
        input.insert(input.end(), info.id.begin(), info.id.end());
    }
    std::vector<unsigned char> digest = md5_hash(input);
    digest.resize(16);

    std::vector<unsigned char> buffer = digest;
    rc4.set_key(key);
    rc4.crypt(buffer.data(), buffer.data(), buffer.size());

    for (int i = 1; i <= 19; ++i) {
        std::vector<unsigned char> iteration_key = key;
        for (unsigned char& byte : iteration_key) {
            byte ^= static_cast<unsigned char>(i);
        }
        rc4.set_key(iteration_key);
        rc4.crypt(buffer.data(), buffer.data(), buffer.size());
    }

    if (info.u_string.size() < buffer.size()) {
        return false;
    }
    return std::equal(buffer.begin(), buffer.end(), info.u_string.begin());
}

bool check_owner_password(const std::string& password,
                          const PDFEncryptInfo& info,
                          int revision,
                          int key_length_bits) {
    if (info.o_string.empty()) {
        return false;
    }
    std::vector<unsigned char> padded = pad_password(password);
    std::vector<unsigned char> digest = md5_hash(padded);
    std::size_t key_length_bytes = static_cast<std::size_t>(key_length_bits / 8);
    if (revision >= 3) {
        for (int i = 0; i < 50; ++i) {
            digest = md5_hash(digest);
        }
    }
    if (digest.size() < key_length_bytes) {
        return false;
    }
    digest.resize(key_length_bytes);

    std::vector<unsigned char> data(info.o_string.begin(), info.o_string.end());
    unlock_pdf::crypto::RC4 rc4(digest);
    rc4.crypt(data.data(), data.data(), data.size());

    if (revision >= 3) {
        for (int i = 1; i <= 19; ++i) {
            std::vector<unsigned char> iteration_key = digest;
            for (unsigned char& byte : iteration_key) {
                byte ^= static_cast<unsigned char>(i);
            }
            rc4.set_key(iteration_key);
            rc4.crypt(data.data(), data.data(), data.size());
        }
    }

    std::string user_password = unpad_password(data);
    if (user_password.empty() && !data.empty()) {
        user_password.assign(reinterpret_cast<const char*>(data.data()),
                             reinterpret_cast<const char*>(data.data() + data.size()));
    }
    return check_user_password(user_password, info, revision, key_length_bits);
}

}  // namespace unlock_pdf::pdf::standard_security
