#include "crypto/aes.h"

#include <algorithm>
#include <array>
#include <cstdint>

namespace unlock_pdf::crypto {
namespace {

static const unsigned char AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const unsigned char AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

inline unsigned char aes_sub_byte(unsigned char value) {
    return AES_SBOX[value];
}

inline unsigned char aes_inv_sub_byte(unsigned char value) {
    return AES_INV_SBOX[value];
}

inline unsigned char multiply(unsigned char x, unsigned char y) {
    unsigned char result = 0;
    unsigned char a = x;
    unsigned char b = y;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= a;
        }
        bool carry = (a & 0x80) != 0;
        a <<= 1;
        if (carry) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return result;
}

uint32_t aes_sub_word(uint32_t word) {
    return (static_cast<uint32_t>(aes_sub_byte((word >> 24) & 0xff)) << 24) |
           (static_cast<uint32_t>(aes_sub_byte((word >> 16) & 0xff)) << 16) |
           (static_cast<uint32_t>(aes_sub_byte((word >> 8) & 0xff)) << 8) |
           static_cast<uint32_t>(aes_sub_byte(word & 0xff));
}

uint32_t aes_rot_word(uint32_t word) {
    return (word << 8) | (word >> 24);
}

void add_round_key(std::array<unsigned char, 16>& state,
                   const std::array<unsigned char, 16>& round_key) {
    for (std::size_t i = 0; i < state.size(); ++i) {
        state[i] ^= round_key[i];
    }
}

void sub_bytes(std::array<unsigned char, 16>& state) {
    for (unsigned char& value : state) {
        value = aes_sub_byte(value);
    }
}

void shift_rows(std::array<unsigned char, 16>& state) {
    unsigned char temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    std::swap(state[2], state[10]);
    std::swap(state[6], state[14]);

    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

void mix_columns(std::array<unsigned char, 16>& state) {
    for (int i = 0; i < 4; ++i) {
        unsigned char* column = state.data() + (i * 4);
        unsigned char a = column[0];
        unsigned char b = column[1];
        unsigned char c = column[2];
        unsigned char d = column[3];

        column[0] = multiply(a, 0x02) ^ multiply(b, 0x03) ^ c ^ d;
        column[1] = a ^ multiply(b, 0x02) ^ multiply(c, 0x03) ^ d;
        column[2] = a ^ b ^ multiply(c, 0x02) ^ multiply(d, 0x03);
        column[3] = multiply(a, 0x03) ^ b ^ c ^ multiply(d, 0x02);
    }
}

void inv_sub_bytes(std::array<unsigned char, 16>& state) {
    for (unsigned char& value : state) {
        value = aes_inv_sub_byte(value);
    }
}

void inv_shift_rows(std::array<unsigned char, 16>& state) {
    unsigned char temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

void inv_mix_columns(std::array<unsigned char, 16>& state) {
    for (int i = 0; i < 4; ++i) {
        unsigned char* column = state.data() + (i * 4);
        unsigned char a = column[0];
        unsigned char b = column[1];
        unsigned char c = column[2];
        unsigned char d = column[3];

        column[0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        column[1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        column[2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        column[3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

}  // namespace

AES128Encryptor::AES128Encryptor(const std::vector<unsigned char>& key) {
    if (key.size() != 16) {
        valid_ = false;
        return;
    }

    std::array<uint32_t, 44> words{};
    for (int i = 0; i < 4; ++i) {
        words[i] = (static_cast<uint32_t>(key[i * 4]) << 24) |
                   (static_cast<uint32_t>(key[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(key[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(key[i * 4 + 3]);
    }

    static const unsigned char rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    for (int i = 4; i < 44; ++i) {
        uint32_t temp = words[i - 1];
        if (i % 4 == 0) {
            temp = aes_sub_word(aes_rot_word(temp)) ^ (static_cast<uint32_t>(rcon[i / 4 - 1]) << 24);
        }
        words[i] = words[i - 4] ^ temp;
    }

    for (int round = 0; round < 11; ++round) {
        for (int word = 0; word < 4; ++word) {
            uint32_t value = words[round * 4 + word];
            round_keys_[round][word * 4 + 0] = static_cast<unsigned char>((value >> 24) & 0xff);
            round_keys_[round][word * 4 + 1] = static_cast<unsigned char>((value >> 16) & 0xff);
            round_keys_[round][word * 4 + 2] = static_cast<unsigned char>((value >> 8) & 0xff);
            round_keys_[round][word * 4 + 3] = static_cast<unsigned char>(value & 0xff);
        }
    }

    valid_ = true;
}

bool AES128Encryptor::valid() const { return valid_; }

void AES128Encryptor::encrypt_block(const unsigned char* input, unsigned char* output) const {
    std::array<unsigned char, 16> state{};
    std::copy(input, input + 16, state.begin());

    add_round_key(state, round_keys_[0]);
    for (int round = 1; round < 10; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys_[round]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys_[10]);

    std::copy(state.begin(), state.end(), output);
}

AES256Decryptor::AES256Decryptor(const std::vector<unsigned char>& key) {
    if (key.size() != 32) {
        valid_ = false;
        return;
    }

    std::array<uint32_t, 60> words{};
    for (int i = 0; i < 8; ++i) {
        words[i] = (static_cast<uint32_t>(key[i * 4]) << 24) |
                   (static_cast<uint32_t>(key[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(key[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(key[i * 4 + 3]);
    }

    static const unsigned char rcon[15] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};

    for (int i = 8; i < 60; ++i) {
        uint32_t temp = words[i - 1];
        if (i % 8 == 0) {
            temp = aes_sub_word(aes_rot_word(temp)) ^ (static_cast<uint32_t>(rcon[i / 8 - 1]) << 24);
        } else if (i % 8 == 4) {
            temp = aes_sub_word(temp);
        }
        words[i] = words[i - 8] ^ temp;
    }

    std::array<std::array<unsigned char, 16>, 15> enc_keys{};
    for (int round = 0; round < 15; ++round) {
        for (int word = 0; word < 4; ++word) {
            uint32_t value = words[round * 4 + word];
            enc_keys[round][word * 4 + 0] = static_cast<unsigned char>((value >> 24) & 0xff);
            enc_keys[round][word * 4 + 1] = static_cast<unsigned char>((value >> 16) & 0xff);
            enc_keys[round][word * 4 + 2] = static_cast<unsigned char>((value >> 8) & 0xff);
            enc_keys[round][word * 4 + 3] = static_cast<unsigned char>(value & 0xff);
        }
    }

    decrypt_round_keys_[0] = enc_keys[14];
    for (int round = 1; round < 14; ++round) {
        decrypt_round_keys_[round] = enc_keys[14 - round];
        inv_mix_columns(decrypt_round_keys_[round]);
    }
    decrypt_round_keys_[14] = enc_keys[0];

    valid_ = true;
}

bool AES256Decryptor::valid() const { return valid_; }

void AES256Decryptor::decrypt_block(const unsigned char* input, unsigned char* output) const {
    std::array<unsigned char, 16> state{};
    std::copy(input, input + 16, state.begin());

    add_round_key(state, decrypt_round_keys_[0]);
    for (int round = 1; round < 14; ++round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, decrypt_round_keys_[round]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, decrypt_round_keys_[14]);

    std::copy(state.begin(), state.end(), output);
}

bool aes128_cbc_encrypt(const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        const std::vector<unsigned char>& plaintext,
                        std::vector<unsigned char>& ciphertext) {
    if (key.size() != 16 || iv.size() != 16 || plaintext.empty() || plaintext.size() % 16 != 0) {
        return false;
    }

    AES128Encryptor encryptor(key);
    if (!encryptor.valid()) {
        return false;
    }

    ciphertext.resize(plaintext.size());
    std::array<unsigned char, 16> previous{};
    std::copy(iv.begin(), iv.end(), previous.begin());
    std::array<unsigned char, 16> block{};
    std::array<unsigned char, 16> encrypted{};

    for (std::size_t offset = 0; offset < plaintext.size(); offset += 16) {
        std::copy(plaintext.begin() + offset, plaintext.begin() + offset + 16, block.begin());
        for (std::size_t i = 0; i < 16; ++i) {
            block[i] ^= previous[i];
        }
        encryptor.encrypt_block(block.data(), encrypted.data());
        std::copy(encrypted.begin(), encrypted.end(), ciphertext.begin() + offset);
        previous = encrypted;
    }

    return true;
}

bool aes256_cbc_decrypt(const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        const std::vector<unsigned char>& ciphertext,
                        std::vector<unsigned char>& plaintext,
                        bool strip_padding) {
    if (key.size() != 32 || iv.size() != 16 || ciphertext.empty() || ciphertext.size() % 16 != 0) {
        return false;
    }

    AES256Decryptor decryptor(key);
    if (!decryptor.valid()) {
        return false;
    }

    plaintext.resize(ciphertext.size());
    std::array<unsigned char, 16> previous{};
    std::copy(iv.begin(), iv.end(), previous.begin());
    std::array<unsigned char, 16> block{};
    std::array<unsigned char, 16> decrypted{};

    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        std::copy(ciphertext.begin() + offset, ciphertext.begin() + offset + 16, block.begin());
        decryptor.decrypt_block(block.data(), decrypted.data());
        for (std::size_t i = 0; i < 16; ++i) {
            plaintext[offset + i] = decrypted[i] ^ previous[i];
        }
        previous = block;
    }

    if (!strip_padding) {
        return true;
    }

    if (plaintext.empty()) {
        return false;
    }

    unsigned char padding = plaintext.back();
    if (padding == 0 || padding > 16 || padding > plaintext.size()) {
        return false;
    }

    for (std::size_t i = 0; i < padding; ++i) {
        if (plaintext[plaintext.size() - 1 - i] != padding) {
            return false;
        }
    }

    plaintext.resize(plaintext.size() - padding);
    return true;
}

}  // namespace unlock_pdf::crypto
