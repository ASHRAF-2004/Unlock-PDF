#define _CRT_SECURE_NO_WARNINGS
#include <algorithm>
#include <array>
#include <atomic>
#include <codecvt>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <locale>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

struct PDFEncryptInfo {
    std::vector<unsigned char> id;
    std::vector<unsigned char> u_string;
    std::vector<unsigned char> o_string;
    std::vector<unsigned char> ue_string;
    std::vector<unsigned char> oe_string;
    std::vector<unsigned char> perms;
    int version = 0;
    int revision = 0;
    int length = 0;
    bool encrypted = false;
};

std::mutex g_mutex;
std::atomic<bool> g_password_found{false};
std::string g_found_password;
std::string g_found_variant;
std::atomic<size_t> g_passwords_tried{0};
size_t g_total_passwords = 0;

void print_progress() {
    size_t total = g_total_passwords;
    if (total == 0) {
        return;
    }

    size_t tried = g_passwords_tried.load();
    float progress = static_cast<float>(tried) / static_cast<float>(total) * 100.0f;
    std::cout << "\rTrying passwords... " << std::fixed << std::setprecision(2)
              << progress << "% (" << tried << "/" << total << ")" << std::flush;
}

struct ByteView {
    const unsigned char* data = nullptr;
    size_t size = 0;

    ByteView() = default;
    ByteView(const unsigned char* ptr, size_t count) : data(ptr), size(count) {}
};

namespace {

inline uint32_t rotr(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

class SHA256 {
public:
    SHA256() {
        reset();
    }

    void reset() {
        state_[0] = 0x6a09e667U;
        state_[1] = 0xbb67ae85U;
        state_[2] = 0x3c6ef372U;
        state_[3] = 0xa54ff53aU;
        state_[4] = 0x510e527fU;
        state_[5] = 0x9b05688cU;
        state_[6] = 0x1f83d9abU;
        state_[7] = 0x5be0cd19U;
        bitlen_ = 0;
        buffer_len_ = 0;
        buffer_.fill(0);
    }

    void update(const unsigned char* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            bitlen_ += 8;
            if (buffer_len_ == 64) {
                transform(buffer_.data());
                buffer_len_ = 0;
            }
        }
    }

    void finalize(unsigned char* hash) {
        uint64_t total_bits = bitlen_;
        buffer_[buffer_len_++] = 0x80;

        if (buffer_len_ > 56) {
            while (buffer_len_ < 64) {
                buffer_[buffer_len_++] = 0x00;
            }
            transform(buffer_.data());
            buffer_len_ = 0;
        }

        while (buffer_len_ < 56) {
            buffer_[buffer_len_++] = 0x00;
        }

        for (int i = 7; i >= 0; --i) {
            buffer_[buffer_len_++] = static_cast<unsigned char>((total_bits >> (i * 8)) & 0xff);
        }

        transform(buffer_.data());
        buffer_len_ = 0;

        for (int i = 0; i < 8; ++i) {
            hash[i * 4 + 0] = static_cast<unsigned char>((state_[i] >> 24) & 0xff);
            hash[i * 4 + 1] = static_cast<unsigned char>((state_[i] >> 16) & 0xff);
            hash[i * 4 + 2] = static_cast<unsigned char>((state_[i] >> 8) & 0xff);
            hash[i * 4 + 3] = static_cast<unsigned char>(state_[i] & 0xff);
        }
    }

private:
    void transform(const unsigned char* chunk) {
        static const uint32_t k[64] = {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
        };

        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(chunk[i * 4]) << 24) |
                   (static_cast<uint32_t>(chunk[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(chunk[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(chunk[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = state_[0];
        uint32_t b = state_[1];
        uint32_t c = state_[2];
        uint32_t d = state_[3];
        uint32_t e = state_[4];
        uint32_t f = state_[5];
        uint32_t g = state_[6];
        uint32_t h = state_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    uint32_t state_[8];
    uint64_t bitlen_ = 0;
    std::array<unsigned char, 64> buffer_{};
    size_t buffer_len_ = 0;
};


std::vector<unsigned char> sha256_bytes(const std::vector<unsigned char>& data) {
    SHA256 ctx;
    if (!data.empty()) {
        ctx.update(data.data(), data.size());
    }
    std::vector<unsigned char> hash(32);
    ctx.finalize(hash.data());
    return hash;
}

inline uint64_t rotr64(uint64_t value, uint32_t bits) {
    return (value >> bits) | (value << (64 - bits));
}

class SHA512 {
public:
    explicit SHA512(size_t digest_bits = 512) {
        set_digest_length(digest_bits);
        reset();
    }

    void reset() {
        static const uint64_t sha512_init[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
            0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
        static const uint64_t sha384_init[8] = {
            0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
            0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
            0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};

        if (digest_len_ == 48) {
            std::copy(std::begin(sha384_init), std::end(sha384_init), state_.begin());
        } else {
            std::copy(std::begin(sha512_init), std::end(sha512_init), state_.begin());
        }
        buffer_.fill(0);
        buffer_len_ = 0;
        bitlen_low_ = 0;
        bitlen_high_ = 0;
    }

    void update(const unsigned char* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            bitlen_low_ += 8;
            if (bitlen_low_ < 8) {
                ++bitlen_high_;
            }
            if (buffer_len_ == 128) {
                transform(buffer_.data());
                buffer_len_ = 0;
            }
        }
        bitlen_high_ += (len >> 61);
    }

    void finalize(unsigned char* hash) {
        buffer_[buffer_len_++] = 0x80;
        if (buffer_len_ > 112) {
            while (buffer_len_ < 128) {
                buffer_[buffer_len_++] = 0x00;
            }
            transform(buffer_.data());
            buffer_len_ = 0;
        }
        while (buffer_len_ < 112) {
            buffer_[buffer_len_++] = 0x00;
        }
        for (int i = 7; i >= 0; --i) {
            buffer_[buffer_len_++] = static_cast<unsigned char>((bitlen_high_ >> (i * 8)) & 0xff);
        }
        for (int i = 7; i >= 0; --i) {
            buffer_[buffer_len_++] = static_cast<unsigned char>((bitlen_low_ >> (i * 8)) & 0xff);
        }
        transform(buffer_.data());
        buffer_len_ = 0;

        for (int i = 0; i < 8 && (i * 8) < static_cast<int>(digest_len_); ++i) {
            for (int j = 0; j < 8 && (i * 8 + j) < static_cast<int>(digest_len_); ++j) {
                hash[i * 8 + j] = static_cast<unsigned char>((state_[i] >> (56 - 8 * j)) & 0xff);
            }
        }
    }

private:
    void set_digest_length(size_t bits) {
        digest_len_ = (bits == 384) ? 48 : 64;
    }

    void transform(const unsigned char* chunk) {
        static const uint64_t k[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
            0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
            0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
            0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
            0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
            0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
            0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
            0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
            0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
            0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
            0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
            0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
            0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
            0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
            0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
            0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
            0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
            0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
            0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
            0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
            0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

        uint64_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint64_t>(chunk[i * 8]) << 56) |
                   (static_cast<uint64_t>(chunk[i * 8 + 1]) << 48) |
                   (static_cast<uint64_t>(chunk[i * 8 + 2]) << 40) |
                   (static_cast<uint64_t>(chunk[i * 8 + 3]) << 32) |
                   (static_cast<uint64_t>(chunk[i * 8 + 4]) << 24) |
                   (static_cast<uint64_t>(chunk[i * 8 + 5]) << 16) |
                   (static_cast<uint64_t>(chunk[i * 8 + 6]) << 8) |
                   static_cast<uint64_t>(chunk[i * 8 + 7]);
        }
        for (int i = 16; i < 80; ++i) {
            uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint64_t a = state_[0];
        uint64_t b = state_[1];
        uint64_t c = state_[2];
        uint64_t d = state_[3];
        uint64_t e = state_[4];
        uint64_t f = state_[5];
        uint64_t g = state_[6];
        uint64_t h = state_[7];

        for (int i = 0; i < 80; ++i) {
            uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            uint64_t ch = (e & f) ^ ((~e) & g);
            uint64_t temp1 = h + S1 + ch + k[i] + w[i];
            uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<uint64_t, 8> state_{};
    std::array<unsigned char, 128> buffer_{};
    size_t buffer_len_ = 0;
    uint64_t bitlen_low_ = 0;
    uint64_t bitlen_high_ = 0;
    size_t digest_len_ = 64;
};

std::vector<unsigned char> sha2_hash(const std::vector<unsigned char>& data, size_t bits) {
    if (bits == 256) {
        return sha256_bytes(data);
    }
    if (bits != 384 && bits != 512) {
        return {};
    }
    SHA512 ctx(bits);
    if (!data.empty()) {
        ctx.update(data.data(), data.size());
    }
    std::vector<unsigned char> hash(bits / 8);
    ctx.finalize(hash.data());
    return hash;
}

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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

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
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

inline unsigned char aes_sub_byte(unsigned char value) {
    return AES_SBOX[value];
}

inline unsigned char aes_inv_sub_byte(unsigned char value) {
    return AES_INV_SBOX[value];
}

inline uint32_t aes_sub_word(uint32_t word) {
    return (static_cast<uint32_t>(aes_sub_byte(static_cast<unsigned char>((word >> 24) & 0xff))) << 24) |
           (static_cast<uint32_t>(aes_sub_byte(static_cast<unsigned char>((word >> 16) & 0xff))) << 16) |
           (static_cast<uint32_t>(aes_sub_byte(static_cast<unsigned char>((word >> 8) & 0xff))) << 8) |
           static_cast<uint32_t>(aes_sub_byte(static_cast<unsigned char>(word & 0xff)));
}

inline uint32_t aes_rot_word(uint32_t word) {
    return (word << 8) | (word >> 24);
}

unsigned char xtime(unsigned char x) {
    return static_cast<unsigned char>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

unsigned char multiply(unsigned char x, unsigned char y) {
    unsigned char result = 0;
    while (y) {
        if (y & 1) {
            result ^= x;
        }
        x = xtime(x);
        y >>= 1;
    }
    return result;
}

class AES128Encryptor {
public:
    AES128Encryptor() = default;

    explicit AES128Encryptor(const std::vector<unsigned char>& key) {
        set_key(key);
    }

    bool valid() const {
        return valid_;
    }

    void set_key(const std::vector<unsigned char>& key) {
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

        for (int round = 0; round <= 10; ++round) {
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

    void encrypt_block(const unsigned char* input, unsigned char* output) const {
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

private:
    static void add_round_key(std::array<unsigned char, 16>& state,
                              const std::array<unsigned char, 16>& round_key) {
        for (size_t i = 0; i < state.size(); ++i) {
            state[i] ^= round_key[i];
        }
    }

    static void sub_bytes(std::array<unsigned char, 16>& state) {
        for (unsigned char& value : state) {
            value = aes_sub_byte(value);
        }
    }

    static void shift_rows(std::array<unsigned char, 16>& state) {
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

    static void mix_columns(std::array<unsigned char, 16>& state) {
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

    std::array<std::array<unsigned char, 16>, 11> round_keys_{};
    bool valid_ = false;
};

class AES256Decryptor {
public:
    explicit AES256Decryptor(const std::vector<unsigned char>& key) {
        set_key(key);
    }

    bool valid() const {
        return valid_;
    }

    void decrypt_block(const unsigned char* input, unsigned char* output) const {
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

private:
    void set_key(const std::vector<unsigned char>& key) {
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
        decrypt_round_keys_[14] = enc_keys[0];
        for (int round = 1; round < 14; ++round) {
            decrypt_round_keys_[round] = enc_keys[14 - round];
        }

        valid_ = true;
    }

    static void add_round_key(std::array<unsigned char, 16>& state,
                              const std::array<unsigned char, 16>& round_key) {
        for (size_t i = 0; i < state.size(); ++i) {
            state[i] ^= round_key[i];
        }
    }

    static void inv_sub_bytes(std::array<unsigned char, 16>& state) {
        for (unsigned char& value : state) {
            value = aes_inv_sub_byte(value);
        }
    }

    static void inv_shift_rows(std::array<unsigned char, 16>& state) {
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

    static void inv_mix_columns(std::array<unsigned char, 16>& state) {
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

    std::array<std::array<unsigned char, 16>, 15> decrypt_round_keys_{};
    bool valid_ = false;
};

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

    for (size_t offset = 0; offset < plaintext.size(); offset += 16) {
        std::copy(plaintext.begin() + offset, plaintext.begin() + offset + 16, block.begin());
        for (size_t i = 0; i < 16; ++i) {
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
                        bool strip_padding = true) {
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

    for (size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        std::copy(ciphertext.begin() + offset, ciphertext.begin() + offset + 16, block.begin());
        decryptor.decrypt_block(block.data(), decrypted.data());
        for (size_t i = 0; i < 16; ++i) {
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

    for (size_t i = 0; i < padding; ++i) {
        if (plaintext[plaintext.size() - 1 - i] != padding) {
            return false;
        }
    }

    plaintext.resize(plaintext.size() - padding);
    return true;
}

std::vector<unsigned char> compute_hash_v5(const std::string& password,
                                           ByteView salt,
                                           ByteView user_data,
                                           int revision) {
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
        size_t combined_length = password.size() + current.size() + user_data.size;
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
        for (size_t i = 0; i < 16 && i < encrypted.size(); ++i) {
            sum += encrypted[i];
        }
        int mod = sum % 3;
        size_t next_bits = (mod == 0) ? 256 : (mod == 1 ? 384 : 512);

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

void skip_whitespace_and_comments(const std::string& data, size_t& pos) {
    while (pos < data.size()) {
        unsigned char ch = static_cast<unsigned char>(data[pos]);
        if (std::isspace(ch)) {
            ++pos;
        } else if (data[pos] == '%') {
            while (pos < data.size() && data[pos] != '\n' && data[pos] != '\r') {
                ++pos;
            }
        } else {
            break;
        }
    }
}

int parse_pdf_int(const std::string& data, size_t& pos) {
    skip_whitespace_and_comments(data, pos);
    if (pos >= data.size()) {
        return 0;
    }

    bool negative = false;
    if (data[pos] == '+') {
        ++pos;
    } else if (data[pos] == '-') {
        negative = true;
        ++pos;
    }

    int value = 0;
    while (pos < data.size() && std::isdigit(static_cast<unsigned char>(data[pos]))) {
        value = value * 10 + (data[pos] - '0');
        ++pos;
    }
    return negative ? -value : value;
}

int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

std::string parse_pdf_name(const std::string& data, size_t& pos) {
    std::string name;
    while (pos < data.size()) {
        char ch = data[pos];
        if (std::isspace(static_cast<unsigned char>(ch)) || ch == '/' || ch == '<' || ch == '>' ||
            ch == '[' || ch == ']' || ch == '(' || ch == ')') {
            break;
        }
        if (ch == '#') {
            if (pos + 2 < data.size()) {
                int high = hex_value(data[pos + 1]);
                int low = hex_value(data[pos + 2]);
                if (high >= 0 && low >= 0) {
                    name.push_back(static_cast<char>((high << 4) | low));
                    pos += 3;
                    continue;
                }
            }
            ++pos;
        } else {
            name.push_back(ch);
            ++pos;
        }
    }
    return name;
}

std::vector<unsigned char> parse_pdf_hex_string(const std::string& data, size_t& pos) {
    std::vector<unsigned char> result;
    if (pos >= data.size() || data[pos] != '<') {
        return result;
    }
    ++pos;

    std::string hex;
    while (pos < data.size() && data[pos] != '>') {
        if (!std::isspace(static_cast<unsigned char>(data[pos]))) {
            hex.push_back(data[pos]);
        }
        ++pos;
    }
    if (pos < data.size() && data[pos] == '>') {
        ++pos;
    }

    if (hex.empty()) {
        return result;
    }

    if (hex.size() % 2 == 1) {
        hex.push_back('0');
    }

    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int high = hex_value(hex[i]);
        int low = hex_value(hex[i + 1]);
        if (high >= 0 && low >= 0) {
            result.push_back(static_cast<unsigned char>((high << 4) | low));
        }
    }

    return result;
}

std::vector<unsigned char> parse_pdf_literal_string(const std::string& data, size_t& pos) {
    std::vector<unsigned char> result;
    if (pos >= data.size() || data[pos] != '(') {
        return result;
    }
    ++pos;

    int depth = 1;
    while (pos < data.size() && depth > 0) {
        char ch = data[pos++];
        if (ch == '\\') {
            if (pos >= data.size()) {
                break;
            }
            char next = data[pos++];
            switch (next) {
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case '(': result.push_back('('); break;
                case ')': result.push_back(')'); break;
                case '\\': result.push_back('\\'); break;
                case '\r':
                    if (pos < data.size() && data[pos] == '\n') {
                        ++pos;
                    }
                    break;
                case '\n':
                    break;
                default:
                    if (next >= '0' && next <= '7') {
                        std::string digits(1, next);
                        for (int i = 0; i < 2 && pos < data.size(); ++i) {
                            char digit = data[pos];
                            if (digit >= '0' && digit <= '7') {
                                digits.push_back(digit);
                                ++pos;
                            } else {
                                break;
                            }
                        }
                        char value = static_cast<char>(std::stoi(digits, nullptr, 8));
                        result.push_back(static_cast<unsigned char>(value));
                    } else {
                        result.push_back(static_cast<unsigned char>(next));
                    }
                    break;
            }
        } else if (ch == '(') {
            result.push_back('(');
            ++depth;
        } else if (ch == ')') {
            --depth;
            if (depth > 0) {
                result.push_back(')');
            }
        } else {
            result.push_back(static_cast<unsigned char>(ch));
        }
    }

    return result;
}

std::vector<unsigned char> parse_pdf_string_object(const std::string& data, size_t& pos) {
    if (pos >= data.size()) {
        return {};
    }

    if (data[pos] == '<') {
        if (pos + 1 < data.size() && data[pos + 1] == '<') {
            return {};
        }
        return parse_pdf_hex_string(data, pos);
    }

    if (data[pos] == '(') {
        return parse_pdf_literal_string(data, pos);
    }

    while (pos < data.size() && !std::isspace(static_cast<unsigned char>(data[pos])) && data[pos] != '/') {
        ++pos;
    }
    return {};
}

size_t find_dictionary_end(const std::string& data, size_t start) {
    int depth = 0;
    size_t pos = start;
    while (pos + 1 < data.size()) {
        if (data[pos] == '<' && data[pos + 1] == '<') {
            depth++;
            pos += 2;
            continue;
        }
        if (data[pos] == '>' && data[pos + 1] == '>') {
            depth--;
            pos += 2;
            if (depth == 0) {
                return pos;
            }
            continue;
        }
        if (data[pos] == '(') {
            ++pos;
            int level = 1;
            while (pos < data.size() && level > 0) {
                char ch = data[pos++];
                if (ch == '\\') {
                    if (pos < data.size()) {
                        ++pos;
                    }
                } else if (ch == '(') {
                    ++level;
                } else if (ch == ')') {
                    --level;
                }
            }
            continue;
        }
        if (data[pos] == '<') {
            ++pos;
            while (pos < data.size() && data[pos] != '>') {
                ++pos;
            }
            if (pos < data.size()) {
                ++pos;
            }
            continue;
        }
        ++pos;
    }
    return std::string::npos;
}

std::vector<unsigned char> extract_document_id(const std::string& data) {
    size_t pos = data.find("/ID");
    if (pos == std::string::npos) {
        return {};
    }
    pos += 3;
    skip_whitespace_and_comments(data, pos);
    if (pos >= data.size() || data[pos] != '[') {
        return {};
    }
    ++pos;
    skip_whitespace_and_comments(data, pos);
    if (pos >= data.size()) {
        return {};
    }
    return parse_pdf_string_object(data, pos);
}

bool extract_encryption_info(const std::string& data, PDFEncryptInfo& info) {
    size_t encrypt_pos = data.find("/Encrypt");
    if (encrypt_pos == std::string::npos) {
        std::cout << "No /Encrypt dictionary found" << std::endl;
        return false;
    }

    size_t pos = encrypt_pos + 8;
    skip_whitespace_and_comments(data, pos);
    if (pos >= data.size() || !std::isdigit(static_cast<unsigned char>(data[pos]))) {
        std::cout << "Failed to parse /Encrypt reference" << std::endl;
        return false;
    }

    int obj_num = parse_pdf_int(data, pos);
    skip_whitespace_and_comments(data, pos);
    int gen_num = 0;
    if (pos < data.size() && std::isdigit(static_cast<unsigned char>(data[pos]))) {
        gen_num = parse_pdf_int(data, pos);
    }

    std::cout << "Found /Encrypt reference to object " << obj_num << " " << gen_num << std::endl;

    std::string obj_marker = std::to_string(obj_num) + " " + std::to_string(gen_num) + " obj";
    size_t obj_pos = data.find(obj_marker);
    if (obj_pos == std::string::npos) {
        std::cout << "Could not locate encryption object" << std::endl;
        return false;
    }

    size_t dict_start = data.find("<<", obj_pos);
    if (dict_start == std::string::npos) {
        std::cout << "Encryption object does not contain a dictionary" << std::endl;
        return false;
    }
    size_t dict_end = find_dictionary_end(data, dict_start);
    if (dict_end == std::string::npos) {
        std::cout << "Failed to parse encryption dictionary" << std::endl;
        return false;
    }

    std::cout << "Found encryption object. Content:" << std::endl;
    std::string snippet = data.substr(dict_start, std::min<size_t>(dict_end - dict_start, 200));
    for (char& ch : snippet) {
        if (ch == '\r' || ch == '\n') {
            ch = ' ';
        }
    }
    std::cout << snippet << std::endl;

    pos = dict_start + 2;
    while (pos < dict_end) {
        skip_whitespace_and_comments(data, pos);
        if (pos >= dict_end) {
            break;
        }
        if (data[pos] != '/') {
            ++pos;
            continue;
        }
        ++pos;
        std::string key = parse_pdf_name(data, pos);
        skip_whitespace_and_comments(data, pos);

        if (key == "V") {
            info.version = parse_pdf_int(data, pos);
        } else if (key == "R") {
            info.revision = parse_pdf_int(data, pos);
        } else if (key == "Length") {
            info.length = parse_pdf_int(data, pos);
        } else if (key == "U") {
            info.u_string = parse_pdf_string_object(data, pos);
        } else if (key == "O") {
            info.o_string = parse_pdf_string_object(data, pos);
        } else if (key == "UE") {
            info.ue_string = parse_pdf_string_object(data, pos);
        } else if (key == "OE") {
            info.oe_string = parse_pdf_string_object(data, pos);
        } else if (key == "Perms") {
            info.perms = parse_pdf_string_object(data, pos);
        } else {
            if (pos >= dict_end) {
                break;
            }
            char token = data[pos];
            if (token == '<' && pos + 1 < data.size() && data[pos + 1] == '<') {
                size_t nested_end = find_dictionary_end(data, pos);
                if (nested_end == std::string::npos) {
                    break;
                }
                pos = nested_end;
            } else if (token == '<') {
                parse_pdf_hex_string(data, pos);
            } else if (token == '(') {
                parse_pdf_literal_string(data, pos);
            } else if (token == '[') {
                ++pos;
                int depth = 1;
                while (pos < dict_end && depth > 0) {
                    if (data[pos] == '[') {
                        ++depth;
                        ++pos;
                    } else if (data[pos] == ']') {
                        --depth;
                        ++pos;
                    } else if (data[pos] == '(') {
                        parse_pdf_literal_string(data, pos);
                    } else if (data[pos] == '<' && pos + 1 < data.size() && data[pos + 1] == '<') {
                        size_t nested = find_dictionary_end(data, pos);
                        if (nested == std::string::npos) {
                            pos = dict_end;
                        } else {
                            pos = nested;
                        }
                    } else if (data[pos] == '<') {
                        parse_pdf_hex_string(data, pos);
                    } else {
                        ++pos;
                    }
                }
            } else {
                while (pos < dict_end && !std::isspace(static_cast<unsigned char>(data[pos])) && data[pos] != '/') {
                    ++pos;
                }
            }
        }
    }

    if (info.revision >= 5 && info.length == 0) {
        info.length = 256;
    }

    info.encrypted = true;
    return true;
}

void print_pdf_structure(const std::string& data) {
    std::cout << "\nAnalyzing PDF structure:" << std::endl;
    std::cout << "------------------------" << std::endl;

    const char* keywords[] = {
        "/Encrypt", "obj", "endobj", "/Filter", "/V ", "/R ", "/O", "/U",
        "/Length", "/CF", "/StmF", "/StrF", "/AESV3"
    };

    for (const char* keyword : keywords) {
        size_t pos = 0;
        int count = 0;
        while ((pos = data.find(keyword, pos)) != std::string::npos) {
            if (count < 3) {
                size_t context_end = std::min(pos + static_cast<size_t>(50), data.size());
                std::string context = data.substr(pos, context_end - pos);
                for (char& ch : context) {
                    if (ch == '\r' || ch == '\n') {
                        ch = ' ';
                    }
                }
                std::cout << "Found '" << keyword << "' at offset " << pos << ": " << context << std::endl;
            }
            ++count;
            ++pos;
        }
        if (count > 0) {
            std::cout << "Total occurrences of '" << keyword << "': " << count << std::endl;
        }
    }

    std::cout << "------------------------\n" << std::endl;
}

bool read_pdf_encrypt_info(const std::string& filename, PDFEncryptInfo& info) {
    std::cout << "Opening PDF file: " << filename << std::endl;
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open PDF file" << std::endl;
        return false;
    }

    std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (data.size() < 5 || data.compare(0, 5, "%PDF-") != 0) {
        std::cerr << "Error: Not a valid PDF file" << std::endl;
        return false;
    }

    std::cout << "PDF file opened successfully" << std::endl;
    std::cout << "Checking PDF header..." << std::endl;
    std::cout << "Valid PDF header found" << std::endl;

    print_pdf_structure(data);

    if (!extract_encryption_info(data, info)) {
        std::cerr << "Error: Could not find encryption information" << std::endl;
        return false;
    }

    info.id = extract_document_id(data);

    std::cout << "PDF encryption detected:" << std::endl;
    std::cout << "  Version: " << info.version << std::endl;
    std::cout << "  Revision: " << info.revision << std::endl;
    if (info.length > 0) {
        std::cout << "  Key Length: " << info.length << " bits" << std::endl;
    }
    if (info.revision >= 5) {
        std::cout << "  Encryption: AES-256" << std::endl;
        std::cout << "  Method: AESV3" << std::endl;
    }

    return true;
}

bool try_user_password(const std::string& password, const PDFEncryptInfo& info, int revision) {
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
    ByteView doc_id(info.id.empty() ? nullptr : info.id.data(), info.id.size());

    std::vector<unsigned char> hash = compute_hash_v5(truncated, validation_salt, doc_id, revision);
    if (hash.size() < 32 || !std::equal(u_data, u_data + 32, hash.begin())) {
        return false;
    }

    std::vector<unsigned char> key = compute_hash_v5(truncated, key_salt, doc_id, revision);
    if (key.size() < 32) {
        return false;
    }

    std::vector<unsigned char> iv(16, 0);
    std::vector<unsigned char> file_key;
    return aes256_cbc_decrypt(key, iv, info.ue_string, file_key, false) && file_key.size() >= 32;
}

bool try_owner_password(const std::string& password, const PDFEncryptInfo& info, int revision) {
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
    ByteView user_entry(info.u_string.empty() ? nullptr : info.u_string.data(), info.u_string.size());

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

void try_passwords(const std::vector<std::string>& passwords,
                   size_t start,
                   size_t end,
                   const PDFEncryptInfo& info) {
    for (size_t i = start; i < end && !g_password_found.load(); ++i) {
        std::string variant;
        if (check_password_variants(passwords[i], info, variant)) {
            std::lock_guard<std::mutex> lock(g_mutex);
            if (!g_password_found) {
                g_password_found = true;
                g_found_password = passwords[i];
                g_found_variant = variant;
                std::cout << "\nPASSWORD FOUND [" << variant << "]: " << passwords[i] << std::endl;
            }
            return;
        }

        size_t tried = ++g_passwords_tried;
        if (tried % 100 == 0) {
            print_progress();
        }
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <password_list> <pdf_file>" << std::endl;
        return 1;
    }

    std::cout << "Reading password list..." << std::endl;
    std::vector<std::string> passwords;
    {
        std::ifstream pass_file(argv[1], std::ios::binary);
        if (!pass_file) {
            std::cerr << "Error: Cannot open password list: " << argv[1] << std::endl;
            return 1;
        }

        std::vector<char> raw_data((std::istreambuf_iterator<char>(pass_file)), std::istreambuf_iterator<char>());

        std::string file_contents;
        if (raw_data.size() >= 2) {
            unsigned char b0 = static_cast<unsigned char>(raw_data[0]);
            unsigned char b1 = static_cast<unsigned char>(raw_data[1]);

            if (raw_data.size() >= 2 && b0 == 0xFF && b1 == 0xFE) {
                std::u16string utf16;
                utf16.reserve((raw_data.size() - 2) / 2);
                for (size_t i = 2; i + 1 < raw_data.size(); i += 2) {
                    char16_t code = static_cast<unsigned char>(raw_data[i]) |
                                    (static_cast<char16_t>(static_cast<unsigned char>(raw_data[i + 1])) << 8);
                    utf16.push_back(code);
                }
                std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
                file_contents = converter.to_bytes(utf16);
            } else if (raw_data.size() >= 2 && b0 == 0xFE && b1 == 0xFF) {
                std::u16string utf16;
                utf16.reserve((raw_data.size() - 2) / 2);
                for (size_t i = 2; i + 1 < raw_data.size(); i += 2) {
                    char16_t code = (static_cast<char16_t>(static_cast<unsigned char>(raw_data[i])) << 8) |
                                    static_cast<unsigned char>(raw_data[i + 1]);
                    utf16.push_back(code);
                }
                std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
                file_contents = converter.to_bytes(utf16);
            } else {
                file_contents.assign(raw_data.begin(), raw_data.end());
            }
        } else {
            file_contents.assign(raw_data.begin(), raw_data.end());
        }

        std::istringstream pass_stream(file_contents);
        std::string line;
        bool first_line = true;
        bool first_line = true;
        while (std::getline(pass_stream, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (first_line) {
                first_line = false;
                if (line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
                    static_cast<unsigned char>(line[1]) == 0xBB &&
                    static_cast<unsigned char>(line[2]) == 0xBF) {
                    line.erase(0, 3);
                }
            }

            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
                line.pop_back();
            }

            if (first_line) {
                first_line = false;
                if (line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
                    static_cast<unsigned char>(line[1]) == 0xBB &&
                    static_cast<unsigned char>(line[2]) == 0xBF) {
                    line.erase(0, 3);
                }
            }

            if (!line.empty()) {
                passwords.push_back(line);
            }
        }
    }

    if (passwords.empty()) {
        std::cerr << "Error: No passwords loaded" << std::endl;
        return 1;
    }

    std::cout << "Loaded " << passwords.size() << " passwords" << std::endl;

    PDFEncryptInfo encrypt_info;
    if (!read_pdf_encrypt_info(argv[2], encrypt_info)) {
        return 1;
    }

    if (encrypt_info.revision < 5) {
        std::cerr << "Error: This version only supports AES-256 (R5/R6) encryption" << std::endl;
        std::cerr << "The PDF file uses revision " << encrypt_info.revision << std::endl;
        return 1;
    }

    if (encrypt_info.revision >= 6) {
        std::cout << "Detected revision " << encrypt_info.revision
                  << " encryption - will test both R" << encrypt_info.revision
                  << " and R5 derivations" << std::endl;
    } else {
        std::cout << "Detected revision 5 encryption - using R5 derivation" << std::endl;
    }

    unsigned int thread_count = std::thread::hardware_concurrency();
    if (thread_count == 0) {
        thread_count = 2;
    }
    if (thread_count > 16) {
        thread_count = 16;
    }

    std::cout << "\nStarting password cracking with " << thread_count << " threads" << std::endl;

    g_total_passwords = passwords.size();
    auto start_time = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    size_t passwords_per_thread = passwords.size() / thread_count;
    size_t remainder = passwords.size() % thread_count;
    size_t current_start = 0;

    for (unsigned int i = 0; i < thread_count; ++i) {
        size_t count = passwords_per_thread + (i < remainder ? 1 : 0);
        size_t current_end = current_start + count;
        threads.emplace_back(try_passwords, std::cref(passwords), current_start, current_end, std::cref(encrypt_info));
        current_start = current_end;
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    std::cout << "\n\nFinished in " << duration.count() << " seconds" << std::endl;

    if (g_password_found) {
        if (!g_found_variant.empty()) {
            std::cout << "Password found [" << g_found_variant << "]: " << g_found_password << std::endl;
        } else {
            std::cout << "Password found: " << g_found_password << std::endl;
        }
        return 0;
    }

    std::cout << "Password not found in the provided list" << std::endl;
    return 1;
}

