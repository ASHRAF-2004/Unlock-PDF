#include "crypto/md5.h"

#include <array>
#include <cstdint>

namespace unlock_pdf::crypto {
namespace {

class MD5 {
public:
    MD5() { reset(); }

    void reset() {
        state_[0] = 0x67452301u;
        state_[1] = 0xefcdab89u;
        state_[2] = 0x98badcfeu;
        state_[3] = 0x10325476u;
        bitlen_ = 0;
        buffer_len_ = 0;
        buffer_.fill(0);
    }

    void update(const unsigned char* data, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            bitlen_ += 8;
            if (buffer_len_ == 64) {
                transform(buffer_.data());
                buffer_len_ = 0;
            }
        }
    }

    void finalize(unsigned char* hash) {
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

        for (int i = 0; i < 8; ++i) {
            buffer_[buffer_len_++] = static_cast<unsigned char>((bitlen_ >> (i * 8)) & 0xff);
        }

        transform(buffer_.data());

        for (int i = 0; i < 4; ++i) {
            hash[i * 4 + 0] = static_cast<unsigned char>(state_[i] & 0xff);
            hash[i * 4 + 1] = static_cast<unsigned char>((state_[i] >> 8) & 0xff);
            hash[i * 4 + 2] = static_cast<unsigned char>((state_[i] >> 16) & 0xff);
            hash[i * 4 + 3] = static_cast<unsigned char>((state_[i] >> 24) & 0xff);
        }
    }

private:
    static uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
    static uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
    static uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
    static uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

    static uint32_t rotate_left(uint32_t value, uint32_t bits) { return (value << bits) | (value >> (32 - bits)); }

    void transform(const unsigned char* chunk) {
        uint32_t a = state_[0];
        uint32_t b = state_[1];
        uint32_t c = state_[2];
        uint32_t d = state_[3];

        uint32_t x[16];
        for (int i = 0; i < 16; ++i) {
            x[i] = (static_cast<uint32_t>(chunk[i * 4 + 0]) << 0) |
                   (static_cast<uint32_t>(chunk[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(chunk[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(chunk[i * 4 + 3]) << 24);
        }

        static const uint32_t s[] = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

        static const uint32_t K[] = {
            0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
            0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
            0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
            0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
            0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
            0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
            0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
            0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};

        for (int i = 0; i < 64; ++i) {
            uint32_t f = 0;
            uint32_t g = 0;

            if (i < 16) {
                f = F(b, c, d);
                g = i;
            } else if (i < 32) {
                f = G(b, c, d);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = H(b, c, d);
                g = (3 * i + 5) % 16;
            } else {
                f = I(b, c, d);
                g = (7 * i) % 16;
            }

            uint32_t temp = d;
            d = c;
            c = b;
            uint32_t sum = a + f + K[i] + x[g];
            b += rotate_left(sum, s[i]);
            a = temp;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
    }

    std::array<uint32_t, 4> state_{};
    uint64_t bitlen_ = 0;
    std::array<unsigned char, 64> buffer_{};
    std::size_t buffer_len_ = 0;
};

}  // namespace

std::vector<unsigned char> md5_bytes(const std::vector<unsigned char>& data) {
    MD5 ctx;
    if (!data.empty()) {
        ctx.update(data.data(), data.size());
    }
    std::vector<unsigned char> hash(16);
    ctx.finalize(hash.data());
    return hash;
}

}  // namespace unlock_pdf::crypto