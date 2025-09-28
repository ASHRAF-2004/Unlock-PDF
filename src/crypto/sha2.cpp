#include "crypto/sha2.h"

#include <algorithm>
#include <array>
#include <cstdint>

namespace unlock_pdf::crypto {
namespace {

inline uint32_t rotr(uint32_t value, uint32_t bits) {
    return (value >> bits) | (value << (32 - bits));
}

class SHA256 {
public:
    SHA256() { reset(); }

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
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

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
    std::size_t buffer_len_ = 0;
};

inline uint64_t rotr64(uint64_t value, uint32_t bits) {
    return (value >> bits) | (value << (64 - bits));
}

class SHA512 {
public:
    explicit SHA512(std::size_t digest_bits = 512) { set_digest_length(digest_bits); reset(); }

    void reset() {
        static const uint64_t sha512_init[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
        static const uint64_t sha384_init[8] = {
            0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};

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

    void update(const unsigned char* data, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i) {
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
    void set_digest_length(std::size_t bits) {
        digest_len_ = (bits == 384) ? 48 : 64;
    }

    void transform(const unsigned char* chunk) {
        static const uint64_t k[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
            0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

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

    void initialize_state() {
        state_.fill(0);
    }

    std::array<uint64_t, 8> state_{};
    std::array<unsigned char, 128> buffer_{};
    std::size_t buffer_len_ = 0;
    uint64_t bitlen_low_ = 0;
    uint64_t bitlen_high_ = 0;
    std::size_t digest_len_ = 64;
};

}  // namespace

std::vector<unsigned char> sha256_bytes(const std::vector<unsigned char>& data) {
    SHA256 ctx;
    if (!data.empty()) {
        ctx.update(data.data(), data.size());
    }
    std::vector<unsigned char> hash(32);
    ctx.finalize(hash.data());
    return hash;
}

void sha256_digest(const unsigned char* data, std::size_t len, unsigned char* out) {
    if (out == nullptr) {
        return;
    }
    SHA256 ctx;
    if (data != nullptr && len != 0) {
        ctx.update(data, len);
    }
    ctx.finalize(out);
}

std::vector<unsigned char> sha2_hash(const std::vector<unsigned char>& data, std::size_t bits) {
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

}  // namespace unlock_pdf::crypto