// Minimal, dependency-free SHA-256 implementation for C++ (public domain style)
// API: std::array<uint8_t,32> sha256(const void* data, size_t len);

#pragma once

#include <array>
#include <cstdint>
#include <cstddef>

namespace purecrypto {

struct Sha256State {
	uint32_t h[8];
	uint64_t bitlen; // total bits processed
	uint8_t buffer[64];
	size_t buffer_len;
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32U - n));
}

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (~x & z);
}

static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t Sigma0(uint32_t x) {
	return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

static inline uint32_t Sigma1(uint32_t x) {
	return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

static inline uint32_t sigma0(uint32_t x) {
	return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

static inline uint32_t sigma1(uint32_t x) {
	return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

static const uint32_t K[64] = {
	0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
	0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
	0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
	0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
	0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
	0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
	0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
	0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

inline void sha256_init(Sha256State &s) {
	s.h[0] = 0x6a09e667U; s.h[1] = 0xbb67ae85U; s.h[2] = 0x3c6ef372U; s.h[3] = 0xa54ff53aU;
	s.h[4] = 0x510e527fU; s.h[5] = 0x9b05688cU; s.h[6] = 0x1f83d9abU; s.h[7] = 0x5be0cd19U;
	s.bitlen = 0;
	s.buffer_len = 0;
}

inline void sha256_compress(Sha256State &s, const uint8_t block[64]) {
	uint32_t w[64];
	for (int i = 0; i < 16; ++i) {
		w[i] = (uint32_t(block[4*i]) << 24) | (uint32_t(block[4*i+1]) << 16) |
				(uint32_t(block[4*i+2]) << 8) | (uint32_t(block[4*i+3]));
	}
	for (int i = 16; i < 64; ++i) {
		w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
	}
	uint32_t a = s.h[0], b = s.h[1], c = s.h[2], d = s.h[3];
	uint32_t e = s.h[4], f = s.h[5], g = s.h[6], h = s.h[7];
	for (int i = 0; i < 64; ++i) {
		uint32_t t1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + w[i];
		uint32_t t2 = Sigma0(a) + Maj(a,b,c);
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d;
	s.h[4] += e; s.h[5] += f; s.h[6] += g; s.h[7] += h;
}

inline void sha256_update(Sha256State &s, const void* data, size_t len) {
	const uint8_t* p = static_cast<const uint8_t*>(data);
	while (len > 0) {
		size_t to_copy = 64 - s.buffer_len;
		if (to_copy > len) to_copy = len;
		for (size_t i = 0; i < to_copy; ++i) s.buffer[s.buffer_len + i] = p[i];
		s.buffer_len += to_copy;
		p += to_copy; len -= to_copy;
		if (s.buffer_len == 64) {
			sha256_compress(s, s.buffer);
			s.bitlen += 512;
			s.buffer_len = 0;
		}
	}
}

inline std::array<uint8_t,32> sha256_final(Sha256State &s) {
	uint64_t total_bits = s.bitlen + static_cast<uint64_t>(s.buffer_len) * 8ULL;
	// append 0x80
	s.buffer[s.buffer_len++] = 0x80U;
	// pad with zeros until 56 bytes
	if (s.buffer_len > 56) {
		while (s.buffer_len < 64) s.buffer[s.buffer_len++] = 0;
		sha256_compress(s, s.buffer);
		s.buffer_len = 0;
	}
	while (s.buffer_len < 56) s.buffer[s.buffer_len++] = 0;
	// append length big-endian
	for (int i = 7; i >= 0; --i) {
		s.buffer[s.buffer_len++] = static_cast<uint8_t>((total_bits >> (i*8)) & 0xFFU);
	}
	sha256_compress(s, s.buffer);
	std::array<uint8_t,32> out{};
	for (int i = 0; i < 8; ++i) {
		out[4*i+0] = static_cast<uint8_t>((s.h[i] >> 24) & 0xFFU);
		out[4*i+1] = static_cast<uint8_t>((s.h[i] >> 16) & 0xFFU);
		out[4*i+2] = static_cast<uint8_t>((s.h[i] >> 8) & 0xFFU);
		out[4*i+3] = static_cast<uint8_t>((s.h[i] >> 0) & 0xFFU);
	}
	return out;
}

inline std::array<uint8_t,32> sha256(const void* data, size_t len) {
	Sha256State s; sha256_init(s); sha256_update(s, data, len); return sha256_final(s);
}

} // namespace purecrypto


