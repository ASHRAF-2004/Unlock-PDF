#ifndef UNLOCK_PDF_CRYPTO_SHA2_H
#define UNLOCK_PDF_CRYPTO_SHA2_H

#include <cstddef>
#include <vector>

namespace unlock_pdf::crypto {

std::vector<unsigned char> sha256_bytes(const std::vector<unsigned char>& data);
std::vector<unsigned char> sha2_hash(const std::vector<unsigned char>& data, std::size_t bits);

}  // namespace unlock_pdf::crypto

#endif  // UNLOCK_PDF_CRYPTO_SHA2_H