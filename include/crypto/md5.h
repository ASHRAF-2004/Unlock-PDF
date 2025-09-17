#ifndef UNLOCK_PDF_CRYPTO_MD5_H
#define UNLOCK_PDF_CRYPTO_MD5_H

#include <cstddef>
#include <vector>

namespace unlock_pdf::crypto {

std::vector<unsigned char> md5_bytes(const std::vector<unsigned char>& data);

}  // namespace unlock_pdf::crypto

#endif  // UNLOCK_PDF_CRYPTO_MD5_H