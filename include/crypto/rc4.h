#ifndef UNLOCK_PDF_CRYPTO_RC4_H
#define UNLOCK_PDF_CRYPTO_RC4_H

#include <cstddef>
#include <vector>

namespace unlock_pdf::crypto {

class RC4 {
public:
    RC4();
    explicit RC4(const std::vector<unsigned char>& key);

    void set_key(const std::vector<unsigned char>& key);
    void crypt(const unsigned char* input, unsigned char* output, std::size_t length);

private:
    void initialize_state();

    std::vector<unsigned char> state_;
    std::size_t x_ = 0;
    std::size_t y_ = 0;
};

}  // namespace unlock_pdf::crypto

#endif  // UNLOCK_PDF_CRYPTO_RC4_H