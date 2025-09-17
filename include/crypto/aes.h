#ifndef UNLOCK_PDF_CRYPTO_AES_H
#define UNLOCK_PDF_CRYPTO_AES_H

#include <array>
#include <vector>

namespace unlock_pdf::crypto {

class AES128Encryptor {
public:
    explicit AES128Encryptor(const std::vector<unsigned char>& key);
    bool valid() const;
    void encrypt_block(const unsigned char* input, unsigned char* output) const;

private:
    std::array<std::array<unsigned char, 16>, 11> round_keys_{};
    bool valid_ = false;
};

class AES256Decryptor {
public:
    explicit AES256Decryptor(const std::vector<unsigned char>& key);
    bool valid() const;
    void decrypt_block(const unsigned char* input, unsigned char* output) const;

private:
    std::array<std::array<unsigned char, 16>, 15> decrypt_round_keys_{};
    bool valid_ = false;
};

bool aes128_cbc_encrypt(const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        const std::vector<unsigned char>& plaintext,
                        std::vector<unsigned char>& ciphertext);

bool aes256_cbc_decrypt(const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        const std::vector<unsigned char>& ciphertext,
                        std::vector<unsigned char>& plaintext,
                        bool strip_padding = true);

}  // namespace unlock_pdf::crypto

#endif  // UNLOCK_PDF_CRYPTO_AES_H