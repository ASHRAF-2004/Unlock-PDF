#ifndef UNLOCK_PDF_STANDARD_SECURITY_UTILS_H
#define UNLOCK_PDF_STANDARD_SECURITY_UTILS_H

#include <string>
#include <vector>

#include "pdf/pdf_types.h"

namespace unlock_pdf::pdf::standard_security {

std::vector<unsigned char> pad_password(const std::string& password);
std::string unpad_password(const std::vector<unsigned char>& padded);

std::vector<unsigned char> compute_encryption_key(const std::string& password,
                                                  const PDFEncryptInfo& info,
                                                  int revision,
                                                  int key_length_bits);

bool check_user_password(const std::string& password,
                         const PDFEncryptInfo& info,
                         int revision,
                         int key_length_bits);

bool check_owner_password(const std::string& password,
                          const PDFEncryptInfo& info,
                          int revision,
                          int key_length_bits);

}  // namespace unlock_pdf::pdf::standard_security

#endif  // UNLOCK_PDF_STANDARD_SECURITY_UTILS_H
