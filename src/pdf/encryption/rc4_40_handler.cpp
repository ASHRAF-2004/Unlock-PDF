#include "pdf/encryption/rc4_40_handler.h"

#include "pdf/encryption/standard_security_utils.h"

namespace unlock_pdf::pdf {

bool RC440Handler::can_handle(const PDFEncryptInfo& info) const {
    if (!info.encrypted) {
        return false;
    }
    if (info.filter != "Standard" && !info.filter.empty()) {
        return false;
    }
    if (info.revision > 2) {
        return false;
    }
    return true;
}

bool RC440Handler::check_password(const std::string& password,
                                  const PDFEncryptInfo& info,
                                  std::string& matched_variant) const {
    int key_length_bits = info.length > 0 ? info.length : 40;
    if (standard_security::check_user_password(password, info, 2, key_length_bits)) {
        matched_variant = "RC4 (40-bit) Password-Based Encryption";
        return true;
    }
    if (standard_security::check_owner_password(password, info, 2, key_length_bits)) {
        matched_variant = "RC4 (40-bit) Owner Password";
        return true;
    }
    return false;
}

}  // namespace unlock_pdf::pdf
