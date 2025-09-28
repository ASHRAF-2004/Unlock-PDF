#include "pdf/encryption/rc4_128_handler.h"

#include "pdf/encryption/standard_security_utils.h"

namespace unlock_pdf::pdf {

bool RC4128Handler::can_handle(const PDFEncryptInfo& info) const {
    if (!info.encrypted) {
        return false;
    }
    if (info.filter != "Standard" && !info.filter.empty()) {
        return false;
    }
    if (info.revision != 3) {
        return false;
    }
    if (!info.string_filter.empty() && info.string_filter != "V2") {
        return false;
    }
    int key_length_bits = info.length > 0 ? info.length : 128;
    return key_length_bits >= 40;
}

bool RC4128Handler::check_password(const std::string& password,
                                   const PDFEncryptInfo& info,
                                   std::string& matched_variant) const {
    int key_length_bits = info.length > 0 ? info.length : 128;
    if (standard_security::check_user_password(password, info, 3, key_length_bits)) {
        matched_variant = "RC4 (128-bit) Password-Based Encryption";
        return true;
    }
    if (standard_security::check_owner_password(password, info, 3, key_length_bits)) {
        matched_variant = "RC4 (128-bit) Owner Password";
        return true;
    }
    return false;
}

}  // namespace unlock_pdf::pdf
