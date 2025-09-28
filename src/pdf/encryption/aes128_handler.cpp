#include "pdf/encryption/aes128_handler.h"

#include "pdf/encryption/standard_security_utils.h"

namespace unlock_pdf::pdf {

bool AES128Handler::can_handle(const PDFEncryptInfo& info) const {
    if (!info.encrypted) {
        return false;
    }
    if (info.filter != "Standard" && !info.filter.empty()) {
        return false;
    }
    return info.revision == 4;
}

bool AES128Handler::check_password(const std::string& password,
                                   const PDFEncryptInfo& info,
                                   std::string& matched_variant) const {
    int key_length_bits = info.length > 0 ? info.length : 128;
    if (standard_security::check_user_password(password, info, 4, key_length_bits)) {
        matched_variant = "AES-128 (Revision 4) Password-Based Encryption";
        return true;
    }
    if (standard_security::check_owner_password(password, info, 4, key_length_bits)) {
        matched_variant = "AES-128 (Revision 4) Owner Password";
        return true;
    }
    return false;
}

}  // namespace unlock_pdf::pdf
