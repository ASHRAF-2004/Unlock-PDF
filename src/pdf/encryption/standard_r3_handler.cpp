#include "pdf/encryption/standard_r3_handler.h"

#include "pdf/encryption/standard_security_utils.h"

namespace unlock_pdf::pdf {

bool StandardRevision3Handler::can_handle(const PDFEncryptInfo& info) const {
    if (!info.encrypted) {
        return false;
    }
    if (info.filter != "Standard" && !info.filter.empty()) {
        return false;
    }
    if (info.revision != 3) {
        return false;
    }
    if (!info.string_filter.empty() && info.string_filter == "V2") {
        return false;
    }
    return true;
}

bool StandardRevision3Handler::check_password(const std::string& password,
                                              const PDFEncryptInfo& info,
                                              std::string& matched_variant) const {
    int key_length_bits = info.length > 0 ? info.length : 128;
    if (standard_security::check_user_password(password, info, 3, key_length_bits)) {
        matched_variant = "Standard Encryption (Revision 3) Password-Based Encryption";
        return true;
    }
    if (standard_security::check_owner_password(password, info, 3, key_length_bits)) {
        matched_variant = "Standard Encryption (Revision 3) Owner Password";
        return true;
    }
    return false;
}

}  // namespace unlock_pdf::pdf
