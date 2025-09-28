#include "pdf/encryption/owner_password_handler.h"

#include <array>
#include <string>

#include "pdf/encryption/standard_security_utils.h"

namespace unlock_pdf::pdf {

bool OwnerPasswordHandler::can_handle(const PDFEncryptInfo& info) const {
    if (!info.encrypted) {
        return false;
    }
    if (!info.filter.empty() && info.filter != "Standard") {
        return false;
    }
    return info.revision >= 2 && info.revision <= 4;
}

bool OwnerPasswordHandler::check_password(const std::string& password,
                                          const PDFEncryptInfo& info,
                                          std::string& matched_variant) const {
    std::array<int, 3> revisions = {2, 3, 4};
    for (int revision : revisions) {
        if (info.revision != 0 && info.revision != revision) {
            continue;
        }
        int key_length_bits = info.length > 0 ? info.length : (revision == 2 ? 40 : 128);
        if (standard_security::check_owner_password(password, info, revision, key_length_bits)) {
            matched_variant = "Owner Password (Revision " + std::to_string(revision) + ")";
            return true;
        }
    }
    return false;
}

}  // namespace unlock_pdf::pdf
