#include "pdf/encryption/x509_handler.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace unlock_pdf::pdf {

namespace {

bool has_x509_marker(const PDFEncryptInfo& info) {
    auto to_lower = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    };

    if (!info.sub_filter.empty()) {
        std::string lower = to_lower(info.sub_filter);
        if (lower.find("x509") != std::string::npos) {
            return true;
        }
    }
    if (!info.filter.empty()) {
        std::string lower = to_lower(info.filter);
        if (lower.find("x509") != std::string::npos) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool X509SignatureHandler::can_handle(const PDFEncryptInfo& info) const {
    if (!info.encrypted) {
        return false;
    }
    return has_x509_marker(info);
}

bool X509SignatureHandler::check_password(const std::string& /*password*/,
                                          const PDFEncryptInfo& /*info*/,
                                          std::string& /*matched_variant*/) const {
    return false;
}

bool X509SignatureHandler::requires_password() const {
    return false;
}

bool X509SignatureHandler::handle_without_password(const PDFEncryptInfo& /*info*/,
                                                   bool& success,
                                                   std::string& matched_variant,
                                                   std::string& discovered_password) const {
    success = false;
    matched_variant = "X.509 Digital Signatures";
    discovered_password.clear();
    return true;
}

}  // namespace unlock_pdf::pdf
