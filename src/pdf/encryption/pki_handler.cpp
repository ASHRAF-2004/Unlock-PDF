#include "pdf/encryption/pki_handler.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace unlock_pdf::pdf {

namespace {

bool has_pki_subfilter(const std::string& sub_filter) {
    if (sub_filter.empty()) {
        return false;
    }
    std::string lower = sub_filter;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lower.find("pkcs7") != std::string::npos || lower.find("pubsec") != std::string::npos ||
           lower.find("x509") != std::string::npos;
}

}  // namespace

bool PKIEncryptionHandler::can_handle(const PDFEncryptInfo& info) const {
    if (!info.encrypted) {
        return false;
    }
    if (info.filter == "Adobe.PubSec" || info.has_recipients) {
        return true;
    }
    return has_pki_subfilter(info.sub_filter);
}

bool PKIEncryptionHandler::check_password(const std::string& /*password*/,
                                          const PDFEncryptInfo& /*info*/,
                                          std::string& /*matched_variant*/) const {
    return false;
}

bool PKIEncryptionHandler::handle_without_password(const PDFEncryptInfo& /*info*/,
                                                   bool& success,
                                                   std::string& matched_variant,
                                                   std::string& discovered_password) const {
    success = false;
    matched_variant = "PKI-based Encryption";
    discovered_password.clear();
    return true;
}

bool PKIEncryptionHandler::requires_password() const {
    return false;
}

}  // namespace unlock_pdf::pdf
