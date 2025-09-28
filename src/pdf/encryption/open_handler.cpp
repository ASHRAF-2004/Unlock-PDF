#include "pdf/encryption/open_handler.h"

namespace unlock_pdf::pdf {

bool OpenProtectionHandler::can_handle(const PDFEncryptInfo& info) const {
    return !info.encrypted;
}

bool OpenProtectionHandler::check_password(const std::string& /*password*/,
                                           const PDFEncryptInfo& /*info*/,
                                           std::string& /*matched_variant*/) const {
    return false;
}

bool OpenProtectionHandler::requires_password() const {
    return false;
}

bool OpenProtectionHandler::handle_without_password(const PDFEncryptInfo& /*info*/,
                                                    bool& success,
                                                    std::string& matched_variant,
                                                    std::string& discovered_password) const {
    success = true;
    matched_variant = "Open Password Protection (No encryption)";
    discovered_password.clear();
    return true;
}

}  // namespace unlock_pdf::pdf
