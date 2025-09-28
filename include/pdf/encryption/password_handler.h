#ifndef UNLOCK_PDF_PASSWORD_HANDLER_H
#define UNLOCK_PDF_PASSWORD_HANDLER_H

#include "pdf/encryption/encryption_handler.h"

namespace unlock_pdf::pdf {

class PasswordBasedEncryptionHandler : public EncryptionHandler {
public:
    std::string name() const override { return "Password-Based Encryption"; }
    bool can_handle(const PDFEncryptInfo& info) const override;
    bool check_password(const std::string& password,
                        const PDFEncryptInfo& info,
                        std::string& matched_variant) const override;
};

}  // namespace unlock_pdf::pdf

#endif  // UNLOCK_PDF_PASSWORD_HANDLER_H
