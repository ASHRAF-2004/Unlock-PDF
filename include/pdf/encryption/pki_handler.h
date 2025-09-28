#ifndef UNLOCK_PDF_PKI_HANDLER_H
#define UNLOCK_PDF_PKI_HANDLER_H

#include "pdf/encryption/encryption_handler.h"

namespace unlock_pdf::pdf {

class PKIEncryptionHandler : public EncryptionHandler {
public:
    std::string name() const override { return "PKI-based Encryption"; }
    bool can_handle(const PDFEncryptInfo& info) const override;
    bool check_password(const std::string& password,
                        const PDFEncryptInfo& info,
                        std::string& matched_variant) const override;
    bool requires_password() const override;
    bool handle_without_password(const PDFEncryptInfo& info,
                                 bool& success,
                                 std::string& matched_variant,
                                 std::string& discovered_password) const override;
};

}  // namespace unlock_pdf::pdf

#endif  // UNLOCK_PDF_PKI_HANDLER_H
