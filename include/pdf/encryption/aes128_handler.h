#ifndef UNLOCK_PDF_AES128_HANDLER_H
#define UNLOCK_PDF_AES128_HANDLER_H

#include "pdf/encryption/encryption_handler.h"

namespace unlock_pdf::pdf {

class AES128Handler : public EncryptionHandler {
public:
    std::string name() const override { return "AES-128 (Revision 4)"; }
    bool can_handle(const PDFEncryptInfo& info) const override;
    bool check_password(const std::string& password,
                        const PDFEncryptInfo& info,
                        std::string& matched_variant) const override;
};

}  // namespace unlock_pdf::pdf

#endif  // UNLOCK_PDF_AES128_HANDLER_H
