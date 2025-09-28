#ifndef UNLOCK_PDF_STANDARD_R3_HANDLER_H
#define UNLOCK_PDF_STANDARD_R3_HANDLER_H

#include "pdf/encryption/encryption_handler.h"

namespace unlock_pdf::pdf {

class StandardRevision3Handler : public EncryptionHandler {
public:
    std::string name() const override { return "Standard Encryption (Revision 3)"; }
    bool can_handle(const PDFEncryptInfo& info) const override;
    bool check_password(const std::string& password,
                        const PDFEncryptInfo& info,
                        std::string& matched_variant) const override;
};

}  // namespace unlock_pdf::pdf

#endif  // UNLOCK_PDF_STANDARD_R3_HANDLER_H
