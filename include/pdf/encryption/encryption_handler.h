#ifndef UNLOCK_PDF_ENCRYPTION_HANDLER_H
#define UNLOCK_PDF_ENCRYPTION_HANDLER_H

#include <memory>
#include <string>

#include "pdf/pdf_types.h"

namespace unlock_pdf::pdf {

class EncryptionHandler {
public:
    virtual ~EncryptionHandler() = default;

    virtual std::string name() const = 0;

    virtual bool can_handle(const PDFEncryptInfo& info) const = 0;

    virtual bool check_password(const std::string& password,
                                const PDFEncryptInfo& info,
                                std::string& matched_variant) const = 0;

    virtual bool requires_password() const { return true; }

    virtual bool handle_without_password(const PDFEncryptInfo& /*info*/,
                                         bool& /*success*/,
                                         std::string& /*matched_variant*/,
                                         std::string& /*discovered_password*/) const {
        return false;
    }
};

using EncryptionHandlerPtr = std::shared_ptr<EncryptionHandler>;

}  // namespace unlock_pdf::pdf

#endif  // UNLOCK_PDF_ENCRYPTION_HANDLER_H
