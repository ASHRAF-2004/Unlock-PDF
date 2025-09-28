#ifndef UNLOCK_PDF_ENCRYPTION_HANDLER_REGISTRY_H
#define UNLOCK_PDF_ENCRYPTION_HANDLER_REGISTRY_H

#include <vector>

#include "pdf/encryption/encryption_handler.h"

namespace unlock_pdf::pdf {

std::vector<EncryptionHandlerPtr> create_default_encryption_handlers();

}  // namespace unlock_pdf::pdf

#endif  // UNLOCK_PDF_ENCRYPTION_HANDLER_REGISTRY_H
