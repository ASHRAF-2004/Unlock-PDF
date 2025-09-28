#include "pdf/encryption/encryption_handler_registry.h"

#include <memory>

#include "pdf/encryption/aes128_handler.h"
#include "pdf/encryption/aes256_handler.h"
#include "pdf/encryption/open_handler.h"
#include "pdf/encryption/owner_password_handler.h"
#include "pdf/encryption/password_handler.h"
#include "pdf/encryption/pki_handler.h"
#include "pdf/encryption/rc4_128_handler.h"
#include "pdf/encryption/rc4_40_handler.h"
#include "pdf/encryption/standard_r3_handler.h"
#include "pdf/encryption/x509_handler.h"

namespace unlock_pdf::pdf {

std::vector<EncryptionHandlerPtr> create_default_encryption_handlers() {
    std::vector<EncryptionHandlerPtr> handlers;
    handlers.reserve(10);

    handlers.emplace_back(std::make_shared<OpenProtectionHandler>());
    handlers.emplace_back(std::make_shared<PKIEncryptionHandler>());
    handlers.emplace_back(std::make_shared<X509SignatureHandler>());
    handlers.emplace_back(std::make_shared<AES256Handler>());
    handlers.emplace_back(std::make_shared<AES128Handler>());
    handlers.emplace_back(std::make_shared<StandardRevision3Handler>());
    handlers.emplace_back(std::make_shared<RC4128Handler>());
    handlers.emplace_back(std::make_shared<RC440Handler>());
    handlers.emplace_back(std::make_shared<PasswordBasedEncryptionHandler>());
    handlers.emplace_back(std::make_shared<OwnerPasswordHandler>());

    return handlers;
}

}  // namespace unlock_pdf::pdf
