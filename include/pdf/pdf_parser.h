#ifndef UNLOCK_PDF_PDF_PARSER_H
#define UNLOCK_PDF_PDF_PARSER_H

#include <string>

#include "pdf/pdf_types.h"

namespace unlock_pdf::pdf {

bool read_pdf_encrypt_info(const std::string& filename, PDFEncryptInfo& info);

}  // namespace unlock_pdf::pdf

#endif  // UNLOCK_PDF_PDF_PARSER_H