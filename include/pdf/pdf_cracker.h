#ifndef UNLOCK_PDF_PDF_CRACKER_H
#define UNLOCK_PDF_PDF_CRACKER_H

#include <cstddef>
#include <string>
#include <vector>

#include "pdf/pdf_types.h"
#include "util/wordlist_generator.h"

namespace unlock_pdf::pdf {

struct CrackResult {
    bool success = false;
    std::string password;
    std::string variant;
    std::size_t passwords_tried = 0;
    std::size_t total_passwords = 0;
};

bool crack_pdf(const std::vector<std::string>& passwords,
               const std::string& pdf_path,
               CrackResult& result,
               unsigned int thread_count = 0);

bool crack_pdf_bruteforce(const unlock_pdf::util::WordlistOptions& options,
                          const std::string& pdf_path,
                          CrackResult& result,
                          unsigned int thread_count = 0);

}  // namespace unlock_pdf::pdf

#endif  // UNLOCK_PDF_PDF_CRACKER_H
