#ifndef UNLOCK_PDF_UTIL_SYSTEM_INFO_H
#define UNLOCK_PDF_UTIL_SYSTEM_INFO_H

#include <cstdint>
#include <string>

namespace unlock_pdf::util {

struct SystemInfo {
    std::string os_name;
    std::string kernel_version;
    std::string architecture;
    std::string cpu_model;
    std::string hostname;
    unsigned int cpu_threads = 0;
    std::uint64_t total_memory_bytes = 0;
    std::uint64_t available_memory_bytes = 0;
};

SystemInfo collect_system_info();
std::string human_readable_bytes(std::uint64_t bytes);

}  // namespace unlock_pdf::util

#endif  // UNLOCK_PDF_UTIL_SYSTEM_INFO_H
