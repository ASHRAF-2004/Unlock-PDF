#include "util/system_info.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#include <winreg.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#else
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace unlock_pdf::util {
namespace {

std::string detect_cpu_model() {
#if defined(_WIN32)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD buffer_size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &buffer_size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(buffer, buffer_size - 1);
        }
        RegCloseKey(hKey);
    }
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    std::ostringstream oss;
    oss << "Family " << sysinfo.wProcessorLevel << " Model " << sysinfo.wProcessorRevision;
    return oss.str();
#elif defined(__APPLE__)
    char buffer[256];
    size_t buffer_len = sizeof(buffer);
    if (sysctlbyname("machdep.cpu.brand_string", &buffer, &buffer_len, nullptr, 0) == 0) {
        return std::string(buffer, buffer_len - 1);
    }
    return "Unknown";
#else
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        std::string key = "model name";
        if (line.compare(0, key.size(), key) == 0) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                std::string value = line.substr(pos + 1);
                value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) { return !std::isspace(ch); }));
                return value;
            }
        }
    }
    return "Unknown";
#endif
}

std::uint64_t detect_total_memory() {
#if defined(_WIN32)
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        return status.ullTotalPhys;
    }
    return 0;
#elif defined(__APPLE__)
    int64_t value = 0;
    size_t size = sizeof(value);
    if (sysctlbyname("hw.memsize", &value, &size, nullptr, 0) == 0) {
        return static_cast<std::uint64_t>(value);
    }
    return 0;
#else
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        return static_cast<std::uint64_t>(info.totalram) * info.mem_unit;
    }
    return 0;
#endif
}

std::uint64_t detect_available_memory() {
#if defined(_WIN32)
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        return status.ullAvailPhys;
    }
    return 0;
#elif defined(__APPLE__)
    vm_size_t page_size;
    mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
    vm_statistics64_data_t vm_stats;
    if (host_page_size(mach_host_self(), &page_size) == KERN_SUCCESS &&
        host_statistics64(mach_host_self(), HOST_VM_INFO, reinterpret_cast<host_info64_t>(&vm_stats), &count) == KERN_SUCCESS) {
        return static_cast<std::uint64_t>(vm_stats.free_count + vm_stats.inactive_count) * page_size;
    }
    return 0;
#else
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        return static_cast<std::uint64_t>(info.freeram) * info.mem_unit;
    }
    return 0;
#endif
}

std::string detect_os_name() {
#if defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#else
    struct utsname uts {};
    if (uname(&uts) == 0) {
        return uts.sysname;
    }
    return "Unknown";
#endif
}

std::string detect_kernel_version() {
#if defined(_WIN32)
    OSVERSIONINFOEXA osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
#pragma warning(push)
#pragma warning(disable : 4996)
    if (GetVersionExA(reinterpret_cast<OSVERSIONINFOA*>(&osvi))) {
#pragma warning(pop)
        std::ostringstream oss;
        oss << osvi.dwMajorVersion << '.' << osvi.dwMinorVersion << " (build " << osvi.dwBuildNumber << ')';
        return oss.str();
    }
    return "Unknown";
#elif defined(__APPLE__)
    char buffer[256];
    size_t size = sizeof(buffer);
    if (sysctlbyname("kern.osrelease", &buffer, &size, nullptr, 0) == 0) {
        return std::string(buffer, size - 1);
    }
    return "Unknown";
#else
    struct utsname uts {};
    if (uname(&uts) == 0) {
        return uts.release;
    }
    return "Unknown";
#endif
}

std::string detect_architecture() {
#if defined(_WIN32)
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    switch (sysinfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            return "x86_64";
        case PROCESSOR_ARCHITECTURE_ARM64:
            return "ARM64";
        case PROCESSOR_ARCHITECTURE_INTEL:
            return "x86";
        default:
            return "Unknown";
    }
#elif defined(__APPLE__)
    char buffer[256];
    size_t size = sizeof(buffer);
    if (sysctlbyname("hw.machine", &buffer, &size, nullptr, 0) == 0) {
        return std::string(buffer, size - 1);
    }
    return "Unknown";
#else
    struct utsname uts {};
    if (uname(&uts) == 0) {
        return uts.machine;
    }
    return "Unknown";
#endif
}

std::string detect_hostname() {
    std::array<char, 256> buffer{};
    if (gethostname(buffer.data(), buffer.size()) == 0) {
        return std::string(buffer.data());
    }
    return "Unknown";
}

}  // namespace

SystemInfo collect_system_info() {
    SystemInfo info;
    info.os_name = detect_os_name();
    info.kernel_version = detect_kernel_version();
    info.architecture = detect_architecture();
    info.cpu_model = detect_cpu_model();
    info.cpu_threads = std::thread::hardware_concurrency();
    info.total_memory_bytes = detect_total_memory();
    info.available_memory_bytes = detect_available_memory();
    info.hostname = detect_hostname();
    return info;
}

std::string human_readable_bytes(std::uint64_t bytes) {
    if (bytes == 0) {
        return "0 B";
    }

    constexpr std::array<const char*, 7> suffixes = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    double count = static_cast<double>(bytes);
    std::size_t suffix_index = 0;
    while (count >= 1024.0 && suffix_index + 1 < suffixes.size()) {
        count /= 1024.0;
        ++suffix_index;
    }

    std::ostringstream oss;
    oss.setf(std::ios::fixed);
    oss.precision(count < 10.0 && suffix_index > 0 ? 2 : 0);
    oss << count << ' ' << suffixes[suffix_index];
    return oss.str();
}

}  // namespace unlock_pdf::util
