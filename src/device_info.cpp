#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <stdexcept>
#include <vector>

#include "crypto/sha2.h"
#include "pdf/encryption/encryption_handler_registry.h"
#include "pdf/encryption/encryption_handler.h"
#include "pdf/pdf_parser.h"
#include "util/system_info.h"

namespace {

enum class Workload {
    Synthetic,
    Pdf
};

enum class HashMode {
    StdHash,
    Sha256
};

struct BenchmarkConfig {
    std::size_t password_length = 8;
    std::size_t attempts = 500000;
    std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    Workload workload = Workload::Synthetic;
    HashMode hash_mode = HashMode::StdHash;
    std::string pdf_path;
};

struct BenchmarkResult {
    std::size_t password_length;
    std::size_t attempts;
    double duration_seconds;
    double attempts_per_second;
};

std::vector<std::string> split_lengths(const std::string& value) {
    std::vector<std::string> parts;
    std::string current;
    std::istringstream iss(value);
    while (std::getline(iss, current, ',')) {
        if (!current.empty()) {
            parts.push_back(current);
        }
    }
    return parts;
}

void print_help(const char* program) {
    std::cout << "Usage: " << program << " [options]\n\n"
              << "Options:\n"
              << "  --attempts <n>       Number of attempts per benchmark length (default: 500000)\n"
              << "  --lengths <list>     Comma separated password lengths to benchmark (default: 6,8,10)\n"
              << "  --include-special    Include printable special characters in the charset\n"
              << "  --custom <chars>     Use a custom character set (overrides other charset options)\n"
              << "  --hash <mode>        Synthetic hash mode: none or sha256 (default: none)\n"
              << "  --pdf <path>         Benchmark the real PDF password check using metadata from <path>\n"
              << "  --help               Show this help message\n";
}

std::string build_special_charset() {
    return "!\"#$%&'()*+,-./:;<=>?@[]^_{|}~";
}

BenchmarkResult run_benchmark(std::size_t length,
                              std::size_t attempts,
                              const std::string& charset,
                              bool use_sha256) {
    if (charset.empty() || length == 0 || attempts == 0) {
        return BenchmarkResult{length, attempts, 0.0, 0.0};
    }

    const std::size_t charset_size = charset.size();
    const char first_char = charset.front();
    const char* charset_data = charset.data();
    std::string candidate(length, first_char);
    std::vector<std::size_t> indices(length, 0);
    std::hash<std::string_view> hasher;
    std::string_view candidate_view(candidate);
    const unsigned char* candidate_bytes = reinterpret_cast<const unsigned char*>(candidate_view.data());
    std::array<unsigned char, 32> digest{};

    volatile std::size_t sink = 0;
    auto start = std::chrono::steady_clock::now();
    for (std::size_t attempt = 0; attempt < attempts; ++attempt) {
        if (use_sha256) {
            unlock_pdf::crypto::sha256_digest(candidate_bytes, candidate_view.size(), digest.data());
            sink = static_cast<std::size_t>(digest.front());
        } else {
            sink = hasher(candidate_view);
        }

        std::size_t pos = 0;
        while (pos < length) {
            std::size_t next_index = indices[pos] + 1;
            if (next_index < charset_size) {
                indices[pos] = next_index;
                candidate[pos] = charset_data[next_index];
                break;
            }
            indices[pos] = 0;
            candidate[pos] = first_char;
            ++pos;
        }
    }
    auto end = std::chrono::steady_clock::now();

    std::chrono::duration<double> elapsed = end - start;
    double duration = elapsed.count();
    double throughput = duration > 0.0 ? static_cast<double>(attempts) / duration : 0.0;

    // Prevent the compiler from optimizing away the benchmark loop.
    (void)sink;

    return BenchmarkResult{length, attempts, duration, throughput};
}

std::vector<const unlock_pdf::pdf::EncryptionHandler*> collect_password_handlers(
    const unlock_pdf::pdf::PDFEncryptInfo& info,
    const std::vector<unlock_pdf::pdf::EncryptionHandlerPtr>& handlers) {
    std::vector<const unlock_pdf::pdf::EncryptionHandler*> password_handlers;
    password_handlers.reserve(handlers.size());
    for (const auto& handler : handlers) {
        if (!handler) {
            continue;
        }
        if (!handler->can_handle(info) || !handler->requires_password()) {
            continue;
        }
        password_handlers.push_back(handler.get());
    }
    return password_handlers;
}

int effective_key_length_bits(const unlock_pdf::pdf::PDFEncryptInfo& info) {
    if (info.length > 0) {
        return info.length;
    }
    if (info.revision <= 0) {
        return 0;
    }
    if (info.revision <= 2) {
        return 40;
    }
    if (info.revision <= 4) {
        return 128;
    }
    return 256;
}

BenchmarkResult run_pdf_benchmark(std::size_t length,
                                  std::size_t attempts,
                                  const std::string& charset,
                                  const unlock_pdf::pdf::PDFEncryptInfo& info,
                                  const std::vector<const unlock_pdf::pdf::EncryptionHandler*>& handlers) {
    if (charset.empty() || length == 0 || attempts == 0 || handlers.empty()) {
        return BenchmarkResult{length, attempts, 0.0, 0.0};
    }

    const std::size_t charset_size = charset.size();
    const char first_char = charset.front();
    const char* charset_data = charset.data();
    std::string candidate(length, first_char);
    std::vector<std::size_t> indices(length, 0);
    std::string matched_variant;

    volatile bool sink = false;
    auto start = std::chrono::steady_clock::now();
    for (std::size_t attempt = 0; attempt < attempts; ++attempt) {
        bool matched = false;
        matched_variant.clear();
        for (const auto* handler : handlers) {
            if (handler->check_password(candidate, info, matched_variant)) {
                matched = true;
                break;
            }
        }
        sink = sink || matched;

        std::size_t pos = 0;
        while (pos < length) {
            std::size_t next_index = indices[pos] + 1;
            if (next_index < charset_size) {
                indices[pos] = next_index;
                candidate[pos] = charset_data[next_index];
                break;
            }
            indices[pos] = 0;
            candidate[pos] = first_char;
            ++pos;
        }
    }
    auto end = std::chrono::steady_clock::now();

    std::chrono::duration<double> elapsed = end - start;
    double duration = elapsed.count();
    double throughput = duration > 0.0 ? static_cast<double>(attempts) / duration : 0.0;

    (void)sink;

    return BenchmarkResult{length, attempts, duration, throughput};
}

}  // namespace

int main(int argc, char* argv[]) {
    BenchmarkConfig config;
    std::vector<std::size_t> lengths = {6, 8, 10};
    bool custom_charset = false;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        auto require_value = [&](std::string_view option) -> std::string {
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing value for option: " + std::string(option));
            }
            return argv[++i];
        };

        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "--attempts") {
            config.attempts = static_cast<std::size_t>(std::stoull(require_value(arg)));
        } else if (arg == "--lengths") {
            lengths.clear();
            for (const auto& token : split_lengths(require_value(arg))) {
                lengths.push_back(static_cast<std::size_t>(std::stoull(token)));
            }
        } else if (arg == "--include-special") {
            config.charset += build_special_charset();
        } else if (arg == "--custom") {
            config.charset = require_value(arg);
            custom_charset = true;
        } else if (arg == "--hash") {
            std::string mode = require_value(arg);
            std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (mode == "sha256") {
                config.hash_mode = HashMode::Sha256;
            } else if (mode == "none") {
                config.hash_mode = HashMode::StdHash;
            } else {
                throw std::runtime_error("Unknown hash mode: " + mode);
            }
        } else if (arg == "--pdf") {
            config.workload = Workload::Pdf;
            config.pdf_path = require_value(arg);
        } else {
            throw std::runtime_error("Unknown option: " + std::string(arg));
        }
    }

    if (!custom_charset) {
        // Ensure charset contains unique characters to avoid skewing the benchmark.
        std::string unique_charset;
        for (char ch : config.charset) {
            if (unique_charset.find(ch) == std::string::npos) {
                unique_charset.push_back(ch);
            }
        }
        config.charset = unique_charset;
    }

    if (config.charset.empty()) {
        std::cerr << "Error: Character set cannot be empty." << std::endl;
        return 1;
    }

    if (config.attempts == 0) {
        std::cerr << "Error: Number of attempts must be greater than zero." << std::endl;
        return 1;
    }

    unlock_pdf::pdf::PDFEncryptInfo pdf_info;
    std::vector<unlock_pdf::pdf::EncryptionHandlerPtr> handler_storage;
    std::vector<const unlock_pdf::pdf::EncryptionHandler*> password_handlers;

    if (config.workload == Workload::Pdf) {
        if (config.pdf_path.empty()) {
            std::cerr << "Error: --pdf requires a file path." << std::endl;
            return 1;
        }
        if (config.hash_mode == HashMode::Sha256) {
            std::cerr << "Error: --hash sha256 cannot be combined with --pdf." << std::endl;
            return 1;
        }

        if (!unlock_pdf::pdf::read_pdf_encrypt_info(config.pdf_path, pdf_info)) {
            return 1;
        }

        handler_storage = unlock_pdf::pdf::create_default_encryption_handlers();
        password_handlers = collect_password_handlers(pdf_info, handler_storage);
        if (password_handlers.empty()) {
            std::cerr << "Error: No password-based handlers are applicable to the provided PDF." << std::endl;
            return 1;
        }
    }

    std::cout << "=====================\n";
    std::cout << "System Information\n";
    std::cout << "=====================\n";
    const auto info = unlock_pdf::util::collect_system_info();
    std::cout << "Hostname:            " << info.hostname << '\n';
    std::cout << "Operating System:    " << info.os_name;
    if (!info.kernel_version.empty()) {
        std::cout << " (kernel " << info.kernel_version << ')';
    }
    std::cout << '\n';
    std::cout << "Architecture:        " << info.architecture << '\n';
    std::cout << "CPU Model:           " << info.cpu_model << '\n';
    std::cout << "Hardware Threads:    " << info.cpu_threads << '\n';
    std::cout << "Total Memory:        " << unlock_pdf::util::human_readable_bytes(info.total_memory_bytes) << '\n';
    std::cout << "Available Memory:    " << unlock_pdf::util::human_readable_bytes(info.available_memory_bytes) << "\n\n";

    std::cout << "Benchmark Configuration\n";
    std::cout << "------------------------\n";
    std::cout << "Character set size:  " << config.charset.size() << '\n';
    if (config.workload == Workload::Pdf) {
        std::cout << "Workload:           PDF password check" << '\n';
        std::cout << "PDF file:           " << config.pdf_path << '\n';
        if (!pdf_info.filter.empty()) {
            std::cout << "Filter:             " << pdf_info.filter << '\n';
        }
        if (!pdf_info.sub_filter.empty()) {
            std::cout << "SubFilter:          " << pdf_info.sub_filter << '\n';
        }
        if (pdf_info.revision != 0) {
            std::cout << "Revision:           R" << pdf_info.revision << '\n';
        }
        int key_length = effective_key_length_bits(pdf_info);
        if (key_length > 0) {
            std::cout << "Key length:         " << key_length << " bits" << '\n';
        }
        std::cout << "Password handlers:  " << password_handlers.size() << '\n';
    } else {
        std::cout << "Workload:           Synthetic hash" << '\n';
        std::cout << "Hash mode:          "
                  << (config.hash_mode == HashMode::Sha256 ? "SHA-256" : "None (std::hash)") << '\n';
        std::cout << "Note:               Use --pdf <file.pdf> to benchmark the real PDF password check." << '\n';
    }
    std::cout << "Attempts per test:   " << config.attempts << "\n\n";

    std::cout << std::left << std::setw(12) << "Length" << std::setw(18) << "Attempts" << std::setw(18) << "Duration (s)"
              << "Attempts/s" << '\n';
    std::cout << std::string(62, '-') << '\n';

    for (std::size_t length : lengths) {
        if (length == 0) {
            continue;
        }
        BenchmarkResult result;
        if (config.workload == Workload::Pdf) {
            result = run_pdf_benchmark(length, config.attempts, config.charset, pdf_info, password_handlers);
        } else {
            result = run_benchmark(length,
                                   config.attempts,
                                   config.charset,
                                   config.hash_mode == HashMode::Sha256);
        }

        std::ostringstream duration_stream;
        duration_stream << std::fixed << std::setprecision(4) << result.duration_seconds;

        std::ostringstream throughput_stream;
        throughput_stream << std::fixed << std::setprecision(2) << result.attempts_per_second;

        std::cout << std::left << std::setw(12) << result.password_length << std::setw(18) << result.attempts
                  << std::setw(18) << duration_stream.str() << throughput_stream.str() << '\n';
    }

    return 0;
}
