#include "pdf/pdf_cracker.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <codecvt>

#include "pdf/encryption/encryption_handler_registry.h"
#include "pdf/pdf_parser.h"

namespace unlock_pdf::pdf {
namespace {

void print_progress(std::size_t tried, std::size_t total) {
    if (total == 0) {
        std::cout << "\rPasswords tried: " << tried << std::flush;
        return;
    }
    double progress = static_cast<double>(tried) / static_cast<double>(total) * 100.0;
    std::cout << "\rTrying passwords... " << std::fixed << std::setprecision(2) << progress << "% (" << tried
              << "/" << total << ")" << std::flush;
}

bool check_password_variants(const std::string& password,
                             const PDFEncryptInfo& info,
                             const std::vector<const EncryptionHandler*>& handlers,
                             std::string& matched_variant) {
    for (const EncryptionHandler* handler : handlers) {
        if (handler->check_password(password, info, matched_variant)) {
            return true;
        }
    }
    return false;
}

bool handle_non_password_handlers(const PDFEncryptInfo& info,
                                  CrackResult& result,
                                  const std::vector<EncryptionHandlerPtr>& handlers) {
    for (const auto& handler : handlers) {
        if (!handler->can_handle(info) || handler->requires_password()) {
            continue;
        }
        bool success = false;
        std::string variant;
        std::string discovered;
        if (handler->handle_without_password(info, success, variant, discovered)) {
            result.success = success;
            result.variant = variant;
            result.password = discovered;
            result.passwords_tried = 0;
            if (success) {
                std::cout << "\nPASSWORD FOUND [" << variant << "]: " << discovered << std::endl;
            } else {
                std::cout << "\nDetected " << variant
                          << ". Password cracking is not applicable for this protection." << std::endl;
            }
            return true;
        }
    }
    return false;
}

std::vector<const EncryptionHandler*> collect_password_handlers(const PDFEncryptInfo& info,
                                                                const std::vector<EncryptionHandlerPtr>& handlers) {
    std::vector<const EncryptionHandler*> password_handlers;
    password_handlers.reserve(handlers.size());
    for (const auto& handler : handlers) {
        if (!handler->can_handle(info) || !handler->requires_password()) {
            continue;
        }
        password_handlers.push_back(handler.get());
    }
    return password_handlers;
}

class PasswordSource {
   public:
    virtual ~PasswordSource() = default;
    virtual bool next(std::string& password) = 0;
    virtual bool has_total() const { return false; }
    virtual std::size_t total() const { return 0; }
};

class VectorPasswordSource final : public PasswordSource {
   public:
    explicit VectorPasswordSource(const std::vector<std::string>& passwords) : passwords_(passwords) {}

    bool next(std::string& password) override {
        std::size_t index = index_.fetch_add(1, std::memory_order_relaxed);
        if (index >= passwords_.size()) {
            return false;
        }
        password = passwords_[index];
        return true;
    }

    bool has_total() const override { return true; }
    std::size_t total() const override { return passwords_.size(); }

   private:
    const std::vector<std::string>& passwords_;
    std::atomic<std::size_t> index_{0};
};

class FilePasswordSource final : public PasswordSource {
   public:
    explicit FilePasswordSource(const std::string& path) : stream_(path, std::ios::binary) {
        if (!stream_) {
            throw std::runtime_error("unable to open wordlist: " + path);
        }

        unsigned char bom[3] = {0, 0, 0};
        stream_.read(reinterpret_cast<char*>(bom), sizeof(bom));
        std::streamsize read_bytes = stream_.gcount();
        std::size_t skip = 0;

        if (read_bytes >= 2 && bom[0] == 0xFF && bom[1] == 0xFE) {
            encoding_ = Encoding::Utf16LE;
            skip = 2;
        } else if (read_bytes >= 2 && bom[0] == 0xFE && bom[1] == 0xFF) {
            encoding_ = Encoding::Utf16BE;
            skip = 2;
        } else if (read_bytes >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF) {
            encoding_ = Encoding::Utf8;
            skip = 3;
        } else {
            encoding_ = Encoding::Utf8;
            skip = 0;
        }

        stream_.clear();
        stream_.seekg(static_cast<std::streamoff>(skip), std::ios::beg);
    }

    bool next(std::string& password) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!stream_) {
            return false;
        }

        std::string line;
        while (true) {
            bool ok = false;
            if (encoding_ == Encoding::Utf8) {
                ok = read_utf8_line(line);
            } else {
                ok = read_utf16_line(line);
            }

            if (!ok) {
                return false;
            }

            if (!line.empty()) {
                password = std::move(line);
                return true;
            }
        }
    }

   private:
    enum class Encoding { Utf8, Utf16LE, Utf16BE };

    bool read_utf8_line(std::string& out) {
        std::string line;
        if (!std::getline(stream_, line)) {
            return false;
        }
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        out = std::move(line);
        return true;
    }

    bool read_utf16_line(std::string& out) {
        std::u16string buffer;
        bool read_any = false;
        while (true) {
            char bytes[2];
            stream_.read(bytes, 2);
            std::streamsize got = stream_.gcount();
            if (got == 0) {
                break;
            }
            if (got < 2) {
                return false;
            }
            read_any = true;
            char16_t code = 0;
            if (encoding_ == Encoding::Utf16LE) {
                code = static_cast<unsigned char>(bytes[0]) |
                       (static_cast<char16_t>(static_cast<unsigned char>(bytes[1])) << 8);
            } else {
                code = (static_cast<char16_t>(static_cast<unsigned char>(bytes[0])) << 8) |
                       static_cast<unsigned char>(bytes[1]);
            }

            if (code == u'\n') {
                break;
            }
            if (code == u'\r') {
                continue;
            }
            buffer.push_back(code);
        }

        if (!read_any && buffer.empty()) {
            return false;
        }

        try {
            out = utf16_converter_.to_bytes(buffer);
        } catch (const std::range_error&) {
            out.clear();
        }
        return true;
    }

    std::ifstream stream_;
    Encoding encoding_ = Encoding::Utf8;
    std::mutex mutex_;
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> utf16_converter_;
};

bool crack_with_source(PasswordSource& source,
                       const std::string& pdf_path,
                       CrackResult& result,
                       unsigned int thread_count) {
    result = CrackResult{};
    if (source.has_total()) {
        result.total_passwords = source.total();
    }

    PDFEncryptInfo encrypt_info;
    if (!read_pdf_encrypt_info(pdf_path, encrypt_info)) {
        return false;
    }

    auto handlers = create_default_encryption_handlers();
    if (handle_non_password_handlers(encrypt_info, result, handlers)) {
        return true;
    }

    std::vector<const EncryptionHandler*> password_handlers = collect_password_handlers(encrypt_info, handlers);
    if (password_handlers.empty()) {
        std::cerr << "Error: No password-based handlers are available for the detected encryption." << std::endl;
        return false;
    }

    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) {
            thread_count = 2;
        }
    }
    thread_count = std::max(thread_count, 1u);
    if (source.has_total()) {
        std::size_t total = source.total();
        if (total > 0 && static_cast<std::size_t>(thread_count) > total) {
            thread_count = static_cast<unsigned int>(total);
            thread_count = std::max(thread_count, 1u);
        }
    }

    std::cout << "\nStarting password cracking with " << thread_count << " threads" << std::endl;

    std::atomic<bool> password_found{false};
    std::atomic<std::size_t> passwords_tried{0};
    std::mutex result_mutex;
    std::string found_password;
    std::string found_variant;

    auto start_time = std::chrono::steady_clock::now();

    auto worker = [&]() {
        while (true) {
            if (password_found.load(std::memory_order_relaxed)) {
                break;
            }

            std::string password;
            if (!source.next(password)) {
                break;
            }

            std::size_t attempt = passwords_tried.fetch_add(1, std::memory_order_relaxed) + 1;

            if (password_found.load(std::memory_order_acquire)) {
                break;
            }

            std::string variant;
            if (check_password_variants(password, encrypt_info, password_handlers, variant)) {
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!password_found.load(std::memory_order_relaxed)) {
                    password_found.store(true, std::memory_order_release);
                    found_password = std::move(password);
                    found_variant = std::move(variant);
                    std::cout << "\nPASSWORD FOUND [" << found_variant << "]: " << found_password << std::endl;
                }
                break;
            }

            if (attempt % 100 == 0) {
                print_progress(attempt, result.total_passwords);
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (unsigned int i = 0; i < thread_count; ++i) {
        threads.emplace_back(worker);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    std::size_t attempted = passwords_tried.load(std::memory_order_relaxed);
    std::cout << std::endl;

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
    std::cout << "\nFinished in " << duration.count() << " seconds" << std::endl;

    result.passwords_tried = attempted;
    if (result.total_passwords == 0 || result.total_passwords < attempted) {
        result.total_passwords = attempted;
    }
    result.success = password_found.load(std::memory_order_relaxed);
    if (result.success) {
        result.password = found_password;
        result.variant = found_variant;
        std::cout << "Password found: " << result.password << std::endl;
    } else {
        std::cout << "Password not found in the provided list" << std::endl;
    }

    return true;
}

}  // namespace

bool crack_pdf(const std::vector<std::string>& passwords,
               const std::string& pdf_path,
               CrackResult& result,
               unsigned int thread_count) {
    if (passwords.empty()) {
        std::cerr << "Error: password list is empty" << std::endl;
        return false;
    }

    VectorPasswordSource source(passwords);
    return crack_with_source(source, pdf_path, result, thread_count);
}

bool crack_pdf_from_file(const std::string& wordlist_path,
                         const std::string& pdf_path,
                         CrackResult& result,
                         unsigned int thread_count) {
    FilePasswordSource source(wordlist_path);
    return crack_with_source(source, pdf_path, result, thread_count);
}

bool crack_pdf_bruteforce(const unlock_pdf::util::WordlistOptions& options,
                          const std::string& pdf_path,
                          CrackResult& result,
                          unsigned int thread_count) {
    result = CrackResult{};

    if (options.min_length == 0 || options.max_length < options.min_length) {
        std::cerr << "Error: invalid password length range" << std::endl;
        return false;
    }

    std::string alphabet;
    if (options.use_custom_characters) {
        if (options.custom_characters.empty()) {
            std::cerr << "Error: custom characters must not be empty" << std::endl;
            return false;
        }
        alphabet = options.custom_characters;
    } else {
        if (options.include_uppercase) {
            alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        }
        if (options.include_lowercase) {
            alphabet += "abcdefghijklmnopqrstuvwxyz";
        }
        if (options.include_digits) {
            alphabet += "0123456789";
        }
        if (options.include_special) {
            alphabet += "!\"#$%&'()*+,-./:;<=>?@[]^_{|}~";
        }
    }

    if (alphabet.empty()) {
        std::cerr << "Error: character set is empty" << std::endl;
        return false;
    }

    PDFEncryptInfo encrypt_info;
    if (!read_pdf_encrypt_info(pdf_path, encrypt_info)) {
        return false;
    }

    auto handlers = create_default_encryption_handlers();
    if (handle_non_password_handlers(encrypt_info, result, handlers)) {
        return true;
    }

    std::vector<const EncryptionHandler*> password_handlers = collect_password_handlers(encrypt_info, handlers);
    if (password_handlers.empty()) {
        std::cerr << "Error: No password-based handlers are available for the detected encryption." << std::endl;
        return false;
    }

    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) {
            thread_count = 2;
        }
    }
    thread_count = std::max(thread_count, 1u);

    std::cout << "\nStarting brute-force password search with " << thread_count << " threads" << std::endl;

    struct Task {
        std::string prefix;
        std::size_t target_length = 0;
    };

    std::vector<Task> tasks;
    std::size_t base_prefix_length = std::min<std::size_t>(options.min_length, static_cast<std::size_t>(2));
    if (base_prefix_length == 0) {
        base_prefix_length = 1;
    }

    std::string current_prefix;
    auto add_tasks_for_length = [&](std::size_t length) {
        std::size_t prefix_length = std::min<std::size_t>(length, base_prefix_length);
        current_prefix.clear();
        current_prefix.reserve(prefix_length);
        if (prefix_length == 0) {
            tasks.push_back(Task{std::string(), length});
            return;
        }

        std::vector<std::size_t> indices(prefix_length, 0);
        while (true) {
            current_prefix.resize(prefix_length);
            for (std::size_t i = 0; i < prefix_length; ++i) {
                current_prefix[i] = alphabet[indices[i]];
            }
            tasks.push_back(Task{current_prefix, length});

            std::size_t pos = prefix_length;
            while (pos > 0) {
                --pos;
                if (++indices[pos] < alphabet.size()) {
                    break;
                }
                indices[pos] = 0;
            }
            if (pos == 0 && indices[0] == 0) {
                break;
            }
        }
    };

    for (std::size_t length = options.min_length; length <= options.max_length; ++length) {
        add_tasks_for_length(length);
    }

    std::atomic<bool> password_found{false};
    std::atomic<std::size_t> passwords_tried{0};
    std::mutex result_mutex;
    std::string found_password;
    std::string found_variant;

    auto worker = [&](const Task& task) {
        std::size_t total_positions = task.target_length - task.prefix.size();
        if (total_positions == 0) {
            std::string variant;
            if (check_password_variants(task.prefix, encrypt_info, password_handlers, variant)) {
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!password_found) {
                    password_found = true;
                    found_password = task.prefix;
                    found_variant = variant;
                    std::cout << "\nPASSWORD FOUND [" << variant << "]: " << task.prefix << std::endl;
                }
            }
            ++passwords_tried;
            return;
        }

        std::vector<std::size_t> indices(total_positions, 0);
        std::string candidate = task.prefix;
        candidate.resize(task.target_length);

        while (!password_found.load()) {
            for (std::size_t i = 0; i < total_positions; ++i) {
                candidate[task.prefix.size() + i] = alphabet[indices[i]];
            }

            std::string variant;
            if (check_password_variants(candidate, encrypt_info, password_handlers, variant)) {
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!password_found) {
                    password_found = true;
                    found_password = candidate;
                    found_variant = variant;
                    std::cout << "\nPASSWORD FOUND [" << variant << "]: " << candidate << std::endl;
                }
                break;
            }

            std::size_t tried = ++passwords_tried;
            if (tried % 1000 == 0) {
                print_progress(tried, 0);
            }

            std::size_t pos = total_positions;
            while (pos > 0) {
                --pos;
                if (++indices[pos] < alphabet.size()) {
                    break;
                }
                indices[pos] = 0;
            }
            if (pos == 0 && indices[0] == 0) {
                break;
            }
        }
    };

    std::vector<std::thread> threads;
    std::atomic<std::size_t> task_index{0};
    auto thread_worker = [&]() {
        while (!password_found.load()) {
            std::size_t index = task_index.fetch_add(1);
            if (index >= tasks.size()) {
                break;
            }
            worker(tasks[index]);
        }
    };

    for (unsigned int i = 0; i < thread_count; ++i) {
        threads.emplace_back(thread_worker);
    }
    for (auto& thread : threads) {
        thread.join();
    }

    result.passwords_tried = passwords_tried.load();
    result.success = password_found.load();
    if (result.success) {
        result.password = found_password;
        result.variant = found_variant;
        std::cout << "Password found: " << found_password << std::endl;
    } else {
        std::cout << "Password not found with brute-force search" << std::endl;
    }

    return true;
}

}  // namespace unlock_pdf::pdf
