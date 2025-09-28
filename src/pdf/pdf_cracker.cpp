#include "pdf/pdf_cracker.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <string>

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

}  // namespace

bool crack_pdf(const std::vector<std::string>& passwords,
               const std::string& pdf_path,
               CrackResult& result,
               unsigned int thread_count) {
    result = CrackResult{};
    result.total_passwords = passwords.size();

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

    if (passwords.empty()) {
        std::cerr << "Error: password list is empty" << std::endl;
        return false;
    }

    if (thread_count == 0) {
        thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) {
            thread_count = 2;
        }
    }
    thread_count = std::min<unsigned int>(thread_count, 16);
    if (thread_count > passwords.size()) {
        thread_count = static_cast<unsigned int>(passwords.size());
        thread_count = std::max(thread_count, 1u);
    }

    std::cout << "\nStarting password cracking with " << thread_count << " threads" << std::endl;

    std::atomic<bool> password_found{false};
    std::atomic<std::size_t> passwords_tried{0};
    std::mutex result_mutex;
    std::string found_password;
    std::string found_variant;

    auto start_time = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    std::size_t per_thread = passwords.size() / thread_count;
    std::size_t remainder = passwords.size() % thread_count;
    std::size_t current_start = 0;

    auto worker = [&](std::size_t start, std::size_t end) {
        for (std::size_t i = start; i < end && !password_found.load(); ++i) {
            std::string variant;
            if (check_password_variants(passwords[i], encrypt_info, password_handlers, variant)) {
                std::lock_guard<std::mutex> lock(result_mutex);
                if (!password_found) {
                    password_found = true;
                    found_password = passwords[i];
                    found_variant = variant;
                    std::cout << "\nPASSWORD FOUND [" << variant << "]: " << passwords[i] << std::endl;
                }
                return;
            }

            std::size_t tried = ++passwords_tried;
            if (tried % 100 == 0) {
                print_progress(tried, passwords.size());
            }
        }
    };

    for (unsigned int i = 0; i < thread_count; ++i) {
        std::size_t count = per_thread + (i < remainder ? 1 : 0);
        std::size_t end = current_start + count;
        threads.emplace_back(worker, current_start, end);
        current_start = end;
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    std::cout << "\n\nFinished in " << duration.count() << " seconds" << std::endl;

    result.passwords_tried = passwords_tried.load();
    result.success = password_found.load();
    if (result.success) {
        result.password = found_password;
        result.variant = found_variant;
        std::cout << "Password found: " << found_password << std::endl;
    } else {
        std::cout << "Password not found in the provided list" << std::endl;
    }

    return true;
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
            alphabet += "!@#$%^&*()_+={}[]|:;<>,.?/~";
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
    thread_count = std::min<unsigned int>(thread_count, 16);
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
