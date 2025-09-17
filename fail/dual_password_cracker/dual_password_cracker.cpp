#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <iomanip>
#include <chrono>
#include <atomic>
#include <cstring>
#include "pure_sha256.hpp"
#include "pure_aes256.hpp"

struct PDFEncryptInfo {
    std::vector<unsigned char> id;          // Document ID
    std::vector<unsigned char> u_string;    // User password validation string
    std::vector<unsigned char> o_string;    // Owner password validation string
    std::vector<unsigned char> ue_string;   // User encryption key (R>=6)
    std::vector<unsigned char> oe_string;   // Owner encryption key (R>=6)
    std::vector<unsigned char> perms;       // Permissions (R>=6)
    int version;                            // Encryption version (V)
    int revision;                           // Security revision (R)
    int length;                             // Key length in bits
    bool encrypted;                         // True if encryption detected
};

std::mutex g_mutex;
bool g_password_found = false;
std::string g_found_password;
std::atomic<size_t> g_passwords_tried{0};
size_t g_total_passwords = 0;

void print_progress() {
    size_t tried = g_passwords_tried.load();
    float progress = (float)tried / g_total_passwords * 100.0f;
    std::cout << "\rTrying passwords... " << std::fixed << std::setprecision(2) 
              << progress << "% (" << tried << "/" << g_total_passwords << ")" << std::flush;
}

// SHA-256 hash with optional salt (pure C++)
std::vector<unsigned char> sha256(const std::string& input,
                                const std::vector<unsigned char>& salt,
                                int /*rounds*/ = 1) {
    std::vector<unsigned char> combined;
    combined.reserve(input.size() + salt.size());
    combined.insert(combined.end(), input.begin(), input.end());
    combined.insert(combined.end(), salt.begin(), salt.end());
    auto digest = purecrypto::sha256(combined.data(), combined.size());
    return std::vector<unsigned char>(digest.begin(), digest.end());
}

bool aes256_cbc_decrypt(const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv,
                       const std::vector<unsigned char>& ciphertext,
                       std::vector<unsigned char>& plaintext) {
    return purecrypto::aes256_cbc_decrypt(key, iv, ciphertext, plaintext);
}

bool check_password_r6(const std::string& password,
                      const PDFEncryptInfo& encrypt_info) {
    // R6 uses SHA-256 with validation salt
    std::vector<unsigned char> validation_salt(encrypt_info.u_string.begin(),
                                             encrypt_info.u_string.begin() + 8);
    
    std::vector<unsigned char> key_salt(encrypt_info.u_string.begin() + 8,
                                      encrypt_info.u_string.begin() + 16);
    
    // Hash password with validation salt
    std::vector<unsigned char> hash = sha256(password, validation_salt);
    
    // Compare with U string (bytes 16-48)
    if (memcmp(hash.data(), encrypt_info.u_string.data() + 16, 32) == 0) {
        // Password matches validation hash, now decrypt UE string
        std::vector<unsigned char> key = sha256(password, key_salt);
        std::vector<unsigned char> iv(16, 0); // Zero IV for this operation
        std::vector<unsigned char> file_key;
        
        if (aes256_cbc_decrypt(key, iv, encrypt_info.ue_string, file_key)) {
            return true; // Successfully decrypted UE string
        }
    }
    
    return false;
}

void try_passwords(const std::vector<std::string>& passwords,
                  size_t start, size_t end,
                  const PDFEncryptInfo& encrypt_info) {
    for (size_t i = start; i < end && !g_password_found; ++i) {
            if (check_password_r6(passwords[i], encrypt_info)) {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_password_found = true;
            g_found_password = passwords[i];
            std::cout << "\nPASSWORD FOUND: " << passwords[i] << std::endl;
            break;
        }
        
        g_passwords_tried++;
        if (i % 100 == 0) {
            print_progress();
        }
    }
}

std::vector<unsigned char> parse_string(const char* start) {
    std::vector<unsigned char> result;
    
    if (*start == '<') {
        // Handle hex string
        start++;
        while (*start && *start != '>') {
            if (isxdigit(start[0]) && isxdigit(start[1])) {
                char hex[3] = {start[0], start[1], 0};
                result.push_back(static_cast<unsigned char>(strtol(hex, nullptr, 16)));
                start += 2;
            } else {
                start++;
            }
        }
    } else if (*start == '(') {
        // Handle literal string
        start++;
        int paren_level = 1;
        while (*start && paren_level > 0) {
            if (*start == '(') paren_level++;
            else if (*start == ')') paren_level--;
            else if (*start == '\\' && start[1]) {
                start++;
                switch (*start) {
                    case 'n': result.push_back('\n'); break;
                    case 'r': result.push_back('\r'); break;
                    case 't': result.push_back('\t'); break;
                    case 'b': result.push_back('\b'); break;
                    case 'f': result.push_back('\f'); break;
                    default: result.push_back(*start);
                }
            } else {
                result.push_back(*start);
            }
            start++;
        }
    }
    
    return result;
}

bool extract_encryption_info(const char* buffer, size_t size, PDFEncryptInfo& info) {
    // Find encryption dictionary
    const char* pos = strstr(buffer, "/Encrypt");
    if (!pos) return false;

    // Get version and revision
    const char* v_pos = strstr(pos, "/V ");
    const char* r_pos = strstr(pos, "/R ");
    if (!v_pos || !r_pos) return false;
    
    info.version = atoi(v_pos + 3);
    info.revision = atoi(r_pos + 3);
    
    // Get U string
    const char* u_pos = strstr(pos, "/U");
    if (u_pos) {
        while (*u_pos && *u_pos != '(' && *u_pos != '<') u_pos++;
        if (*u_pos) info.u_string = parse_string(u_pos);
    }
    
    // Get O string 
    const char* o_pos = strstr(pos, "/O");
    if (o_pos) {
        while (*o_pos && *o_pos != '(' && *o_pos != '<') o_pos++;
        if (*o_pos) info.o_string = parse_string(o_pos);
    }
    
    // Get R6-specific strings
    if (info.revision >= 6) {
        // Get UE string
        const char* ue_pos = strstr(pos, "/UE");
        if (ue_pos) {
            while (*ue_pos && *ue_pos != '(' && *ue_pos != '<') ue_pos++;
            if (*ue_pos) info.ue_string = parse_string(ue_pos);
        }
        
        // Get OE string
        const char* oe_pos = strstr(pos, "/OE");
        if (oe_pos) {
            while (*oe_pos && *oe_pos != '(' && *oe_pos != '<') oe_pos++;
            if (*oe_pos) info.oe_string = parse_string(oe_pos);
        }
        
        // Get Perms string
        const char* perms_pos = strstr(pos, "/Perms");
        if (perms_pos) {
            while (*perms_pos && *perms_pos != '(' && *perms_pos != '<') perms_pos++;
            if (*perms_pos) info.perms = parse_string(perms_pos);
        }
    }
    
    info.length = 256; // AES-256 for V5
    info.encrypted = true;
    
    return true;
}

bool read_pdf_encrypt_info(const std::string& filename, PDFEncryptInfo& info) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open PDF file" << std::endl;
        return false;
    }

    // Read entire file
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);
    
    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        std::cerr << "Error: Failed to read PDF file" << std::endl;
        return false;
    }

    // Verify PDF header
    if (size < 5 || memcmp(buffer.data(), "%PDF-", 5) != 0) {
        std::cerr << "Error: Not a valid PDF file" << std::endl;
        return false;
    }

    if (!extract_encryption_info(buffer.data(), size, info)) {
        std::cerr << "Error: Could not find encryption information" << std::endl;
        return false;
    }

    std::cout << "PDF encryption detected:" << std::endl;
    std::cout << "  Revision: " << info.revision << std::endl;
    std::cout << "  Key Length: " << info.length << " bits" << std::endl;
    if (info.revision >= 6) {
        std::cout << "  Encryption: AES-256" << std::endl
                  << "  Method: AESV3" << std::endl;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <password_list> <pdf_file>" << std::endl;
        return 1;
    }

    std::cout << "\nLoading password list..." << std::endl;

    // Read password list
    std::vector<std::string> passwords;
    {
        std::ifstream pass_file(argv[1]);
        if (!pass_file) {
            std::cerr << "Error: Cannot open password list file: " << argv[1] << std::endl;
            return 1;
        }

        std::string line;
        while (std::getline(pass_file, line)) {
            if (!line.empty()) {
                passwords.push_back(line);
            }
        }
    }

    if (passwords.empty()) {
        std::cerr << "Error: No passwords loaded from " << argv[1] << std::endl;
        return 1;
    }

    std::cout << "Loaded " << passwords.size() << " passwords" << std::endl;

    // Read PDF encryption info
    std::cout << "\nAnalyzing PDF file..." << std::endl;
    PDFEncryptInfo encrypt_info;
    if (!read_pdf_encrypt_info(argv[2], encrypt_info)) {
        return 1;
    }

    // Calculate threads and workload
    unsigned int thread_count = std::thread::hardware_concurrency();
    if (thread_count == 0) thread_count = 2;
    if (thread_count > 16) thread_count = 16; // Limit max threads
    
    std::cout << "\nStarting password cracking with " << thread_count << " threads" << std::endl;
    
    g_total_passwords = passwords.size();
    auto start_time = std::chrono::steady_clock::now();
    
    std::vector<std::thread> threads;
    size_t passwords_per_thread = passwords.size() / thread_count;
    
    // Create threads
    for (unsigned int i = 0; i < thread_count; ++i) {
        size_t start = i * passwords_per_thread;
        size_t end = (i == thread_count - 1) ? passwords.size() : start + passwords_per_thread;
        
        threads.emplace_back(try_passwords,
                           std::ref(passwords),
                           start,
                           end,
                           std::ref(encrypt_info));
    }

    // Wait for threads to finish
    for (auto& thread : threads) {
        thread.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    std::cout << "\n\nFinished in " << duration.count() << " seconds" << std::endl;

    // Report results
    if (g_password_found) {
        std::cout << "Password found: " << g_found_password << std::endl;
        return 0;
    } else {
        std::cout << "Password not found in the provided list" << std::endl;
        return 1;
    }
}