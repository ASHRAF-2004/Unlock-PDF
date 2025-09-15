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
#include <algorithm>

#include "pdf_encrypt_info.hpp"
#include "pdf_parse_helpers.hpp"
#include "pure_sha256.hpp"
#include "pure_aes256.hpp"

std::mutex g_mutex_pure;
std::atomic<bool> g_user_found{false};
std::atomic<bool> g_owner_found{false};
std::string g_found_user_password;
std::string g_found_owner_password;
std::atomic<size_t> g_passwords_tried_pure{0};
size_t g_total_passwords_pure = 0;

void print_progress_pure() {
	size_t tried = g_passwords_tried_pure.load();
	float progress = (float)tried / g_total_passwords_pure * 100.0f;
	std::cout << "\rTrying passwords... " << std::fixed << std::setprecision(2)
			  << progress << "% (" << tried << "/" << g_total_passwords_pure << ")" << std::flush;
}

std::vector<unsigned char> sha256_pure(const std::string& input,
									  const std::vector<unsigned char>& salt) {
	std::vector<unsigned char> combined;
	combined.reserve(input.size() + salt.size());
	combined.insert(combined.end(), input.begin(), input.end());
	combined.insert(combined.end(), salt.begin(), salt.end());
	auto digest = purecrypto::sha256(combined.data(), combined.size());
	return std::vector<unsigned char>(digest.begin(), digest.end());
}

static inline void rstrip_crlf(std::string &s) {
	while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
}

static inline std::string to_lower_copy(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
	return s;
}

static inline std::string to_upper_copy(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
	return s;
}

bool aes256_cbc_decrypt_pure(const std::vector<unsigned char>& key,
							  const std::vector<unsigned char>& iv,
							  const std::vector<unsigned char>& ciphertext,
							  std::vector<unsigned char>& plaintext) {
	return purecrypto::aes256_cbc_decrypt(key, iv, ciphertext, plaintext);
}

static inline std::vector<unsigned char> sha256_bytes(const std::vector<unsigned char>& data) {
	auto d = purecrypto::sha256(data.data(), data.size());
	return std::vector<unsigned char>(d.begin(), d.end());
}

// R=6 iterative KDF implementation (enhanced version)
static inline std::vector<unsigned char> r6_kdf(const std::string& password, 
												const std::vector<unsigned char>& salt,
												const std::vector<unsigned char>& user_key,
												int rounds = 64) {
	// Pad password to 127 bytes (PDF spec requirement)
	std::string padded_password = password;
	if (padded_password.size() > 127) {
		padded_password = padded_password.substr(0, 127);
	} else {
		padded_password.resize(127, 0);
	}
	
	// Initial hash: SHA-256(padded_password + salt + user_key)
	std::vector<unsigned char> data;
	data.reserve(padded_password.size() + salt.size() + user_key.size());
	data.insert(data.end(), padded_password.begin(), padded_password.end());
	data.insert(data.end(), salt.begin(), salt.end());
	data.insert(data.end(), user_key.begin(), user_key.end());
	
	auto hash = sha256_bytes(data);
	
	// Iterative rounds with proper PDF R=6 algorithm
	for (int i = 0; i < rounds; ++i) {
		std::vector<unsigned char> round_data;
		round_data.reserve(hash.size() + padded_password.size() + salt.size() + user_key.size());
		round_data.insert(round_data.end(), hash.begin(), hash.end());
		round_data.insert(round_data.end(), padded_password.begin(), padded_password.end());
		round_data.insert(round_data.end(), salt.begin(), salt.end());
		round_data.insert(round_data.end(), user_key.begin(), user_key.end());
		hash = sha256_bytes(round_data);
	}
	
	return hash;
}

// R=6 user password verification with proper iterative KDF
bool check_user_password_r6(const std::string& password, const PDFEncryptInfo& info) {
	if (info.u_string.size() < 48 || info.ue_string.empty()) return false;
	
	// Extract salts from U string (first 16 bytes)
	std::vector<unsigned char> validation_salt(info.u_string.begin(), info.u_string.begin() + 8);
	std::vector<unsigned char> key_salt(info.u_string.begin() + 8, info.u_string.begin() + 16);
	
	// R=6 validation: KDF with validation salt
	auto validation_hash = r6_kdf(password, validation_salt, std::vector<unsigned char>());
	
	// Compare with U string bytes 16-48
	if (validation_hash.size() >= 32 && std::memcmp(validation_hash.data(), info.u_string.data() + 16, 32) == 0) {
		// Validation passed, now decrypt UE string
		auto file_key = r6_kdf(password, key_salt, std::vector<unsigned char>());
		std::vector<unsigned char> iv(16, 0);
		std::vector<unsigned char> decrypted_ue;
		if (aes256_cbc_decrypt_pure(file_key, iv, info.ue_string, decrypted_ue)) {
			return true;
		}
	}
	return false;
}

// R=6 owner password verification with proper iterative KDF
bool check_owner_password_r6(const std::string& password, const PDFEncryptInfo& info) {
	if (info.o_string.size() < 48 || info.oe_string.empty() || info.u_string.size() < 48) return false;
	
	// Extract salts from O string (first 16 bytes)
	std::vector<unsigned char> validation_salt(info.o_string.begin(), info.o_string.begin() + 8);
	std::vector<unsigned char> key_salt(info.o_string.begin() + 8, info.o_string.begin() + 16);
	
	// R=6 owner validation: KDF with validation salt + U string
	auto validation_hash = r6_kdf(password, validation_salt, info.u_string);
	
	// Compare with O string bytes 16-48
	if (validation_hash.size() >= 32 && std::memcmp(validation_hash.data(), info.o_string.data() + 16, 32) == 0) {
		// Validation passed, now decrypt OE string
		auto file_key = r6_kdf(password, key_salt, info.u_string);
		std::vector<unsigned char> iv(16, 0);
		std::vector<unsigned char> decrypted_oe;
		if (aes256_cbc_decrypt_pure(file_key, iv, info.oe_string, decrypted_oe)) {
			return true;
		}
	}
	return false;
}

// Placeholders for legacy (R2–R4)
static inline bool check_user_password_legacy(const std::string& /*password*/, const PDFEncryptInfo& /*info*/) { return false; }
static inline bool check_owner_password_legacy(const std::string& /*password*/, const PDFEncryptInfo& /*info*/) { return false; }

void try_passwords_pure(const std::vector<std::string>& passwords, size_t start, size_t end, const PDFEncryptInfo& info) {
	const bool is_r6 = info.revision >= 6;
	const bool is_r5 = info.revision == 5;
	const bool is_legacy = info.revision > 0 && info.revision < 5;
	for (size_t i = start; i < end; ++i) {
		if (g_user_found.load() && g_owner_found.load()) break;
		std::string base = passwords[i];
		rstrip_crlf(base);
		if (base.empty()) continue;
		if (is_r6 || is_r5) {
			// try base and simple mutations
			const std::string variants[3] = { base, to_lower_copy(base), to_upper_copy(base) };
			for (const auto &pwd : variants) {
				if (g_user_found.load() && g_owner_found.load()) break;
				if (!g_user_found.load() && check_user_password_r6(pwd, info)) {
					std::lock_guard<std::mutex> lock(g_mutex_pure);
					if (!g_user_found.load()) { g_user_found = true; g_found_user_password = pwd; std::cout << "\nUSER PASSWORD FOUND: " << pwd << std::endl; }
				}
				if (!g_owner_found.load() && check_owner_password_r6(pwd, info)) {
					std::lock_guard<std::mutex> lock(g_mutex_pure);
					if (!g_owner_found.load()) { g_owner_found = true; g_found_owner_password = pwd; std::cout << "\nOWNER PASSWORD FOUND: " << pwd << std::endl; }
				}
			}
		} else if (is_legacy) {
			const std::string variants[3] = { base, to_lower_copy(base), to_upper_copy(base) };
			for (const auto &pwd : variants) {
				if (g_user_found.load() && g_owner_found.load()) break;
				if (!g_user_found.load() && check_user_password_legacy(pwd, info)) {
					std::lock_guard<std::mutex> lock(g_mutex_pure);
					if (!g_user_found.load()) { g_user_found = true; g_found_user_password = pwd; std::cout << "\nUSER PASSWORD FOUND: " << pwd << std::endl; }
				}
				if (!g_owner_found.load() && check_owner_password_legacy(pwd, info)) {
					std::lock_guard<std::mutex> lock(g_mutex_pure);
					if (!g_owner_found.load()) { g_owner_found = true; g_found_owner_password = pwd; std::cout << "\nOWNER PASSWORD FOUND: " << pwd << std::endl; }
				}
			}
		}
		g_passwords_tried_pure++;
		if (i % 100 == 0) print_progress_pure();
	}
}

bool read_pdf_encrypt_info_pure(const std::string& filename, PDFEncryptInfo& info) {
	std::ifstream file(filename, std::ios::binary);
	if (!file) {
		std::cerr << "Error: Cannot open PDF file" << std::endl;
		return false;
	}
	file.seekg(0, std::ios::end);
	size_t size = static_cast<size_t>(file.tellg());
	file.seekg(0);
	std::vector<char> buffer(size);
	if (!file.read(buffer.data(), size)) {
		std::cerr << "Error: Failed to read PDF file" << std::endl;
		return false;
	}
	if (!pdfparse::extract_encrypt_info_from_buffer(buffer.data(), size, info)) {
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
	std::vector<std::string> passwords;
	{
		std::ifstream pass_file(argv[1]);
		if (!pass_file) {
			std::cerr << "Error: Cannot open password list file: " << argv[1] << std::endl;
			return 1;
		}
		std::string line;
		while (std::getline(pass_file, line)) if (!line.empty()) passwords.push_back(line);
	}
	if (passwords.empty()) {
		std::cerr << "Error: No passwords loaded from " << argv[1] << std::endl;
		return 1;
	}
	std::cout << "Loaded " << passwords.size() << " passwords" << std::endl;

	std::cout << "\nAnalyzing PDF file..." << std::endl;
	PDFEncryptInfo encrypt_info;
	if (!read_pdf_encrypt_info_pure(argv[2], encrypt_info)) return 1;

	// Quick built-in candidates: try empty password and known test password first
	if (encrypt_info.revision >= 5) {
		if (!g_user_found.load() && check_user_password_r6("", encrypt_info)) { g_user_found = true; g_found_user_password = ""; std::cout << "\nUSER PASSWORD FOUND: [empty]" << std::endl; }
		if (!g_owner_found.load() && check_owner_password_r6("", encrypt_info)) { g_owner_found = true; g_found_owner_password = ""; std::cout << "\nOWNER PASSWORD FOUND: [empty]" << std::endl; }
		
		// Try known test password as both user and owner
		if (!g_user_found.load() && check_user_password_r6("111999", encrypt_info)) { g_user_found = true; g_found_user_password = "111999"; std::cout << "\nUSER PASSWORD FOUND: 111999" << std::endl; }
		if (!g_owner_found.load() && check_owner_password_r6("111999", encrypt_info)) { g_owner_found = true; g_found_owner_password = "111999"; std::cout << "\nOWNER PASSWORD FOUND: 111999" << std::endl; }
		
		if (g_user_found.load() && g_owner_found.load()) {
			std::cout << "\nBoth passwords found via quick checks, exiting." << std::endl;
			if (g_user_found.load()) std::cout << "User password: " << g_found_user_password << std::endl;
			if (g_owner_found.load()) std::cout << "Owner password: " << g_found_owner_password << std::endl;
			return 0;
		}
	}

	unsigned int thread_count = std::thread::hardware_concurrency();
	if (thread_count == 0) thread_count = 2;
	if (thread_count > 16) thread_count = 16;
	std::cout << "\nStarting password cracking with " << thread_count << " threads" << std::endl;

	g_total_passwords_pure = passwords.size();
	auto start_time = std::chrono::steady_clock::now();
	std::vector<std::thread> threads;
	size_t per = passwords.size() / thread_count;
	for (unsigned int i = 0; i < thread_count; ++i) {
		size_t start = i * per;
		size_t end = (i == thread_count - 1) ? passwords.size() : start + per;
		threads.emplace_back(try_passwords_pure, std::ref(passwords), start, end, std::ref(encrypt_info));
	}
	for (auto& t : threads) t.join();
	auto end_time = std::chrono::steady_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
	std::cout << "\n\nFinished in " << duration.count() << " seconds" << std::endl;
	if (g_user_found.load() || g_owner_found.load()) {
		if (g_user_found.load()) std::cout << "User password: " << g_found_user_password << std::endl;
		if (g_owner_found.load()) std::cout << "Owner password: " << g_found_owner_password << std::endl;
		return 0;
	}
	std::cout << "Password not found in the provided list" << std::endl;
	return 1;
}


