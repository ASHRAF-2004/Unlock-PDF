#pragma once

#include <vector>
#include <string>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include "pdf_encrypt_info.hpp"

namespace pdfparse {

inline std::vector<unsigned char> parse_pdf_string(const char* start) {
	std::vector<unsigned char> result;
	if (!start) return result;
	if (*start == '<') {
		start++;
		while (*start && *start != '>') {
			if (isxdigit(static_cast<unsigned char>(start[0])) && isxdigit(static_cast<unsigned char>(start[1]))) {
				char hex[3] = { start[0], start[1], 0 };
				result.push_back(static_cast<unsigned char>(strtol(hex, nullptr, 16)));
				start += 2;
			} else {
				start++;
			}
		}
	} else if (*start == '(') {
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
					default: result.push_back(static_cast<unsigned char>(*start));
				}
			} else {
				result.push_back(static_cast<unsigned char>(*start));
			}
			start++;
		}
	}
	return result;
}

inline const char* find_token(const char* haystack, size_t hay_size, const char* needle) {
	if (!haystack || !needle) return nullptr;
	const char* end = haystack + hay_size;
	const size_t nlen = std::strlen(needle);
	for (const char* p = haystack; p + nlen <= end; ++p) {
		if (std::memcmp(p, needle, nlen) == 0) return p;
	}
	return nullptr;
}

inline const char* skip_ws(const char* p, const char* end) {
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) ++p;
	return p;
}

inline int parse_int_after(const char* p, const char* end) {
	p = skip_ws(p, end);
	int sign = 1; if (p < end && *p == '-') { sign = -1; ++p; }
	int value = 0; while (p < end && std::isdigit(static_cast<unsigned char>(*p))) { value = value * 10 + (*p - '0'); ++p; }
	return value * sign;
}

inline void parse_string_after(const char* p, const char* end, std::vector<unsigned char>& out) {
	p = skip_ws(p, end);
	if (p >= end) return;
	if (*p == '<' || *p == '(') {
		out = parse_pdf_string(p);
	}
}

inline bool extract_encrypt_info_from_buffer(const char* buffer, size_t size, PDFEncryptInfo& info) {
	if (!buffer || size < 5 || std::memcmp(buffer, "%PDF-", 5) != 0) return false;
	const char* start = buffer;
	const char* end = buffer + size;
	const char* enc = find_token(start, size, "/Encrypt");
	if (!enc) return false;
	// Version and Revision
	const char* vpos = find_token(enc, static_cast<size_t>(end - enc), "/V ");
	const char* rpos = find_token(enc, static_cast<size_t>(end - enc), "/R ");
	if (vpos) info.version = parse_int_after(vpos + 3, end);
	if (rpos) info.revision = parse_int_after(rpos + 3, end);
	// U
	const char* upos = find_token(enc, static_cast<size_t>(end - enc), "/U");
	if (upos) parse_string_after(upos + 2, end, info.u_string);
	// O
	const char* opos = find_token(enc, static_cast<size_t>(end - enc), "/O");
	if (opos) parse_string_after(opos + 2, end, info.o_string);
	if (info.revision >= 6) {
		const char* uepos = find_token(enc, static_cast<size_t>(end - enc), "/UE");
		if (uepos) parse_string_after(uepos + 3, end, info.ue_string);
		const char* oepos = find_token(enc, static_cast<size_t>(end - enc), "/OE");
		if (oepos) parse_string_after(oepos + 3, end, info.oe_string);
		const char* permspos = find_token(enc, static_cast<size_t>(end - enc), "/Perms");
		if (permspos) parse_string_after(permspos + 6, end, info.perms);
		info.length = 256;
	}
	info.encrypted = true;
	return true;
}

} // namespace pdfparse


