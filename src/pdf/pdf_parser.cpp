#include "pdf/pdf_parser.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>

namespace unlock_pdf::pdf {
namespace {

void skip_whitespace_and_comments(const std::string& data, std::size_t& pos) {
    while (pos < data.size()) {
        unsigned char ch = static_cast<unsigned char>(data[pos]);
        if (std::isspace(ch)) {
            ++pos;
        } else if (data[pos] == '%') {
            while (pos < data.size() && data[pos] != '\n' && data[pos] != '\r') {
                ++pos;
            }
        } else {
            break;
        }
    }
}

bool parse_pdf_boolean(const std::string& data, std::size_t& pos, bool& value) {
    skip_whitespace_and_comments(data, pos);
    if (pos + 4 <= data.size() && data.compare(pos, 4, "true") == 0) {
        pos += 4;
        value = true;
        return true;
    }
    if (pos + 5 <= data.size() && data.compare(pos, 5, "false") == 0) {
        pos += 5;
        value = false;
        return true;
    }
    return false;
}

int parse_pdf_int(const std::string& data, std::size_t& pos) {
    skip_whitespace_and_comments(data, pos);
    if (pos >= data.size()) {
        return 0;
    }

    bool negative = false;
    if (data[pos] == '+') {
        ++pos;
    } else if (data[pos] == '-') {
        negative = true;
        ++pos;
    }

    int value = 0;
    while (pos < data.size() && std::isdigit(static_cast<unsigned char>(data[pos]))) {
        value = value * 10 + (data[pos] - '0');
        ++pos;
    }
    return negative ? -value : value;
}

int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

std::string parse_pdf_name(const std::string& data, std::size_t& pos) {
    std::string name;
    while (pos < data.size()) {
        char ch = data[pos];
        if (std::isspace(static_cast<unsigned char>(ch)) || ch == '/' || ch == '<' || ch == '>' ||
            ch == '[' || ch == ']' || ch == '(' || ch == ')') {
            break;
        }
        if (ch == '#') {
            if (pos + 2 < data.size()) {
                int high = hex_value(data[pos + 1]);
                int low = hex_value(data[pos + 2]);
                if (high >= 0 && low >= 0) {
                    name.push_back(static_cast<char>((high << 4) | low));
                    pos += 3;
                    continue;
                }
            }
            ++pos;
        } else {
            name.push_back(ch);
            ++pos;
        }
    }
    return name;
}

std::vector<unsigned char> parse_pdf_hex_string(const std::string& data, std::size_t& pos) {
    std::vector<unsigned char> result;
    if (pos >= data.size() || data[pos] != '<') {
        return result;
    }
    ++pos;

    std::string hex;
    while (pos < data.size() && data[pos] != '>') {
        if (!std::isspace(static_cast<unsigned char>(data[pos]))) {
            hex.push_back(data[pos]);
        }
        ++pos;
    }
    if (pos < data.size() && data[pos] == '>') {
        ++pos;
    }

    if (hex.empty()) {
        return result;
    }

    if (hex.size() % 2 == 1) {
        hex.push_back('0');
    }

    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        int high = hex_value(hex[i]);
        int low = hex_value(hex[i + 1]);
        if (high >= 0 && low >= 0) {
            result.push_back(static_cast<unsigned char>((high << 4) | low));
        }
    }

    return result;
}

std::vector<unsigned char> parse_pdf_literal_string(const std::string& data, std::size_t& pos) {
    std::vector<unsigned char> result;
    if (pos >= data.size() || data[pos] != '(') {
        return result;
    }
    ++pos;

    int depth = 1;
    while (pos < data.size() && depth > 0) {
        char ch = data[pos++];
        if (ch == '\\') {
            if (pos >= data.size()) {
                break;
            }
            char next = data[pos++];
            switch (next) {
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case '(': result.push_back('('); break;
                case ')': result.push_back(')'); break;
                case '\\': result.push_back('\\'); break;
                case '\r':
                    if (pos < data.size() && data[pos] == '\n') {
                        ++pos;
                    }
                    break;
                case '\n':
                    break;
                default:
                    if (next >= '0' && next <= '7') {
                        std::string digits(1, next);
                        for (int i = 0; i < 2 && pos < data.size(); ++i) {
                            char digit = data[pos];
                            if (digit >= '0' && digit <= '7') {
                                digits.push_back(digit);
                                ++pos;
                            } else {
                                break;
                            }
                        }
                        char value = static_cast<char>(std::stoi(digits, nullptr, 8));
                        result.push_back(static_cast<unsigned char>(value));
                    } else {
                        result.push_back(static_cast<unsigned char>(next));
                    }
                    break;
            }
        } else if (ch == '(') {
            result.push_back('(');
            ++depth;
        } else if (ch == ')') {
            --depth;
            if (depth > 0) {
                result.push_back(')');
            }
        } else {
            result.push_back(static_cast<unsigned char>(ch));
        }
    }

    return result;
}

std::vector<unsigned char> parse_pdf_string_object(const std::string& data, std::size_t& pos) {
    if (pos >= data.size()) {
        return {};
    }

    if (data[pos] == '<') {
        if (pos + 1 < data.size() && data[pos + 1] == '<') {
            return {};
        }
        return parse_pdf_hex_string(data, pos);
    }

    if (data[pos] == '(') {
        return parse_pdf_literal_string(data, pos);
    }

    while (pos < data.size() && !std::isspace(static_cast<unsigned char>(data[pos])) && data[pos] != '/') {
        ++pos;
    }
    return {};
}

std::size_t find_dictionary_end(const std::string& data, std::size_t start) {
    int depth = 0;
    std::size_t pos = start;
    while (pos + 1 < data.size()) {
        if (data[pos] == '<' && data[pos + 1] == '<') {
            depth++;
            pos += 2;
            continue;
        }
        if (data[pos] == '>' && data[pos + 1] == '>') {
            depth--;
            pos += 2;
            if (depth == 0) {
                return pos;
            }
            continue;
        }
        if (data[pos] == '(') {
            ++pos;
            int level = 1;
            while (pos < data.size() && level > 0) {
                char ch = data[pos++];
                if (ch == '\\') {
                    if (pos < data.size()) {
                        ++pos;
                    }
                } else if (ch == '(') {
                    ++level;
                } else if (ch == ')') {
                    --level;
                }
            }
            continue;
        }
        if (data[pos] == '<') {
            ++pos;
            while (pos < data.size() && data[pos] != '>') {
                ++pos;
            }
            if (pos < data.size()) {
                ++pos;
            }
            continue;
        }
        ++pos;
    }
    return std::string::npos;
}

std::vector<unsigned char> extract_document_id(const std::string& data) {
    std::size_t pos = data.find("/ID");
    if (pos == std::string::npos) {
        return {};
    }
    pos += 3;
    skip_whitespace_and_comments(data, pos);
    if (pos >= data.size() || data[pos] != '[') {
        return {};
    }
    ++pos;
    skip_whitespace_and_comments(data, pos);
    if (pos >= data.size()) {
        return {};
    }
    return parse_pdf_string_object(data, pos);
}

bool extract_encryption_info(const std::string& data, PDFEncryptInfo& info) {
    std::size_t encrypt_pos = data.find("/Encrypt");
    if (encrypt_pos == std::string::npos) {
        std::cout << "No /Encrypt dictionary found" << std::endl;
        info = PDFEncryptInfo{};
        info.encrypted = false;
        return true;
    }

    std::size_t pos = encrypt_pos + 8;
    skip_whitespace_and_comments(data, pos);
    if (pos >= data.size() || !std::isdigit(static_cast<unsigned char>(data[pos]))) {
        std::cout << "Failed to parse /Encrypt reference" << std::endl;
        return false;
    }

    int obj_num = parse_pdf_int(data, pos);
    skip_whitespace_and_comments(data, pos);
    int gen_num = 0;
    if (pos < data.size() && std::isdigit(static_cast<unsigned char>(data[pos]))) {
        gen_num = parse_pdf_int(data, pos);
    }

    std::cout << "Found /Encrypt reference to object " << obj_num << " " << gen_num << std::endl;

    std::string obj_marker = std::to_string(obj_num) + " " + std::to_string(gen_num) + " obj";
    std::size_t obj_pos = data.find(obj_marker);
    if (obj_pos == std::string::npos) {
        std::cout << "Could not locate encryption object" << std::endl;
        return false;
    }

    std::size_t dict_start = data.find("<<", obj_pos);
    if (dict_start == std::string::npos) {
        std::cout << "Encryption object does not contain a dictionary" << std::endl;
        return false;
    }
    std::size_t dict_end = find_dictionary_end(data, dict_start);
    if (dict_end == std::string::npos) {
        std::cout << "Failed to parse encryption dictionary" << std::endl;
        return false;
    }

    std::cout << "Found encryption object. Content:" << std::endl;
    std::string snippet = data.substr(dict_start, std::min<std::size_t>(dict_end - dict_start, 200));
    for (char& ch : snippet) {
        if (ch == '\r' || ch == '\n') {
            ch = ' ';
        }
    }
    std::cout << snippet << std::endl;

    std::unordered_map<std::string, std::string> crypt_filter_methods;

    auto skip_pdf_object_in_range = [&](std::size_t& position, std::size_t limit) {
        skip_whitespace_and_comments(data, position);
        if (position >= limit) {
            return;
        }
        if (data[position] == '<') {
            if (position + 1 < data.size() && data[position + 1] == '<') {
                std::size_t nested_end = find_dictionary_end(data, position);
                if (nested_end == std::string::npos || nested_end > limit) {
                    position = limit;
                } else {
                    position = nested_end;
                }
            } else {
                parse_pdf_hex_string(data, position);
            }
            return;
        }
        if (data[position] == '(') {
            parse_pdf_literal_string(data, position);
            return;
        }
        if (data[position] == '[') {
            ++position;
            int depth = 1;
            while (position < limit && depth > 0) {
                skip_whitespace_and_comments(data, position);
                if (position >= limit) {
                    break;
                }
                char token = data[position];
                if (token == '[') {
                    ++depth;
                    ++position;
                } else if (token == ']') {
                    --depth;
                    ++position;
                } else if (token == '(') {
                    parse_pdf_literal_string(data, position);
                } else if (token == '<') {
                    if (position + 1 < data.size() && data[position + 1] == '<') {
                        std::size_t nested_end = find_dictionary_end(data, position);
                        if (nested_end == std::string::npos || nested_end > limit) {
                            position = limit;
                        } else {
                            position = nested_end;
                        }
                    } else {
                        parse_pdf_hex_string(data, position);
                    }
                } else {
                    ++position;
                }
            }
            return;
        }
        while (position < limit && !std::isspace(static_cast<unsigned char>(data[position])) &&
               data[position] != '/') {
            ++position;
        }
    };

    auto update_selected_crypt_filter = [&]() {
        if (crypt_filter_methods.empty()) {
            return;
        }

        auto pick_filter = [&](const std::string& name) -> bool {
            if (name.empty()) {
                return false;
            }
            auto it = crypt_filter_methods.find(name);
            if (it == crypt_filter_methods.end()) {
                return false;
            }
            info.crypt_filter = it->first;
            info.crypt_filter_method = it->second;
            return true;
        };

        if (pick_filter(info.stream_filter)) {
            return;
        }
        if (pick_filter(info.string_filter)) {
            return;
        }
        if (pick_filter(info.ef_filter)) {
            return;
        }

        if (!pick_filter("StdCF")) {
            info.crypt_filter = crypt_filter_methods.begin()->first;
            info.crypt_filter_method = crypt_filter_methods.begin()->second;
        }
    };

    pos = dict_start + 2;
    while (pos < dict_end) {
        skip_whitespace_and_comments(data, pos);
        if (pos >= dict_end) {
            break;
        }
        if (data[pos] != '/') {
            ++pos;
            continue;
        }
        ++pos;
        std::string key = parse_pdf_name(data, pos);
        skip_whitespace_and_comments(data, pos);

        if (key == "V") {
            info.version = parse_pdf_int(data, pos);
        } else if (key == "R") {
            info.revision = parse_pdf_int(data, pos);
        } else if (key == "Length") {
            info.length = parse_pdf_int(data, pos);
        } else if (key == "P") {
            info.permissions = parse_pdf_int(data, pos);
        } else if (key == "U") {
            info.u_string = parse_pdf_string_object(data, pos);
        } else if (key == "O") {
            info.o_string = parse_pdf_string_object(data, pos);
        } else if (key == "UE") {
            info.ue_string = parse_pdf_string_object(data, pos);
        } else if (key == "OE") {
            info.oe_string = parse_pdf_string_object(data, pos);
        } else if (key == "Perms") {
            info.perms = parse_pdf_string_object(data, pos);
        } else if (key == "Filter") {
            if (pos < dict_end && data[pos] == '/') {
                ++pos;
                info.filter = parse_pdf_name(data, pos);
            }
        } else if (key == "SubFilter") {
            if (pos < dict_end && data[pos] == '/') {
                ++pos;
                info.sub_filter = parse_pdf_name(data, pos);
            }
        } else if (key == "CF") {
            std::size_t cf_pos = pos;
            if (cf_pos < dict_end && data[cf_pos] == '<' && cf_pos + 1 < data.size() &&
                data[cf_pos + 1] == '<') {
                std::size_t cf_end = find_dictionary_end(data, cf_pos);
                if (cf_end == std::string::npos) {
                    pos = dict_end;
                    break;
                }
                cf_pos += 2;
                while (cf_pos < cf_end) {
                    skip_whitespace_and_comments(data, cf_pos);
                    if (cf_pos >= cf_end) {
                        break;
                    }
                    if (data[cf_pos] != '/') {
                        ++cf_pos;
                        continue;
                    }
                    ++cf_pos;
                    std::string filter_name = parse_pdf_name(data, cf_pos);
                    skip_whitespace_and_comments(data, cf_pos);
                    if (cf_pos >= cf_end) {
                        break;
                    }
                    std::size_t value_pos = cf_pos;
                    if (value_pos < cf_end && data[value_pos] == '<' && value_pos + 1 < data.size() &&
                        data[value_pos + 1] == '<') {
                        std::size_t filter_dict_end = find_dictionary_end(data, value_pos);
                        if (filter_dict_end == std::string::npos || filter_dict_end > cf_end) {
                            cf_pos = cf_end;
                            break;
                        }
                        value_pos += 2;
                        while (value_pos < filter_dict_end) {
                            skip_whitespace_and_comments(data, value_pos);
                            if (value_pos >= filter_dict_end) {
                                break;
                            }
                            if (data[value_pos] != '/') {
                                ++value_pos;
                                continue;
                            }
                            ++value_pos;
                            std::string inner_key = parse_pdf_name(data, value_pos);
                            skip_whitespace_and_comments(data, value_pos);
                            std::size_t inner_value_pos = value_pos;
                            if (inner_key == "CFM") {
                                std::string method;
                                if (inner_value_pos < filter_dict_end && data[inner_value_pos] == '/') {
                                    ++inner_value_pos;
                                    method = parse_pdf_name(data, inner_value_pos);
                                } else if (inner_value_pos < filter_dict_end &&
                                           data[inner_value_pos] == '(') {
                                    auto bytes = parse_pdf_literal_string(data, inner_value_pos);
                                    method.assign(bytes.begin(), bytes.end());
                                } else if (inner_value_pos < filter_dict_end &&
                                           data[inner_value_pos] == '<') {
                                    auto bytes = parse_pdf_hex_string(data, inner_value_pos);
                                    method.assign(bytes.begin(), bytes.end());
                                }
                                if (!method.empty()) {
                                    crypt_filter_methods[filter_name] = method;
                                }
                            }
                            skip_pdf_object_in_range(inner_value_pos, filter_dict_end);
                            value_pos = inner_value_pos;
                        }
                        cf_pos = filter_dict_end;
                    } else {
                        skip_pdf_object_in_range(value_pos, cf_end);
                        cf_pos = value_pos;
                    }
                }
                pos = cf_end;
            } else {
                skip_pdf_object_in_range(cf_pos, dict_end);
                pos = cf_pos;
            }
            update_selected_crypt_filter();
        } else if (key == "StmF") {
            if (pos < dict_end && data[pos] == '/') {
                ++pos;
                info.stream_filter = parse_pdf_name(data, pos);
            }
            update_selected_crypt_filter();
        } else if (key == "StrF") {
            if (pos < dict_end && data[pos] == '/') {
                ++pos;
                info.string_filter = parse_pdf_name(data, pos);
            }
            update_selected_crypt_filter();
        } else if (key == "EFF") {
            if (pos < dict_end && data[pos] == '/') {
                ++pos;
                info.ef_filter = parse_pdf_name(data, pos);
            }
        } else if (key == "EncryptMetadata") {
            bool value = info.encrypt_metadata;
            if (parse_pdf_boolean(data, pos, value)) {
                info.encrypt_metadata = value;
            }
        } else if (key == "Recipients") {
            info.has_recipients = true;
            if (pos < dict_end && data[pos] == '[') {
                ++pos;
                int depth = 1;
                while (pos < dict_end && depth > 0) {
                    if (data[pos] == '[') {
                        ++depth;
                        ++pos;
                    } else if (data[pos] == ']') {
                        --depth;
                        ++pos;
                    } else if (data[pos] == '<' && pos + 1 < data.size() && data[pos + 1] == '<') {
                        std::size_t nested = find_dictionary_end(data, pos);
                        if (nested == std::string::npos) {
                            pos = dict_end;
                        } else {
                            pos = nested;
                        }
                    } else if (data[pos] == '<') {
                        parse_pdf_hex_string(data, pos);
                    } else if (data[pos] == '(') {
                        parse_pdf_literal_string(data, pos);
                    } else {
                        ++pos;
                    }
                }
            } else if (pos < dict_end && data[pos] == '<') {
                parse_pdf_hex_string(data, pos);
            }
        } else {
            if (pos >= dict_end) {
                break;
            }
            char token = data[pos];
            if (token == '<' && pos + 1 < data.size() && data[pos + 1] == '<') {
                std::size_t nested_end = find_dictionary_end(data, pos);
                if (nested_end == std::string::npos) {
                    break;
                }
                pos = nested_end;
            } else if (token == '<') {
                parse_pdf_hex_string(data, pos);
            } else if (token == '(') {
                parse_pdf_literal_string(data, pos);
            } else if (token == '[') {
                ++pos;
                int depth = 1;
                while (pos < dict_end && depth > 0) {
                    if (data[pos] == '[') {
                        ++depth;
                        ++pos;
                    } else if (data[pos] == ']') {
                        --depth;
                        ++pos;
                    } else if (data[pos] == '(') {
                        parse_pdf_literal_string(data, pos);
                    } else if (data[pos] == '<' && pos + 1 < data.size() && data[pos + 1] == '<') {
                        std::size_t nested = find_dictionary_end(data, pos);
                        if (nested == std::string::npos) {
                            pos = dict_end;
                        } else {
                            pos = nested;
                        }
                    } else if (data[pos] == '<') {
                        parse_pdf_hex_string(data, pos);
                    } else {
                        ++pos;
                    }
                }
            } else {
                while (pos < dict_end && !std::isspace(static_cast<unsigned char>(data[pos])) && data[pos] != '/') {
                    ++pos;
                }
            }
        }
    }

    update_selected_crypt_filter();

    if (info.revision >= 5 && info.length == 0) {
        info.length = 256;
    }

    info.encrypted = true;
    return true;
}

void print_pdf_structure(const std::string& data) {
    std::cout << "\nAnalyzing PDF structure:" << std::endl;
    std::cout << "------------------------" << std::endl;

    struct KeywordRule {
        const char* token;
        bool require_word_boundaries;
    };

    const KeywordRule keywords[] = {
        {"/Encrypt", true}, {"obj", true},     {"endobj", true}, {"/Filter", true},
        {"/V ", false},     {"/R ", false},     {"/O", true},      {"/U", true},
        {"/Length", true},  {"/CF", true},      {"/StmF", true},   {"/StrF", true},
        {"/AESV3", true}};

    auto requires_boundary = [](char ch) {
        return std::isalnum(static_cast<unsigned char>(ch)) || ch == '_';
    };

    for (const auto& keyword : keywords) {
        std::size_t pos = 0;
        int count = 0;
        const std::size_t token_length = std::strlen(keyword.token);
        while ((pos = data.find(keyword.token, pos)) != std::string::npos) {
            if (keyword.require_word_boundaries) {
                bool prefix_ok = true;
                if (pos > 0) {
                    prefix_ok = !requires_boundary(data[pos - 1]);
                }
                bool suffix_ok = true;
                if (pos + token_length < data.size()) {
                    suffix_ok = !requires_boundary(data[pos + token_length]);
                }
                if (!prefix_ok || !suffix_ok) {
                    pos += token_length;
                    continue;
                }
            }

            if (count < 3) {
                std::size_t context_end = std::min(pos + static_cast<std::size_t>(50), data.size());
                std::string context = data.substr(pos, context_end - pos);
                for (char& ch : context) {
                    if (ch == '\r' || ch == '\n') {
                        ch = ' ';
                    }
                }
                std::cout << "Found '" << keyword.token << "' at offset " << pos << ": " << context
                          << std::endl;
            }
            ++count;
            pos += token_length;
        }
        if (count > 0) {
            std::cout << "Total occurrences of '" << keyword.token << "': " << count << std::endl;
        }
    }

    std::cout << "------------------------\n" << std::endl;
}

}  // namespace

bool read_pdf_encrypt_info(const std::string& filename, PDFEncryptInfo& info) {
    std::cout << "Opening PDF file: " << filename << std::endl;
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open PDF file" << std::endl;
        return false;
    }

    std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (data.size() < 5 || data.compare(0, 5, "%PDF-") != 0) {
        std::cerr << "Error: Not a valid PDF file" << std::endl;
        return false;
    }

    std::cout << "PDF file opened successfully" << std::endl;
    std::cout << "Checking PDF header..." << std::endl;
    std::cout << "Valid PDF header found" << std::endl;

    print_pdf_structure(data);

    if (!extract_encryption_info(data, info)) {
        std::cerr << "Error: Could not find encryption information" << std::endl;
        return false;
    }

    info.id = extract_document_id(data);

    std::cout << "PDF encryption detected:" << std::endl;
    std::cout << "  Version: " << info.version << std::endl;
    std::cout << "  Revision: " << info.revision << std::endl;
    if (info.length > 0) {
        std::cout << "  Key Length: " << info.length << " bits" << std::endl;
    }

    int effective_key_length = info.length;
    if (effective_key_length == 0) {
        if (info.revision >= 5) {
            effective_key_length = 256;
        } else if (info.version >= 4) {
            effective_key_length = 128;
        } else if (info.version >= 2) {
            effective_key_length = 40;
        } else if (info.version >= 1) {
            effective_key_length = 40;
        }
    }

    auto method_to_algorithm = [&](const std::string& method_value) {
        if (method_value == "AESV3") {
            return std::string("AES-256");
        }
        if (method_value == "AESV2") {
            if (effective_key_length >= 256) {
                return std::string("AES-256");
            }
            if (effective_key_length >= 192) {
                return std::string("AES-192");
            }
            if (effective_key_length >= 128) {
                return std::string("AES-128");
            }
            if (effective_key_length > 0) {
                return std::string("AES-") + std::to_string(effective_key_length);
            }
            return std::string("AES");
        }
        if (method_value == "V2") {
            if (effective_key_length > 0) {
                return std::string("RC4-") + std::to_string(effective_key_length);
            }
            return std::string("RC4");
        }
        if (method_value == "V1") {
            return std::string("RC4-40");
        }
        if (method_value == "Identity" || method_value == "None") {
            return std::string("No encryption");
        }
        return method_value;
    };

    std::string encryption_description;
    std::string method_description;

    if (!info.crypt_filter_method.empty()) {
        encryption_description = method_to_algorithm(info.crypt_filter_method);
        method_description = info.crypt_filter_method;
        if (!info.crypt_filter.empty()) {
            method_description += " (crypt filter: " + info.crypt_filter + ")";
        }
    } else {
        if (info.revision >= 6) {
            encryption_description = "AES-256";
            method_description = "AESV3";
        } else if (info.revision >= 5) {
            encryption_description = "AES-256";
            method_description = "Standard Security Handler R5";
        } else if (info.version >= 4) {
            if (effective_key_length >= 128) {
                encryption_description = "AES-128";
                method_description = "AESV2";
            } else {
                encryption_description = method_to_algorithm("V2");
                method_description = "V2";
            }
        } else if (info.version >= 2) {
            encryption_description = method_to_algorithm("V2");
            method_description = "V2";
        } else if (info.version >= 1) {
            encryption_description = "RC4-40";
            method_description = "V1";
        }
    }

    if (encryption_description.empty()) {
        encryption_description = "Unknown";
    }
    if (method_description.empty()) {
        method_description = "Unknown";
    }

    std::cout << "  Encryption: " << encryption_description << std::endl;
    std::cout << "  Method: " << method_description << std::endl;

    return true;
}

}  // namespace unlock_pdf::pdf