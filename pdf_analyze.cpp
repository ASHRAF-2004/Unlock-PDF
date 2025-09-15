#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstring>

void analyze_pdf(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << filename << std::endl;
        return;
    }

    // Get file size
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::cout << "PDF File Analysis for: " << filename << "\n";
    std::cout << "File size: " << file_size << " bytes\n\n";

    // Read entire file into memory for analysis
    std::vector<char> buffer(file_size);
    file.read(buffer.data(), file_size);

    // Verify PDF header
    if (file_size < 5 || memcmp(buffer.data(), "%PDF-", 5) != 0) {
        std::cerr << "Not a valid PDF file (missing %PDF- header)" << std::endl;
        return;
    }

    std::cout << "PDF Header: Found\n";
    std::cout << "PDF Version: " << buffer[5] << "." << buffer[7] << "\n\n";

    // Convert to string for easier searching
    std::string content(buffer.data(), file_size);

    // Look for encryption markers
    size_t pos;
    std::vector<std::pair<std::string, size_t>> findings;

    std::cout << "Searching for encryption markers...\n";

    const char* markers[] = {
        "/Encrypt",
        "/Filter/Standard",
        "/V 1",  // Encryption version
        "/V 2",
        "/V 4",
        "/V 5",
        "/R 2",  // Revision
        "/R 3",
        "/R 4",
        "/R 5",
        "/R 6",
        "/U (",   // User password
        "/O (",   // Owner password
        "/Length 40",  // RC4 40-bit
        "/Length 128", // RC4 or AES 128-bit
        "/CF",    // Crypt filters
        "/StmF",  // Stream filter
        "/StrF",  // String filter
        "/Identity",
        "/Encrypt\n",
        "/Encrypt\r",
        "/Encrypt "
    };

    bool found_encryption = false;
    bool found_standard_filter = false;
    bool found_user_pass = false;
    bool found_owner_pass = false;
    int encryption_version = 0;
    int encryption_revision = 0;

    std::cout << "\nFound markers:\n";

    for (const char* marker : markers) {
        size_t marker_pos = 0;
        while ((marker_pos = content.find(marker, marker_pos)) != std::string::npos) {
            found_encryption = true;
            
            // Get context around the marker
            size_t context_start = (marker_pos > 50) ? marker_pos - 50 : 0;
            size_t context_length = std::min(size_t(300), file_size - context_start);
            std::string context = content.substr(context_start, context_length);

            // Clean up context for display
            for (char& c : context) {
                if (c == '\r' || c == '\n') c = ' ';
                if (!isprint(c)) c = '.';
            }

            if (strstr(marker, "/Filter/Standard")) found_standard_filter = true;
            if (strstr(marker, "/U (")) found_user_pass = true;
            if (strstr(marker, "/O (")) found_owner_pass = true;
            
            if (strstr(marker, "/V ")) {
                encryption_version = atoi(marker + 3);
            }
            if (strstr(marker, "/R ")) {
                encryption_revision = atoi(marker + 3);
            }

            std::cout << "\nMarker '" << marker << "' at offset " << marker_pos << ":\n";
            std::cout << "Context: " << context << "\n";
            
            marker_pos += strlen(marker);
        }
    }

    std::cout << "\nEncryption Analysis Summary:\n";
    std::cout << "-----------------------------\n";

    if (!found_encryption) {
        std::cout << "No encryption markers found - file appears to be unencrypted.\n";
    } else {
        std::cout << "Encryption markers found:\n";
        if (found_standard_filter) {
            std::cout << "- Standard PDF encryption detected\n";
            if (encryption_version > 0) {
                std::cout << "- Encryption version: " << encryption_version << "\n";
            }
            if (encryption_revision > 0) {
                std::cout << "- Encryption revision: " << encryption_revision << "\n";
            }
            if (found_user_pass || found_owner_pass) {
                std::cout << "- Password protection confirmed:\n";
                std::cout << "  * User password: " << (found_user_pass ? "Present" : "Not found") << "\n";
                std::cout << "  * Owner password: " << (found_owner_pass ? "Present" : "Not found") << "\n";
            }
        }
    }

    // Search for compressed objects that might contain encryption data
    std::cout << "\nSearching for compressed objects...\n";
    
    const char* stream_start = nullptr;
    pos = 0;
    while ((pos = content.find("stream\n", pos)) != std::string::npos || 
           (pos = content.find("stream\r", pos)) != std::string::npos) {
        size_t endstream = content.find("endstream", pos);
        if (endstream != std::string::npos) {
            size_t stream_length = endstream - pos - 7;
            if (stream_length > 0 && stream_length < 1000) {  // Only show small streams
                std::cout << "Found stream at offset " << pos << " (length: " << stream_length << ")\n";
                
                // Show a bit of the stream content (first 50 bytes)
                std::cout << "Stream preview: ";
                for (size_t i = pos + 7; i < pos + 57 && i < endstream; ++i) {
                    char c = content[i];
                    if (isprint(c)) std::cout << c;
                    else std::cout << '.';
                }
                std::cout << "\n";
            }
        }
        pos++;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pdf_file>\n";
        std::cerr << "This tool analyzes PDF structure and encryption\n";
        return 1;
    }

    analyze_pdf(argv[1]);
    return 0;
}