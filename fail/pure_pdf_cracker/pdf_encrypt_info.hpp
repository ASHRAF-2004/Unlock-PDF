#pragma once

#include <vector>
#include <string>

struct PDFEncryptInfo {
	std::vector<unsigned char> id;
	std::vector<unsigned char> u_string;
	std::vector<unsigned char> o_string;
	std::vector<unsigned char> ue_string;
	std::vector<unsigned char> oe_string;
	std::vector<unsigned char> perms;
	int version = 0;
	int revision = 0;
	int length = 0;
	bool encrypted = false;
};


