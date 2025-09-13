#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <input.pdf> <output.pdf> <password>\n";
        return 1;
    }

    std::string input = argv[1];
    std::string output = argv[2];
    std::string password = argv[3];

    std::string command = "qpdf --password=" + password + " --decrypt \"" + input + "\" \"" + output + "\"";
    int result = std::system(command.c_str());

    if (result != 0) {
        std::cerr << "Failed to decrypt PDF" << std::endl;
        return result;
    }

    std::cout << "Unlocked PDF saved to " << output << std::endl;
    return 0;
}
