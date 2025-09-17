#include "crypto/rc4.h"

#include <algorithm>

namespace unlock_pdf::crypto {

RC4::RC4() : state_(256) { initialize_state(); }

RC4::RC4(const std::vector<unsigned char>& key) : state_(256) {
    set_key(key);
}

void RC4::set_key(const std::vector<unsigned char>& key) {
    state_.resize(256);
    initialize_state();

    if (key.empty()) {
        return;
    }

    std::size_t j = 0;
    for (std::size_t i = 0; i < 256; ++i) {
        j = (j + state_[i] + key[i % key.size()]) % 256;
        std::swap(state_[i], state_[j]);
    }

    x_ = 0;
    y_ = 0;
}

void RC4::crypt(const unsigned char* input, unsigned char* output, std::size_t length) {
    for (std::size_t i = 0; i < length; ++i) {
        x_ = (x_ + 1) % 256;
        y_ = (y_ + state_[x_]) % 256;
        std::swap(state_[x_], state_[y_]);
        unsigned char key_stream = state_[(state_[x_] + state_[y_]) % 256];
        output[i] = input[i] ^ key_stream;
    }
}

void RC4::initialize_state() {
    for (std::size_t i = 0; i < 256; ++i) {
        state_[i] = static_cast<unsigned char>(i);
    }
    x_ = 0;
    y_ = 0;
}

}  // namespace unlock_pdf::crypto