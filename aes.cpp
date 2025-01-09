#include "aes.h"

AES::AES(const std::vector<uint8_t>& key) : key_(key) {
    if (key_.size() != 16) {
        throw std::invalid_argument("Key must be 16 bytes (128 bits).");
    }

    key_expansion();
}

std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t>& plaintext) {
    if (plaintext.size() % 16 != 0) {
        throw std::invalid_argument("Plaintext length must be a multiple of 16 bytes.");
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i += 16) {
        std::vector<uint8_t> block(plaintext.begin() + i, plaintext.begin() + i + 16);
        add_round_key(block, 0);
        for (size_t r = 1; r < 10; ++r) {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, r);
        }
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, 10);
        std::copy(block.begin(), block.end(), ciphertext.begin() + i);
    }

    return ciphertext;
}

std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t>& ciphertext) {
    if (ciphertext.size() % 16 != 0)   {
        throw std::invalid_argument("Ciphertext length must be a multiple of 16 bytes.");
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        std::vector<uint8_t> block(ciphertext.begin() + i, ciphertext.begin() + i + 16);
        add_round_key(block, 10);
        for (size_t r = 9; r > 0; --r) {
            inv_shift_rows(block);
            inv_sub_bytes(block);
            add_round_key(block, r);
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, 0);
        std::copy(block.begin(), block.end(), plaintext.begin() + i);
    }

    return plaintext;
}
