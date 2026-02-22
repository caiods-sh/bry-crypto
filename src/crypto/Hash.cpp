#include "Hash.hpp"
#include <openssl/evp.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace crypto {

std::string Hash::GenerateSHA512FromFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) throw std::runtime_error("Could not open file: " + filePath);

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) throw std::runtime_error("Error creating OpenSSL context!");

    if (EVP_DigestInit_ex(context, EVP_sha512(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Error in DigestInit");
    }

    std::vector<char> buffer(4096);
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        if (EVP_DigestUpdate(context, buffer.data(), file.gcount()) != 1) {
            EVP_MD_CTX_free(context);
            throw std::runtime_error("Error in DigestUpdate");
        }
    }

    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context, hash.data(), &length) != 1) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Error in DigestFinal");
    }

    EVP_MD_CTX_free(context);
    hash.resize(length);
    return toHex(hash);
}

std::string Hash::toHex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : data) ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

}