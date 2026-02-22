#include "Pkcs12Loader.hpp"
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace crypto {

Pkcs12Data Pkcs12Loader::loadFromFile(const std::string& filePath, const std::string& password) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open PKCS12 file: " + filePath);
    }

    std::vector<unsigned char> buffer(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    const unsigned char* p = buffer.data();
    PKCS12* p12 = d2i_PKCS12(nullptr, &p, static_cast<long>(buffer.size()));
    if (!p12) {
        throw std::runtime_error("Error parsing PKCS12 file");
    }

    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;

    if (!PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca)) {
        PKCS12_free(p12);
        throw std::runtime_error("Error parsing PKCS12 structure (invalid password or file)");
    }

    PKCS12_free(p12);

    if (ca) {
        sk_X509_pop_free(ca, X509_free);
    }

    if (!pkey || !cert) {
        if (pkey) EVP_PKEY_free(pkey);
        if (cert) X509_free(cert);
        throw std::runtime_error("PKCS12 does not contain both private key and certificate");
    }

    return Pkcs12Data(pkey, cert);
}

}