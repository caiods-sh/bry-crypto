#pragma once

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <string>
#include <memory>

namespace crypto {

struct Pkcs12Data {
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> privateKey;
    std::unique_ptr<X509, void(*)(X509*)> certificate;

    Pkcs12Data(EVP_PKEY* pkey, X509* cert)
        : privateKey(pkey, EVP_PKEY_free),
          certificate(cert, X509_free) {}
};

class Pkcs12Loader {
public:
    static Pkcs12Data loadFromFile(const std::string& filePath, const std::string& password);
};

}