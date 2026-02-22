#include "Signer.hpp"
#include "Pkcs12Loader.hpp"

#include <openssl/cms.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <stdexcept>

namespace crypto {

static void throwLastOpenSslError(const std::string& msg) {
    unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    throw std::runtime_error(msg + ": " + buf);
}

void Signer::signFileToP7s(const std::string& inputFilePath,
                           const std::string& pkcs12Path,
                           const std::string& pkcs12Password,
                           const std::string& outputP7sPath
    ) {
    // 1 - Primeiramente chamo a outra classe que processa o arquivo Pkcs12,
    //     retornando a chave privada e o certificado.
    Pkcs12Data pkcs12 = Pkcs12Loader::loadFromFile(pkcs12Path, pkcs12Password);


    // 2 - Depois leio o conteúdo do arquivo que será assinado
    std::ifstream file(inputFilePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open input file: " + inputFilePath);
    }

    std::vector<unsigned char> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    BIO* dataBio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
    if (!dataBio) throw std::runtime_error("Error creating BIO for input data");


    // 3 - Em seguida crio o CMS (attached, SHA-512, RSA)
    int flags = CMS_BINARY | CMS_PARTIAL;
    CMS_ContentInfo* cms = CMS_sign(nullptr, nullptr, nullptr, dataBio, flags);

    if (!cms) {
        BIO_free(dataBio);
        throwLastOpenSslError("Error creating CMS structure");
    }

    if (!CMS_add1_signer(cms, pkcs12.certificate.get(), pkcs12.privateKey.get(), EVP_sha512(), flags)) {
        CMS_ContentInfo_free(cms);
        BIO_free(dataBio);
        throwLastOpenSslError("Error adding signer with SHA-512");
    }

    if (!CMS_final(cms, dataBio, nullptr, flags)) {
        CMS_ContentInfo_free(cms);
        BIO_free(dataBio);
        throwLastOpenSslError("Error finalizing CMS signature");
    }


    // 4 - Por último gravo em arquivo .p7s em formato DER (binário)
    std::ofstream outFile(outputP7sPath, std::ios::binary);
    if (!outFile) {
        CMS_ContentInfo_free(cms);
        BIO_free(dataBio);
        throw std::runtime_error("Could not open output file: " + outputP7sPath);
    }

    BIO* outBio = BIO_new(BIO_s_mem());
    if (!outBio) {
        CMS_ContentInfo_free(cms);
        BIO_free(dataBio);
        throw std::runtime_error("Error creating BIO for output");
    }

    if (i2d_CMS_bio(outBio, cms) != 1) {
        BIO_free(outBio);
        CMS_ContentInfo_free(cms);
        BIO_free(dataBio);
        throwLastOpenSslError("Error writing CMS to BIO");
    }

    char buffer[4096];
    int readBytes = 0;
    while ((readBytes = BIO_read(outBio, buffer, sizeof(buffer))) > 0) {
        outFile.write(buffer, readBytes);
    }

    BIO_free(outBio);
    CMS_ContentInfo_free(cms);
    BIO_free(dataBio);
}

}