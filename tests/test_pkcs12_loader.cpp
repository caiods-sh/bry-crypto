#include <gtest/gtest.h>
#include "crypto/Pkcs12Loader.hpp"
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

static std::string getResourcesDir() {
    fs::path base = PROJECT_SOURCE_DIR;
    auto path = base / "resources";
    return path.string();
}

static std::string getValidPkcs12Path() {
    return getResourcesDir() + "/pkcs12/cert_unit_test.pfx";
}

static const std::string VALID_PASSWORD   = "devc++";
static const std::string INVALID_PASSWORD = "wrong_password";

TEST(Pkcs12LoaderTest, NonExistentFileThrowsException) {
    std::string path = "/tmp/non_existent_pkcs12_file.p12";
    EXPECT_THROW(
        crypto::Pkcs12Loader::loadFromFile(path, VALID_PASSWORD),
        std::runtime_error
    );
}

TEST(Pkcs12LoaderTest, InvalidPasswordThrowsException) {
    if (!fs::exists(getValidPkcs12Path())) {
        GTEST_SKIP() << "Valid PKCS12 file not found. Adjust getValidPkcs12Path() for this environment.";
    }

    EXPECT_THROW(
        crypto::Pkcs12Loader::loadFromFile(getValidPkcs12Path(), INVALID_PASSWORD),
        std::runtime_error
    );
}

TEST(Pkcs12LoaderTest, ValidPkcs12LoadsKeyAndCertificate) {
    if (!fs::exists(getValidPkcs12Path())) {
        GTEST_SKIP() << "Valid PKCS12 file not found. Adjust getValidPkcs12Path() for this environment.";
    }

    crypto::Pkcs12Data data = crypto::Pkcs12Loader::loadFromFile(getValidPkcs12Path(), VALID_PASSWORD);

    EXPECT_NE(data.privateKey.get(), nullptr);
    EXPECT_NE(data.certificate.get(), nullptr);
}