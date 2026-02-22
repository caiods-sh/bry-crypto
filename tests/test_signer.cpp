#include <gtest/gtest.h>
#include "crypto/Signer.hpp"
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

static std::string getResourcesDir() {
    fs::path base = PROJECT_SOURCE_DIR;
    auto path = base / "resources";
    return path.string();
}

static std::string getDocPath() {
    return getResourcesDir() + "/arquivos/test_doc.txt";
}

static std::string getPkcs12Path() {
    return getResourcesDir() + "/pkcs12/cert_unit_test.pfx";
}

static const std::string VALID_PASSWORD   = "devc++";
static const std::string INVALID_PASSWORD = "wrong_password";

TEST(SignerTest, NonExistentInputFileThrowsException) {
    if (!fs::exists(getPkcs12Path())) {
        GTEST_SKIP() << "Valid PKCS12 file not found. Adjust getPkcs12Path() for this environment.";
    }

    std::string fakeInput = "/tmp/non_existent_input_file.txt";
    std::string outputP7s = "/tmp/test_signature_nonexistent_input.p7s";

    EXPECT_THROW(
        crypto::Signer::signFileToP7s(fakeInput, getPkcs12Path(), VALID_PASSWORD, outputP7s),
        std::runtime_error
    );
}

TEST(SignerTest, InvalidPkcs12PasswordThrowsException) {
    if (!fs::exists(getPkcs12Path()) || !fs::exists(getDocPath())) {
        GTEST_SKIP() << "Required resources not found. Adjust getDocPath()/getPkcs12Path().";
    }

    std::string outputP7s = "/tmp/test_signature_invalid_password.p7s";

    EXPECT_THROW(
        crypto::Signer::signFileToP7s(getDocPath(), getPkcs12Path(), INVALID_PASSWORD, outputP7s),
        std::runtime_error
    );
}

TEST(SignerTest, ValidSignatureFileIsCreatedAndNonEmpty) {
    if (!fs::exists(getPkcs12Path()) || !fs::exists(getDocPath())) {
        GTEST_SKIP() << "Required resources not found. Adjust getDocPath()/getPkcs12Path().";
    }

    std::string outputP7s = "/tmp/test_signature_valid.p7s";

    if (fs::exists(outputP7s)) {
        fs::remove(outputP7s);
    }

    ASSERT_FALSE(fs::exists(outputP7s));

    ASSERT_NO_THROW(
        crypto::Signer::signFileToP7s(getDocPath(), getPkcs12Path(), VALID_PASSWORD, outputP7s)
    );

    ASSERT_TRUE(fs::exists(outputP7s));

    auto size = fs::file_size(outputP7s);
    EXPECT_GT(size, 0u);

    fs::remove(outputP7s);
}