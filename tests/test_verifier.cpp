#include <gtest/gtest.h>
#include "crypto/Verifier.hpp"
#include "crypto/Signer.hpp"
#include <openssl/cms.h>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

// ─── Helpers ────────────────────────────────────────────────────────────────

static std::string getDocPath() {
    fs::path base = PROJECT_SOURCE_DIR;
    return (base / "resources" / "arquivos" / "doc.txt").string();
}

static std::string getPkcs12Path() {
    fs::path base = PROJECT_SOURCE_DIR;
    return (base / "resources" / "pkcs12" / "cert_unit_test.pfx").string();
}

static const std::string VALID_PASSWORD = "devc++";


static std::string generateValidP7s() {
    std::string outputPath = "/tmp/test_verifier_valid.p7s";

    if (!fs::exists(outputPath)) {
        crypto::Signer::signFileToP7s(getDocPath(), getPkcs12Path(), VALID_PASSWORD, outputPath);
    }

    return outputPath;
}

// Corrompe um .p7s alterando um byte no meio do arquivo.
static std::string generateCorruptedP7s() {
    std::string validPath   = generateValidP7s();
    std::string corruptPath = "/tmp/test_verifier_corrupted.p7s";

    BIO* in = BIO_new_file(validPath.c_str(), "rb");
    CMS_ContentInfo* cms = d2i_CMS_bio(in, nullptr);
    BIO_free(in);

    if (!cms) throw std::runtime_error("Failed to parse valid CMS for corruption test");

    ASN1_OCTET_STRING** pos = CMS_get0_content(cms);
    if (pos && *pos && (*pos)->data && (*pos)->length > 0) {
        (*pos)->data[(*pos)->length / 2] ^= 0xFF;
    }

    BIO* out = BIO_new_file(corruptPath.c_str(), "wb");
    i2d_CMS_bio(out, cms);
    BIO_free(out);

    CMS_ContentInfo_free(cms);

    return corruptPath;
}

// ─── Fixtures ────────────────────────────────────────────────────────────────

class VerifierTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!fs::exists(getPkcs12Path()) || !fs::exists(getDocPath())) {
            GTEST_SKIP() << "Required resources not found. Adjust getPkcs12Path()/getDocPath().";
        }
    }

    void TearDown() override {
        if (fs::exists("/tmp/test_verifier_valid.p7s"))     fs::remove("/tmp/test_verifier_valid.p7s");
        if (fs::exists("/tmp/test_verifier_corrupted.p7s")) fs::remove("/tmp/test_verifier_corrupted.p7s");
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

TEST_F(VerifierTest, NonExistentFileThrowsException) {
    EXPECT_THROW(
        crypto::Verifier::verifyP7s("/tmp/non_existent_signature.p7s"),
        std::runtime_error
    );
}

TEST_F(VerifierTest, ValidSignatureReturnsIsValidTrue) {
    std::string p7sPath = generateValidP7s();

    auto result = crypto::Verifier::verifyP7s(p7sPath);

    EXPECT_TRUE(result.isValid);
}

TEST_F(VerifierTest, CorruptedSignatureReturnsIsValidFalse) {
    std::string corruptedPath = generateCorruptedP7s();

    auto result = crypto::Verifier::verifyP7s(corruptedPath);

    EXPECT_FALSE(result.isValid);
}

TEST_F(VerifierTest, ValidSignatureReturnsNonEmptySignerCommonName) {
    std::string p7sPath = generateValidP7s();

    auto result = crypto::Verifier::verifyP7s(p7sPath);

    EXPECT_FALSE(result.signerCommonName.empty());
}

TEST_F(VerifierTest, ValidSignatureReturnsNonEmptyHashAlgorithm) {
    std::string p7sPath = generateValidP7s();

    auto result = crypto::Verifier::verifyP7s(p7sPath);

    EXPECT_FALSE(result.hashAlgorithm.empty());
}

TEST_F(VerifierTest, ValidSignatureHashAlgorithmIsSHA512) {
    std::string p7sPath = generateValidP7s();

    auto result = crypto::Verifier::verifyP7s(p7sPath);

    EXPECT_EQ(result.hashAlgorithm, "SHA512");
}