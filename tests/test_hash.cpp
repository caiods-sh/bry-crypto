#include <gtest/gtest.h>
#include "crypto/hash.hpp"
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

static std::string createTempFile(const std::string& content) {
    std::string path = "/tmp/bry_test_hash_" + std::to_string(std::rand()) + ".txt";
    std::ofstream f(path, std::ios::binary);
    f << content;
    return path;
}


TEST(HashTest, HelloWorldProducesCorrectHash) {
    std::string path = createTempFile("hello world");
    std::string result = crypto::Hash::GenerateSHA512FromFile(path);
    fs::remove(path);

    EXPECT_EQ(result,
        "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f"
        "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
}


TEST(HashTest, NonExistentFileThrowsException) {
    EXPECT_THROW(
        crypto::Hash::GenerateSHA512FromFile("/tmp/not_existent_file.txt"),
        std::runtime_error
    );
}


TEST(HashTest, ResultIsLowercaseHex) {
    std::string path = createTempFile("bry test");
    std::string result = crypto::Hash::GenerateSHA512FromFile(path);
    fs::remove(path);

    for (char c : result) {
        EXPECT_TRUE(std::isxdigit(c) && !std::isupper(c))
            << "Char is not lowercase hex: " << c;
    }
}


TEST(HashTest, HashLengthIs128Characters) {
    std::string path = createTempFile("random content");
    std::string result = crypto::Hash::GenerateSHA512FromFile(path);
    fs::remove(path);

    EXPECT_EQ(result.size(), 128u);
}


TEST(HashTest, SameContentProducesSameHash) {
    std::string path1 = createTempFile("equal content");
    std::string path2 = createTempFile("equal content");

    std::string hash1 = crypto::Hash::GenerateSHA512FromFile(path1);
    std::string hash2 = crypto::Hash::GenerateSHA512FromFile(path2);

    fs::remove(path1);
    fs::remove(path2);

    EXPECT_EQ(hash1, hash2);
}


TEST(HashTest, DifferentContentProducesDifferentHash) {
    std::string path1 = createTempFile("Content A");
    std::string path2 = createTempFile("Content B");

    std::string hash1 = crypto::Hash::GenerateSHA512FromFile(path1);
    std::string hash2 = crypto::Hash::GenerateSHA512FromFile(path2);

    fs::remove(path1);
    fs::remove(path2);

    EXPECT_NE(hash1, hash2);
}