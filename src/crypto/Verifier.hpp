#pragma once

#include <string>
#include <vector>

namespace crypto {

struct VerificationResult {
    bool isValid;
    std::string signerCommonName;
    std::string signingTime;
    std::string hashHex;
    std::string hashAlgorithm;
};

class Verifier {
public:
    static VerificationResult verifyP7s(const std::string& p7sFilePath);
};

}