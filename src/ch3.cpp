#include <iostream>
#include "crypto/Verifier.hpp"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <signature.p7s>" << std::endl;
        return 1;
    }

    try {
        auto res = crypto::Verifier::verifyP7s(argv[1]);

        std::cout << "--- Verification Result ---" << std::endl;
        std::cout << "Is Valid: " << (res.isValid ? "YES" : "NO") << std::endl;
        std::cout << "Signer:   " << res.signerCommonName << std::endl;
        std::cout << "Hash Alg: " << res.hashAlgorithm << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}