#include <iostream>
#include "crypto/Signer.hpp"

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <doc_file> <p12_file> <p12_password>" << std::endl;
        return 1;
    }

    const std::string inputFile   = argv[1];
    const std::string pkcs12File  = argv[2];
    const std::string pkcs12Pass  = argv[3];
    const std::string outputP7s   = "signature.p7s";

    try {
        crypto::Signer::signFileToP7s(inputFile, pkcs12File, pkcs12Pass, outputP7s);
        std::cout << "Signature successfully generated at: " << outputP7s << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Signing error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}