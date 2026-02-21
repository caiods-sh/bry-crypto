#include <iostream>
#include "crypto/hash.hpp"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Use: " << argv[0] << " <file_path>" << std::endl;
        return 1;
    }

    try {
        std::string hash = crypto::Hash::GenerateSHA512FromFile(argv[1]);
        std::cout << "SHA-512: " << hash << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}