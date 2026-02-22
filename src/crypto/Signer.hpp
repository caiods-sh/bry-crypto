#pragma once

#include <string>
#include "Pkcs12Loader.hpp"

namespace crypto {

class Signer {
public:
    static void signFileToP7s(const std::string& inputFilePath,
                              const std::string& pkcs12Path,
                              const std::string& pkcs12Password,
                              const std::string& outputP7sPath);
};

}