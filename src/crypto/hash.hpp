#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace crypto {

class Hash {
public:
    static std::string GenerateSHA512FromFile(const std::string& filePath);

private:
    static std::string toHex(const std::vector<uint8_t>& data);
};

}