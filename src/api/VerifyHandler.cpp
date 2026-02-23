#include "VerifyHandler.hpp"
#include "crypto/Verifier.hpp"

#include <Poco/Net/HTMLForm.h>
#include <Poco/Net/PartHandler.h>
#include <Poco/Net/MessageHeader.h>
#include <Poco/JSON/Object.h>
#include <Poco/StreamCopier.h>

#include <sstream>
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

// ─── PartHandler ─────────────────────────────────────────────────────────────

class VerifyMultiPartHandler : public Poco::Net::PartHandler {
public:
    std::map<std::string, std::vector<unsigned char>> files;

    void handlePart(const Poco::Net::MessageHeader& header, std::istream& stream) override {
        std::string disposition = header.get("Content-Disposition", "");
        std::string fieldName   = extractParam(disposition, "name");
        std::string fileName    = extractParam(disposition, "filename");

        if (!fileName.empty()) {
            std::vector<unsigned char> buffer;
            char c;
            while (stream.get(c)) {
                buffer.push_back(static_cast<unsigned char>(c));
            }
            files[fieldName] = std::move(buffer);
        }
    }

private:
    static std::string extractParam(const std::string& header, const std::string& param) {
        std::string key = param + "=\"";
        size_t pos = header.find(key);
        if (pos == std::string::npos) return "";
        pos += key.size();
        size_t end = header.find("\"", pos);
        if (end == std::string::npos) return "";
        return header.substr(pos, end - pos);
    }
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

static std::string writeTempFile(const std::vector<unsigned char>& data, const std::string& suffix) {
    std::string path = "/tmp/bry_api_verify_" + std::to_string(std::rand()) + suffix;
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Could not create temp file: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return path;
}

static void sendError(Poco::Net::HTTPServerResponse& response, int status, const std::string& message) {
    response.setStatus(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(status));
    response.setContentType("application/json");
    auto& out = response.send();
    out << "{\"error\": \"" << message << "\"}";
}

// ─── Handler ─────────────────────────────────────────────────────────────────

namespace api {

void VerifyHandler::handleRequest(
    Poco::Net::HTTPServerRequest& request,
    Poco::Net::HTTPServerResponse& response
) {
    if (request.getMethod() != Poco::Net::HTTPRequest::HTTP_POST) {
        sendError(response, 405, "Method Not Allowed. Use POST.");
        return;
    }

    std::string p7sFilePath;

    try {
        VerifyMultiPartHandler partHandler;
        Poco::Net::HTMLForm form(request, request.stream(), partHandler);

        if (partHandler.files.find("signature") == partHandler.files.end()) {
            sendError(response, 400, "Missing field: 'signature' (CMS attached .p7s file)");
            return;
        }

        p7sFilePath = writeTempFile(partHandler.files["signature"], ".p7s");

        crypto::VerificationResult result = crypto::Verifier::verifyP7s(p7sFilePath);

        Poco::JSON::Object json;

        json.set("status", result.isValid ? "VALIDO" : "INVALIDO");

        if (result.isValid) {
            Poco::JSON::Object infos;

            if (!result.signerCommonName.empty())
                infos.set("signerName", result.signerCommonName);

            if (!result.signingTime.empty())
                infos.set("signingTime", result.signingTime);

            if (!result.hashHex.empty())
                infos.set("documentHash", result.hashHex);

            if (!result.hashAlgorithm.empty())
                infos.set("hashAlgorithm", result.hashAlgorithm);

            json.set("infos", infos);
        }

        std::ostringstream oss;
        json.stringify(oss, 2);

        response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
        response.setContentType("application/json");
        auto& out = response.send();
        out << oss.str();

    } catch (const std::exception& e) {
        std::cerr << "[VerifyHandler] Error: " << e.what() << std::endl;
        sendError(response, 500, e.what());
    }

    if (!p7sFilePath.empty() && fs::exists(p7sFilePath)) fs::remove(p7sFilePath);
}

}