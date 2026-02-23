#include "SignatureHandler.hpp"
#include "crypto/Signer.hpp"

#include <Poco/Net/HTMLForm.h>
#include <Poco/Net/PartHandler.h>
#include <Poco/Net/MessageHeader.h>
#include <Poco/Base64Encoder.h>
#include <Poco/StreamCopier.h>

#include <sstream>
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <iostream>
#include <map>
#include <vector>

namespace fs = std::filesystem;

// ─── PartHandler ─────────────────────────────────────────────────────────────

class MultiPartHandler : public Poco::Net::PartHandler {
public:
    std::map<std::string, std::vector<unsigned char>> files;
    std::map<std::string, std::string> fields;

    ~MultiPartHandler() noexcept override = default;

    void handlePart(const Poco::Net::MessageHeader& header, std::istream& stream) override {
        std::string disposition = header.get("Content-Disposition", "");
        std::string fieldName = extractParam(disposition, "name");
        std::string fileName  = extractParam(disposition, "filename");

        if (!fileName.empty()) {
            std::vector<unsigned char> buffer;
            char c;
            while (stream.get(c)) {
                buffer.push_back(static_cast<unsigned char>(c));
            }
            files[fieldName] = std::move(buffer);
        } else {
            std::string value;
            Poco::StreamCopier::copyToString(stream, value);
            fields[fieldName] = value;
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
    std::string path = "/tmp/bry_api_" + std::to_string(std::rand()) + suffix;
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Could not create temp file: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return path;
}

static std::string encodeBase64(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    Poco::Base64Encoder encoder(oss);
    encoder.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    encoder.close();
    return oss.str();
}

static void sendError(Poco::Net::HTTPServerResponse& response, int status, const std::string& message) {
    response.setStatus(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(status));
    response.setContentType("application/json");
    auto& out = response.send();
    out << "{\"error\": \"" << message << "\"}";
}

// ─── Handler ─────────────────────────────────────────────────────────────────

namespace api {

void SignatureHandler::handleRequest(
    Poco::Net::HTTPServerRequest& request,
    Poco::Net::HTTPServerResponse& response
) {
    if (request.getMethod() != Poco::Net::HTTPRequest::HTTP_POST) {
        sendError(response, 405, "Method Not Allowed. Use POST.");
        return;
    }

    std::string inputFilePath;
    std::string pkcs12FilePath;
    std::string outputP7sPath;

    try {
        MultiPartHandler partHandler;
        Poco::Net::HTMLForm form(request, request.stream(), partHandler);

        if (partHandler.files.find("file") == partHandler.files.end()) {
            sendError(response, 400, "Missing field: 'file' (document to sign)");
            return;
        }
        if (partHandler.files.find("pkcs12") == partHandler.files.end()) {
            sendError(response, 400, "Missing field: 'pkcs12' (PKCS12 certificate file)");
            return;
        }
        if (!form.has("password")) {
            sendError(response, 400, "Missing field: 'password' (PKCS12 password)");
            return;
        }

        const std::string password = form.get("password");

        inputFilePath  = writeTempFile(partHandler.files["file"],   ".doc");
        pkcs12FilePath = writeTempFile(partHandler.files["pkcs12"], ".p12");
        outputP7sPath  = "/tmp/bry_api_signature_" + std::to_string(std::rand()) + ".p7s";

        crypto::Signer::signFileToP7s(inputFilePath, pkcs12FilePath, password, outputP7sPath);

        std::ifstream p7sFile(outputP7sPath, std::ios::binary);
        if (!p7sFile) throw std::runtime_error("Could not read generated signature file");

        std::vector<unsigned char> p7sBytes(
            (std::istreambuf_iterator<char>(p7sFile)),
            std::istreambuf_iterator<char>()
        );

        std::string base64Signature = encodeBase64(p7sBytes);

        response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
        response.setContentType("text/plain");
        auto& out = response.send();
        out << base64Signature;

    } catch (const std::exception& e) {
        std::cerr << "[SignatureHandler] Error: " << e.what() << std::endl;
        sendError(response, 500, e.what());
    }

    if (!inputFilePath.empty()  && fs::exists(inputFilePath))  fs::remove(inputFilePath);
    if (!pkcs12FilePath.empty() && fs::exists(pkcs12FilePath)) fs::remove(pkcs12FilePath);
    if (!outputP7sPath.empty()  && fs::exists(outputP7sPath))  fs::remove(outputP7sPath);
}

}