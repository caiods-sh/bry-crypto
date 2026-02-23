#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Util/ServerApplication.h>
#include <iostream>
#include <vector>

#include "SignatureHandler.hpp"
#include "VerifyHandler.hpp"

using namespace Poco::Net;
using namespace Poco::Util;

class RequestHandlerFactory : public HTTPRequestHandlerFactory {
public:
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request) override {
        if (request.getURI() == "/signature/") 
            return new api::SignatureHandler();
        if (request.getURI() == "/verify/") 
            return new api::VerifyHandler();
        
        return nullptr;
    }
};

class RestServerApp : public ServerApplication {
protected:
    int main(const std::vector<std::string>& args) override {
        (void)args;
        unsigned short port = 8080;
        
        ServerSocket svs(port);
        HTTPServer srv(new RequestHandlerFactory(), svs, new HTTPServerParams());

        std::cout << "BRY API Server started on port " << port << std::endl;
        srv.start();
        
        waitForTerminationRequest();
        
        srv.stop();
        std::cout << "Server stopped." << std::endl;
        
        return Application::EXIT_OK;
    }
};

int main(int argc, char** argv) {
    RestServerApp app;
    return app.run(argc, argv);
}