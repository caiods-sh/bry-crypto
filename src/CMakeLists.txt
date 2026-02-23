add_library(crypto_lib STATIC 
    crypto/Hash.cpp
    crypto/Pkcs12Loader.cpp
    crypto/Verifier.cpp
    crypto/Signer.cpp
)

target_include_directories(crypto_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(crypto_lib
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
)

add_executable(bry_challenge_one ch1.cpp)
target_link_libraries(
    bry_challenge_one
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        crypto_lib
)

add_executable(bry_challenge_two ch2.cpp)
target_link_libraries(
    bry_challenge_two
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        crypto_lib
)

add_executable(bry_challenge_tree ch3.cpp)
target_link_libraries(
    bry_challenge_tree
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        crypto_lib
)


add_executable(bry_api 
    api/SignatureHandler.cpp 
    api/VerifyHandler.cpp 
    api/RestServer.cpp
)

target_link_libraries(bry_api 
    PRIVATE 
        crypto_lib 
        Poco::Net 
        Poco::Util 
        Poco::Foundation
        OpenSSL::Crypto
)