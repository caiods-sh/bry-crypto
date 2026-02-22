enable_testing()

# Hash
add_executable(test_hash test_hash.cpp)
target_link_libraries(test_hash
    PRIVATE
        crypto_lib
        GTest::GTest
        GTest::Main
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_include_directories(test_hash PRIVATE ${CMAKE_SOURCE_DIR}/src)

# P12Loader
add_executable(test_pkcs12_loader test_pkcs12_loader.cpp)
target_link_libraries(test_pkcs12_loader
    PRIVATE
        crypto_lib
        GTest::GTest
        GTest::Main
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_include_directories(test_pkcs12_loader PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_pkcs12_loader PRIVATE
    PROJECT_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

# SIGNER
add_executable(test_signer test_signer.cpp)
target_link_libraries(test_signer
    PRIVATE
        crypto_lib
        GTest::GTest
        GTest::Main
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_include_directories(test_signer PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_signer PRIVATE
    PROJECT_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

# Verifier
add_executable(test_verifier test_verifier.cpp)
target_link_libraries(test_verifier
    PRIVATE
        crypto_lib
        GTest::GTest
        GTest::Main
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_include_directories(test_verifier PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(test_verifier PRIVATE
    PROJECT_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)


include(GoogleTest)
gtest_discover_tests(test_hash)
gtest_discover_tests(test_pkcs12_loader)
gtest_discover_tests(test_signer)
gtest_discover_tests(test_verifier)