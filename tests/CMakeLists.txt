enable_testing()

add_executable(test_hash test_hash.cpp)

target_link_libraries(test_hash
    PRIVATE
    crypto_lib
    GTest::GTest
    GTest::Main
)

target_include_directories(test_hash PRIVATE ${CMAKE_SOURCE_DIR}/src)

include(GoogleTest)
gtest_discover_tests(test_hash)