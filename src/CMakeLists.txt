add_library(crypto_lib STATIC 
    crypto/hash.cpp
)

target_include_directories(crypto_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(crypto_lib PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(bry_challenge_one main.cpp)
target_link_libraries(bry_challenge_one PRIVATE crypto_lib)