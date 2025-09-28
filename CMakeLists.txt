cmake_minimum_required(VERSION 3.16)
project(pdf_password_retriever LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(pdf_password_retriever
    src/main.cpp
    src/util/wordlist_generator.cpp
    src/pdf/pdf_parser.cpp
    src/pdf/pdf_cracker.cpp
    src/pdf/encryption/encryption_handler_registry.cpp
    src/pdf/encryption/standard_security_utils.cpp
    src/pdf/encryption/rc4_40_handler.cpp
    src/pdf/encryption/rc4_128_handler.cpp
    src/pdf/encryption/aes128_handler.cpp
    src/pdf/encryption/aes256_handler.cpp
    src/pdf/encryption/standard_r3_handler.cpp
    src/pdf/encryption/pki_handler.cpp
    src/pdf/encryption/password_handler.cpp
    src/pdf/encryption/open_handler.cpp
    src/pdf/encryption/owner_password_handler.cpp
    src/pdf/encryption/x509_handler.cpp
    src/crypto/aes.cpp
    src/crypto/md5.cpp
    src/crypto/rc4.cpp
    src/crypto/sha2.cpp)

target_include_directories(pdf_password_retriever PRIVATE include)

target_compile_definitions(pdf_password_retriever PRIVATE _CRT_SECURE_NO_WARNINGS)