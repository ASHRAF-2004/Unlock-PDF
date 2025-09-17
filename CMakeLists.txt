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
    src/crypto/aes.cpp
    src/crypto/md5.cpp
    src/crypto/rc4.cpp
    src/crypto/sha2.cpp)

target_include_directories(pdf_password_retriever PRIVATE include)

target_compile_definitions(pdf_password_retriever PRIVATE _CRT_SECURE_NO_WARNINGS)