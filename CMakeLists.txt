cmake_minimum_required(VERSION 3.12)
project(des_try)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(des_try
        des.cpp
        encrypt_decrypt.h
        function.h
        read_file.h
        )
