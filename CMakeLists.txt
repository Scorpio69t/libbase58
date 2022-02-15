cmake_minimum_required(VERSION 3.8)

project(base58)

add_library(base58 SHARED base58.c)

add_executable(base58-cli main.c base58.c)

target_link_libraries(base58-cli gcrypt)