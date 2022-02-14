cmake_minimum_required(VERSION 3.8)

project(base58)

add_library(base58 SHARED base58.cpp)

add_subdirectory(test)
