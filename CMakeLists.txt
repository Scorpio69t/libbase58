cmake_minimum_required(VERSION 3.8)

project(base58 VERSION 1.0)

add_library(base58 SHARED base58.c)
set_target_properties(base58 PROPERTIES PUBLIC_HEADER "base58.h")

add_executable(base58-cli main.c base58.c)

target_link_libraries(base58-cli gcrypt)

# 写入库的版本信息
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
        Base58ConfigVersion.cmake
        VERSION ${PACKAGE_VERSION}
        COMPATIBILITY AnyNewerVersion  # 表示该函数库向下兼容
        )

# 将库文件，可执行文件，头文件安装到指定目录    
install(TARGETS base58 base58-cli
    EXPORT Base58Targets
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include)

# 将库的相关信息输出为 Base58Targets.cmake，供find_package查找
install(EXPORT Base58Targets
        FILE Base58Targets.cmake
        NAMESPACE Base58::
        DESTINATION lib/cmake/Base58
        )

configure_file(Base58Config.cmake.in Base58Config.cmake @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/Base58Config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/Base58ConfigVersion.cmake"
            DESTINATION lib/cmake/Base58
            )