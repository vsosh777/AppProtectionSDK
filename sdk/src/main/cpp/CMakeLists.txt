cmake_minimum_required(VERSION 3.4.1)

project(app_protection)

add_library(app_protection SHARED
            memory_monitor.cpp
            app_protection_jni.cpp
            sha256.cpp)

find_library(log-lib log)

set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../openssl)
include_directories(${OPENSSL_ROOT_DIR}/include)

target_include_directories(app_protection PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_ROOT_DIR}/include)

target_link_libraries(app_protection
    ${log-lib}) 