# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required (VERSION 2.6)
project (Pkcs11RunnersForProjectWycheproof)
include_directories(include)
file(GLOB SOURCES "src/*.cc")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g")

include(FindOpenSSL)

add_executable(Pkcs11RunnersForProjectWycheproof ${SOURCES})

target_link_libraries(Pkcs11RunnersForProjectWycheproof -ljansson)
target_link_libraries(Pkcs11RunnersForProjectWycheproof -ldl)
target_link_libraries(Pkcs11RunnersForProjectWycheproof ${OPENSSL_CRYPTO_LIBRARY})
