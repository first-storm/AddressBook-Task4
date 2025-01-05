cmake_minimum_required(VERSION 3.30)
project(project4_mylasthw C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)

if (NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found!")
endif()

message(STATUS "OpenSSL Include Directory: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")

find_path(JANSSON_INCLUDE_DIR jansson.h)
find_library(JANSSON_LIBRARY jansson)

if (NOT JANSSON_INCLUDE_DIR OR NOT JANSSON_LIBRARY)
    message(FATAL_ERROR "jansson not found!")
endif()

message(STATUS "Jansson Include Directory: ${JANSSON_INCLUDE_DIR}")
message(STATUS "Jansson Library: ${JANSSON_LIBRARY}")

include_directories(${OPENSSL_INCLUDE_DIR} ${JANSSON_INCLUDE_DIR})

add_executable(project4_mylasthw main.c
        contacts.c
        menu.c
        menu.h
        entry.c
        entry.h
        encryption.c
        encryption.h)

target_link_libraries(project4_mylasthw PRIVATE ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARY})
