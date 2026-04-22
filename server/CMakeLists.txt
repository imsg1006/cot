cmake_minimum_required(VERSION 3.14)
project(MTA_Server)

set(CMAKE_CXX_STANDARD 17)

include(FetchContent)

# Fetch trezor-crypto
FetchContent_Declare(
    trezor_crypto
    GIT_REPOSITORY https://github.com/trezor/trezor-crypto.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(trezor_crypto)

# Fetch nanopb
FetchContent_Declare(
    nanopb
    GIT_REPOSITORY https://github.com/nanopb/nanopb.git
    GIT_TAG        nanopb-0.4.8
)
FetchContent_MakeAvailable(nanopb)

# Protobuf generation for nanopb
set(NANOPB_PROTOC_PATH ${nanopb_SOURCE_DIR}/generator/protoc)
nanopb_generate_cpp(PROTO_SRCS PROTO_HDRS ${CMAKE_SOURCE_DIR}/../proto/mtacot.proto)

# Assuming Boost is installed on the target machine
find_package(Boost REQUIRED)

add_executable(server src/main.cpp src/server.cpp src/server.h src/crypto_utils.cpp src/crypto_utils.h ${PROTO_SRCS} ${PROTO_HDRS})

target_include_directories(server PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${Boost_INCLUDE_DIRS}
    ${trezor_crypto_SOURCE_DIR}
    ${nanopb_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(server PRIVATE
    trezor-crypto
    protobuf-nanopb
    Boost::boost
)
