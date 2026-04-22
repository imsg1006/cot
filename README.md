# MTA Protocol with Correlated Oblivious Transfer (CoT)

This project implements a secure Multi-Party Computation (MPC) system using the Multiplicative-to-Additive (MtA) protocol. It leverages Correlated Oblivious Transfer (CoT) to securely convert multiplicative shares into additive shares between a client and a server.

## Overview

The system architecture consists of:
*   **Server**: Implemented in C++ utilizing Boost.Asio for asynchronous TCP/IP networking, Trezor Crypto for secp256k1 elliptic curve operations, and Nanopb for lightweight Protocol Buffers parsing.
*   **Client**: Implemented in TypeScript/Node.js utilizing the native `crypto` module and `protobufjs`.
*   **Protocol**: Communication between the client and server is serialized using Protocol Buffers (`mtacot.proto`). Operations involve cryptographic operations on 32-byte random integers over the secp256k1 elliptic curve.

## Prerequisites

### Server
*   C++17 Compiler
*   CMake (>= 3.14)
*   Boost Libraries
*   *(Note: Trezor Crypto and Nanopb are fetched automatically via CMake)*

### Client
*   Node.js (>= 18)
*   npm or yarn

## Project Structure

*   `proto/mtacot.proto`: Protocol Buffers definition for the communication between client and server.
*   `server/`: C++ server implementation.
    *   `CMakeLists.txt`: Build configuration.
    *   `src/server.cpp`: Main server logic and Boost.Asio networking.
    *   `src/crypto_utils.cpp`: secp256k1 cryptographic primitives using Trezor Crypto.
*   `client/`: TypeScript client implementation.
    *   `package.json`: Node.js dependencies and scripts.
    *   `src/client.ts`: Main client logic and TCP connection handling.
    *   `src/crypto_utils.ts`: Cryptographic primitives for the client.

## Building and Running

### Server

1.  Navigate to the `server` directory:
    ```bash
    cd server
    ```
2.  Create a build directory and configure:
    ```bash
    mkdir build
    cd build
    cmake ..
    ```
3.  Build the server:
    ```bash
    cmake --build .
    ```
4.  Run the server:
    ```bash
    ./server
    ```

### Client

1.  Navigate to the `client` directory:
    ```bash
    cd client
    ```
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Generate the protobuf definitions:
    ```bash
    npm run build:proto
    ```
4.  Start the client:
    ```bash
    npm start
    ```

## Protocol Details

The protocol implements the Multiplicative-to-Additive (MtA) conversion. It ensures that two parties holding secret multiplicative shares (e.g., $a$ and $b$) can compute additive shares (e.g., $\alpha$ and $\beta$) such that $a \cdot b = \alpha + \beta$, without revealing their individual shares to each other. This is achieved using Correlated Oblivious Transfer over the secp256k1 curve.
