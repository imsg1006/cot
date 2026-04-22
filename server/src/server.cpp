#include "server.h"
#include "crypto_utils.h"
#include "mtacot.pb.h"
#include <pb_encode.h>
#include <pb_decode.h>
#include <boost/asio.hpp>
#include <iostream>
#include <iomanip>

using boost::asio::ip::tcp;

// A simple utility to print bytes as hex
void printHex(const std::string& name, const std::array<uint8_t, 32>& arr) {
    std::cout << name << ": ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)arr[i];
    }
    std::cout << std::dec << std::endl;
}

// Callbacks for nanopb repeated fields
bool encode_bytes_array(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {
    auto* vec = static_cast<std::vector<std::vector<uint8_t>>*>(*arg);
    for (const auto& item : *vec) {
        if (!pb_encode_tag_for_field(stream, field)) return false;
        if (!pb_encode_string(stream, item.data(), item.size())) return false;
    }
    return true;
}

bool decode_bytes_array(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    auto* vec = static_cast<std::vector<std::vector<uint8_t>>*>(*arg);
    std::vector<uint8_t> item(stream->bytes_left);
    if (!pb_read(stream, item.data(), stream->bytes_left)) return false;
    vec->push_back(item);
    return true;
}

void runServer(short port) {
    CryptoUtils::init();

    // Alice's multiplicative share
    auto x = CryptoUtils::generateRandomScalar();
    printHex("Server multiplicative share (x)", x);

    // Setup network
    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));
    std::cout << "Server listening on port " << port << "..." << std::endl;

    tcp::socket socket(io_context);
    acceptor.accept(socket);
    std::cout << "Client connected." << std::endl;

    // Phase 1: Server generates a_i and sends A_i to Bob
    std::vector<std::array<uint8_t, 32>> a_scalars;
    std::vector<std::vector<uint8_t>> A_points;
    for (int i = 0; i < 256; i++) {
        auto a = CryptoUtils::generateRandomScalar();
        a_scalars.push_back(a);
        auto A = CryptoUtils::multiplyG(a);
        A_points.push_back(std::vector<uint8_t>(A.begin(), A.end()));
    }

    mtacot_CoTRequest req_msg = mtacot_CoTRequest_init_default;
    req_msg.A.funcs.encode = encode_bytes_array;
    req_msg.A.arg = &A_points;

    std::vector<uint8_t> req_buffer(256 * 35); // Approx 256 * 35 bytes
    pb_ostream_t stream = pb_ostream_from_buffer(req_buffer.data(), req_buffer.size());
    if (!pb_encode(&stream, mtacot_CoTRequest_fields, &req_msg)) {
        std::cerr << "Failed to encode CoTRequest: " << PB_GET_ERROR(&stream) << std::endl;
        return;
    }
    
    // Send prefixed with length
    uint32_t req_len = stream.bytes_written;
    boost::asio::write(socket, boost::asio::buffer(&req_len, sizeof(req_len)));
    boost::asio::write(socket, boost::asio::buffer(req_buffer.data(), req_len));
    std::cout << "Sent CoTRequest with length " << req_len << std::endl;

    // Phase 2: Wait for Bob's response B_i
    uint32_t res_len = 0;
    boost::asio::read(socket, boost::asio::buffer(&res_len, sizeof(res_len)));
    std::vector<uint8_t> res_buffer(res_len);
    boost::asio::read(socket, boost::asio::buffer(res_buffer.data(), res_len));

    mtacot_CoTResponse res_msg = mtacot_CoTResponse_init_default;
    std::vector<std::vector<uint8_t>> B_points;
    res_msg.B.funcs.decode = decode_bytes_array;
    res_msg.B.arg = &B_points;

    pb_istream_t in_stream = pb_istream_from_buffer(res_buffer.data(), res_buffer.size());
    if (!pb_decode(&in_stream, mtacot_CoTResponse_fields, &res_msg)) {
        std::cerr << "Failed to decode CoTResponse" << std::endl;
        return;
    }
    std::cout << "Received CoTResponse" << std::endl;

    // Phase 3: Server computes (e0, e1) and sums U
    std::vector<std::vector<uint8_t>> e0_arr;
    std::vector<std::vector<uint8_t>> e1_arr;

    std::array<uint8_t, 32> U = {0};

    for (int i = 0; i < 256; i++) {
        // U_i
        auto Ui = CryptoUtils::generateRandomScalar();

        // Accumulate U = - sum(2^i * Ui)
        // Wait, calculate U_i * 2^i
        // To simplify, we shift inside the loop or just do bn operation
        // But trezor-crypto doesn't easily let us shift by 'i' over 256 width easily without manual.
        // It's easier to maintain a multiplier 2^i and multiply!
        std::array<uint8_t, 32> pow2 = {0};
        // Set bit i in pow2
        pow2[31 - (i / 8)] |= (1 << (i % 8));

        auto U_component = CryptoUtils::mulModN(Ui, pow2);
        auto U_accum = CryptoUtils::addModN(U, U_component);
        U = U_accum;

        // m0 and m1
        auto m0 = Ui;
        auto m1 = CryptoUtils::addModN(Ui, x);

        // Parse points
        std::array<uint8_t, 33> B_comp, A_comp;
        std::copy(B_points[i].begin(), B_points[i].end(), B_comp.begin());
        std::copy(A_points[i].begin(), A_points[i].end(), A_comp.begin());
        auto point_B = CryptoUtils::parsePoint(B_comp);
        auto point_A = CryptoUtils::parsePoint(A_comp);

        // k0 = a_i * B_i (X coord)
        auto k0 = CryptoUtils::multiplyPointAndGetX(a_scalars[i], point_B);

        // k1 = a_i * (B_i - A_i)
        auto diff = CryptoUtils::subtractPoints(point_B, point_A);
        auto k1 = CryptoUtils::multiplyPointAndGetX(a_scalars[i], diff);

        // Encrypt using XOR 
        auto e0 = CryptoUtils::xor32(m0, k0);
        auto e1 = CryptoUtils::xor32(m1, k1);

        e0_arr.push_back(std::vector<uint8_t>(e0.begin(), e0.end()));
        e1_arr.push_back(std::vector<uint8_t>(e1.begin(), e1.end()));
    }

    // Negate U as per assignment
    U = CryptoUtils::negateModN(U);

    // Send Phase 3 Extensions
    mtacot_OTExtension ext_msg = mtacot_OTExtension_init_default;
    ext_msg.e0.funcs.encode = encode_bytes_array;
    ext_msg.e0.arg = &e0_arr;
    ext_msg.e1.funcs.encode = encode_bytes_array;
    ext_msg.e1.arg = &e1_arr;

    std::vector<uint8_t> ext_buffer(256 * 68); 
    pb_ostream_t ext_stream = pb_ostream_from_buffer(ext_buffer.data(), ext_buffer.size());
    if (!pb_encode(&ext_stream, mtacot_OTExtension_fields, &ext_msg)) {
        std::cerr << "Failed to encode OTExtension" << std::endl;
        return;
    }

    uint32_t ext_len = ext_stream.bytes_written;
    boost::asio::write(socket, boost::asio::buffer(&ext_len, sizeof(ext_len)));
    boost::asio::write(socket, boost::asio::buffer(ext_buffer.data(), ext_len));
    std::cout << "Sent OTExtension" << std::endl;

    printHex("Server additive share (U)", U);
    
    // Done.
}
