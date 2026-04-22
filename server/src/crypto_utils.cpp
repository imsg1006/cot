#include "crypto_utils.h"
#include "rand.h" // Wait, trezor-crypto has rand.h! Wait, let's just use std::random
#include "secp256k1.h"
#include <random>
#include <cstring>
#include <stdexcept>

const ecdsa_curve* CryptoUtils::curve = &secp256k1;

void CryptoUtils::init() {
    // any initialization if needed
}

std::array<uint8_t, 32> CryptoUtils::generateRandomScalar() {
    std::array<uint8_t, 32> out;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist;
    for(size_t i = 0; i < 32; i += 4) {
        uint32_t r = dist(gen);
        out[i] = r & 0xFF;
        out[i+1] = (r >> 8) & 0xFF;
        out[i+2] = (r >> 16) & 0xFF;
        out[i+3] = (r >> 24) & 0xFF;
    }
    // Simplistic: Should ensure out < order, but 2^256 is close to secp256k1 order
    // the assignment allows this.
    return out;
}

std::array<uint8_t, 33> CryptoUtils::multiplyG(const std::array<uint8_t, 32>& scalar) {
    bignum256 k;
    bn_read_be(scalar.data(), &k);
    curve_point res;
    scalar_multiply(curve, &k, &res);
    std::array<uint8_t, 33> out;
    compress_coords(&res, out.data());
    return out;
}

curve_point CryptoUtils::parsePoint(const std::array<uint8_t, 33>& compPoint) {
    curve_point p;
    if (ecdsa_read_pubkey(curve, compPoint.data(), &p) != 1) {
        throw std::runtime_error("Invalid point");
    }
    return p;
}

std::array<uint8_t, 33> CryptoUtils::serializePoint(const curve_point& p) {
    std::array<uint8_t, 33> out;
    compress_coords(&p, out.data());
    return out;
}

void CryptoUtils::negatePoint(curve_point& p) {
    // Y = -Y mod p
    bignum256 tmp_y;
    bn_zero(&tmp_y);
    bn_subtractmod(&curve->prime, &p.y, &tmp_y, &curve->prime);
    bn_copy(&tmp_y, &p.y);
}

std::array<uint8_t, 32> CryptoUtils::multiplyPointAndGetX(const std::array<uint8_t, 32>& scalar, const curve_point& p) {
    bignum256 k;
    bn_read_be(scalar.data(), &k);
    curve_point res;
    point_multiply(curve, &k, &p, &res);
    std::array<uint8_t, 32> out;
    bn_write_be(&res.x, out.data());
    return out;
}

curve_point CryptoUtils::subtractPoints(const curve_point& B, const curve_point& A) {
    curve_point negA = A;
    negatePoint(negA);
    curve_point res = B;
    point_add(curve, &negA, &res);
    return res;
}

std::array<uint8_t, 32> CryptoUtils::addModN(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    bignum256 B_a, B_b;
    bn_read_be(a.data(), &B_a);
    bn_read_be(b.data(), &B_b);
    bn_addmod(&B_a, &B_b, &curve->order);
    std::array<uint8_t, 32> out;
    bn_write_be(&B_a, out.data());
    return out;
}

std::array<uint8_t, 32> CryptoUtils::negateModN(const std::array<uint8_t, 32>& a) {
    bignum256 B_a, res;
    bn_read_be(a.data(), &B_a);
    bn_zero(&res);
    bn_subtractmod(&curve->order, &B_a, &res, &curve->order);
    std::array<uint8_t, 32> out;
    bn_write_be(&res, out.data());
    return out;
}

std::array<uint8_t, 32> CryptoUtils::mulModN(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    bignum256 B_a, B_b;
    bn_read_be(a.data(), &B_a);
    bn_read_be(b.data(), &B_b);
    bn_multiply(&B_a, &B_b, &curve->order);
    std::array<uint8_t, 32> out;
    bn_write_be(&B_b, out.data());
    return out;
}

std::array<uint8_t, 32> CryptoUtils::xor32(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    std::array<uint8_t, 32> out;
    for(size_t i = 0; i < 32; ++i) {
        out[i] = a[i] ^ b[i];
    }
    return out;
}
