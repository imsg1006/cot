#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <cstdint>
#include <array>
#include "ecdsa.h"
#include "bignum.h"

class CryptoUtils {
public:
    static void init();
    
    // Generate 32 bytes random scalar securely
    static std::array<uint8_t, 32> generateRandomScalar();
    
    // Perform a.G and return compressed 33-byte point
    static std::array<uint8_t, 33> multiplyG(const std::array<uint8_t, 32>& scalar);
    
    // Read 33-byte compressed point into curve_point
    static curve_point parsePoint(const std::array<uint8_t, 33>& compPoint);
    
    // Serialize curve_point to 33-byte compressed
    static std::array<uint8_t, 33> serializePoint(const curve_point& p);

    // Negate a point (Y = -Y mod p)
    static void negatePoint(curve_point& p);
    
    // Perform a.P and return the abscissa (X-coord) as 32 bytes
    static std::array<uint8_t, 32> multiplyPointAndGetX(const std::array<uint8_t, 32>& scalar, const curve_point& p);
    
    // Point subtraction: B - A
    static curve_point subtractPoints(const curve_point& B, const curve_point& A);
    
    // Addition modular SECP256K1 order n
    static std::array<uint8_t, 32> addModN(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b);
    static std::array<uint8_t, 32> negateModN(const std::array<uint8_t, 32>& a);
    static std::array<uint8_t, 32> mulModN(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b);

    // XOR two 32-byte arrays
    static std::array<uint8_t, 32> xor32(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b);

    static const ecdsa_curve* curve;
};

#endif // CRYPTO_UTILS_H
