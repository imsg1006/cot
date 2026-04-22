import crypto from 'crypto';

const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

function mod(a: bigint, b: bigint): bigint {
    const res = a % b;
    return res >= 0n ? res : res + b;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
    let res = 1n;
    let b = base % m;
    let e = exp;
    while (e > 0n) {
        if (e % 2n === 1n) res = (res * b) % m;
        b = (b * b) % m;
        e /= 2n;
    }
    return res;
}

function modInverse(a: bigint, m: bigint): bigint {
    let m0 = m, y = 0n, x = 1n;
    if (m === 1n) return 0n;
    let currA = a;
    while (currA > 1n) {
        let q = currA / m0;
        let t = m0;
        m0 = currA % m0;
        currA = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    if (x < 0n) x += m;
    return x;
}

type Point = { x: bigint, y: bigint };

export function uncompressPoint(buffer: Uint8Array): Point {
    const prefix = buffer[0];
    const xHex = Buffer.from(buffer.slice(1)).toString('hex');
    const x = BigInt(`0x${xHex}`);
    
    // y^2 = x^3 + 7
    const x3_plus_7 = mod(x ** 3n + 7n, P);
    let y = modPow(x3_plus_7, (P + 1n) / 4n, P);
    
    if ((y % 2n) !== BigInt(prefix % 2)) {
        y = P - y;
    }
    
    return { x, y };
}

export function pointAdd(p1: Point, p2: Point): Point {
    if (p1.x === p2.x && p1.y === p2.y) {
        const lambda = mod((3n * p1.x * p1.x) * modInverse(2n * p1.y, P), P);
        const x3 = mod(lambda * lambda - 2n * p1.x, P);
        const y3 = mod(lambda * (p1.x - x3) - p1.y, P);
        return { x: x3, y: y3 };
    } else {
        const num = mod(p2.y - p1.y, P);
        const den = mod(p2.x - p1.x, P);
        const lambda = mod(num * modInverse(den, P), P);
        const x3 = mod(lambda * lambda - p1.x - p2.x, P);
        const y3 = mod(lambda * (p1.x - x3) - p1.y, P);
        return { x: x3, y: y3 };
    }
}

export function compressPoint(p: Point): Buffer {
    const prefix = p.y % 2n === 0n ? 0x02 : 0x03;
    let xHex = p.x.toString(16);
    xHex = xHex.padStart(64, '0');
    return Buffer.concat([Buffer.from([prefix]), Buffer.from(xHex, 'hex')]);
}

export function generateRandomScalar(): Buffer {
    let scalar: Buffer;
    do {
        scalar = crypto.randomBytes(32);
    } while (BigInt('0x' + scalar.toString('hex')) >= N || BigInt('0x' + scalar.toString('hex')) === 0n);
    return scalar;
}

export function multiplyG(scalar: Buffer): Buffer {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(scalar);
    return ecdh.getPublicKey(null, 'compressed');
}

export function computeDH(scalar: Buffer, pubKey: Buffer): Buffer {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(scalar);
    // Returns 32 bytes X-coordinate (standard key derivation output without hashing if we just get secret)
    return ecdh.computeSecret(pubKey); 
}

export function xor32(a: Buffer | Uint8Array, b: Buffer | Uint8Array): Buffer {
    const res = Buffer.alloc(32);
    for (let i = 0; i < 32; ++i) {
        res[i] = a[i] ^ b[i];
    }
    return res;
}

export function modN(a: bigint): bigint {
    return mod(a, N);
}
