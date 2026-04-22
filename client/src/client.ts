import net from 'net';
import protobuf from 'protobufjs';
import path from 'path';
import { generateRandomScalar, multiplyG, computeDH, xor32, uncompressPoint, compressPoint, pointAdd, modN } from './crypto_utils';

function printHex(name: string, buf: Buffer | Uint8Array) {
    console.log(`${name}: ${Buffer.from(buf).toString('hex')}`);
}

async function runClient() {
    const root = protobuf.loadSync(path.join(__dirname, '../../proto/mtacot.proto'));
    const CoTRequest = root.lookupType('mtacot.CoTRequest');
    const CoTResponse = root.lookupType('mtacot.CoTResponse');
    const OTExtension = root.lookupType('mtacot.OTExtension');

    const y = generateRandomScalar(); // 32 bytes
    printHex('Client multiplicative share (y)', y);

    const client = new net.Socket();
    client.connect(8080, '127.0.0.1', () => {
        console.log('Connected to server');
    });

    let buffer = Buffer.alloc(0);
    let expectedLength = -1;
    let phase = 1;

    // We store A_i points and b_scalars since we will need them later
    let A_points: Buffer[] = [];
    let b_scalars: Buffer[] = [];

    client.on('data', (data) => {
        buffer = Buffer.concat([buffer, data]);

        while (true) {
            if (expectedLength === -1) {
                if (buffer.length < 4) return;
                expectedLength = buffer.readUInt32LE(0);
                buffer = buffer.slice(4);
            }

            if (buffer.length < expectedLength) return;

            const msgData = buffer.slice(0, expectedLength);
            buffer = buffer.slice(expectedLength);
            expectedLength = -1; // Reset for next message

            if (phase === 1) {
                console.log('Received CoTRequest');
                const req = CoTRequest.decode(msgData) as any;
                A_points = req.A.map((a: Uint8Array) => Buffer.from(a));

                const B_points: Buffer[] = [];
                for (let i = 0; i < 256; i++) {
                    const b = generateRandomScalar();
                    b_scalars.push(b);
                    
                    const bit = (y[31 - Math.floor(i / 8)] >> (i % 8)) & 1;
                    let B_i: Buffer;

                    if (bit === 0) {
                        B_i = multiplyG(b);
                    } else {
                        const bG = multiplyG(b);
                        const p1 = uncompressPoint(bG);
                        const p2 = uncompressPoint(A_points[i]);
                        const sum = pointAdd(p1, p2);
                        B_i = compressPoint(sum);
                    }
                    B_points.push(B_i);
                }

                const resMsg = CoTResponse.create({ B: B_points });
                const resBuf = CoTResponse.encode(resMsg).finish();

                const lenBuf = Buffer.alloc(4);
                lenBuf.writeUInt32LE(resBuf.length, 0);
                client.write(Buffer.concat([lenBuf, resBuf]));
                console.log('Sent CoTResponse');
                phase = 2;
            } else if (phase === 2) {
                console.log('Received OTExtension');
                const ext = OTExtension.decode(msgData) as any;
                
                let V = 0n;

                for (let i = 0; i < 256; i++) {
                    const bit = (y[31 - Math.floor(i / 8)] >> (i % 8)) & 1;

                    // kc = (b_i * A_i)_x
                    const kc = computeDH(b_scalars[i], A_points[i]);

                    const ec = Buffer.from(bit === 0 ? ext.e0[i] : ext.e1[i]);
                    const mc = xor32(ec, kc);
                    const mc_big = BigInt('0x' + mc.toString('hex'));

                    // Calculate 2^i * m_c mod n
                    const pow2 = 2n ** BigInt(i);
                    const term = modN(pow2 * mc_big);
                    V = modN(V + term);
                }

                let vHex = V.toString(16);
                vHex = vHex.padStart(64, '0');
                printHex('Client additive share (V)', Buffer.from(vHex, 'hex'));
                
                client.destroy();
                return;
            }
        }
    });

    client.on('close', () => {
        console.log('Connection closed');
    });
}

runClient().catch(console.error);
