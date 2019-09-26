// // see https://eprint.iacr.org/2015/1098.pdf
// // import MiniNero
// // import PaperWallet
// import * as _ from 'lodash';
// import ecurve from 'ecurve';
// import { keccak256 } from 'js-sha3';
// import { soliditySha3, bintohex } from './common';

// const ecparams = ecurve.getCurveByName('secp256k1');
// const { Point } = ecurve;
// const { BigInteger } = crypto;
// const hs = crypto.hmacSha256;
// const basePoint = ecparams.G;

// const EC = require('elliptic').ec;

// const ec = new EC('secp256k1');

// const hashToPointCN = (hexVal) => {
//     const u = BigInteger.fromHex(keccak256(hexVal)).mod(
//         BigInteger.fromHex(ec.p)
//     );
//     const A = ec.a;
//     ma = -1 * A % ec.q
//     ma2 = -1 * A * A % ec.q
//     sqrtm1 = ed25519.sqroot(-1)
//     d = ed25519.theD() // print(radix255(d))

//     w = (2 * u * u + 1) % q
//     xp = (w *  w - 2 * A * A * u * u) % q

//     // like sqrt (w / x) although may have to check signs..
//     // so, note that if a squareroot exists, then clearly a square exists..
//     rx = ed25519.expmod(w * ed25519.inv(xp),(q+3)/8,q)
//     // rx is ok.

//     x = rx * rx * (w * w - 2 * A * A * u * u) % q

//     y = (2 * u * u  + 1 - x) % q // w - x, if y is zero, then x = w

//     negative = False
//     if (y != 0):
//         y = (w + x) % q // checking if you got the negative square root.
//         if (y != 0) :
//             negative = True
//         else :
//             rx = rx * -1 * ed25519.sqroot(-2 * A * (A + 2) ) % q
//             negative = False
//     else :
//         // y was 0..
//         rx = (rx * -1 * ed25519.sqroot(2 * A * (A + 2) ) ) % q
//     if not negative:
//         rx = (rx * u) % q
//         z = (-2 * A * u * u)  % q
//         sign = 0
//     else:
//         z = -1 * A
//         x = x * sqrtm1 % q // ..
//         y = (w - x) % q
//         if (y != 0) :
//             rx = rx * ed25519.sqroot( -1 * sqrtm1 * A * (A + 2)) % q
//         else :
//             rx = rx * -1 * ed25519.sqroot( sqrtm1 * A * (A + 2)) % q
//         sign = 1
//     // setsign
//     if ( (rx % 2) != sign ):
//         rx =  - (rx) % q
//     rz = (z + w) % q
//     ry = (z - w) % q
//     rx = rx * rz % q

//     P = ed25519ietf.point_compress([rx, ry, rz])
//     P8 = mul8(P)
//     toPointCheck(P)
//     return P8
// }

// // export const keyVector = (rows) => _.fill(rows, null);

// export const keyImage = (x, rows) => {
//     const HP = [];
//     const KeyImage = [];
//     for (let i = 0; i < rows; i++) {
//         HP[i] = BigInteger.fromBuffer(hs(basePoint.multiply(BigInteger.fromHex(x[i]))));
//         KeyImage[i] = HP[i].multiply(BigInteger.fromHex(x[i]));
//     }

//     return KeyImage;
// };

// const _generateRandomPoints = utxoLength => _.fill(Array(utxoLength), () => ec.genKeyPair());

// const hashToPoint = eccPoint => {
//     const hashedPoint = keccak256(eccPoint.getEncoded(true).toString('hex'));

//     Point.decodeFrom(ecparams, hashedPoint);
// }
// const UTXO_RING_SIZE = 11;
// /**
//  * Using MLSAG technique to apply ring-signature for spending utxos
//  * base on a group 11 utxos
//  * Notice that MLSAG in tomo using stealth address as public key in ringCT (Pj)
//  * @param {string} privSpendKey of current wallet
//  * @param {utxo array} utxos list utxo, refer src/utxo.js for more detail about data structure
//  * @param {buffer} message Message that got signed
//  * @param {number} index Index of real spended utxo
//  */
// export const MLSAGSign = (privSpendKey, utxos, message, index) => {
//     // Prepare key and random factors
//     const L = []; // list of keyvectors? except it's indexed by cols... it's kind of internal actually
//     const R = [];
//     const pubKeys = [];
//     // generate random public key Point
//     const s = _generateRandomPoints(UTXO_RING_SIZE);
//     // create hash of all Pj (stealth address)
//     const Pi = _.map(utxos, (utxo) => {
//         const point = ecparams.pointFromX(parseInt(utxo.pubkeyYBit) % 2 === 1,
//             BigInteger(utxo.pubkeyX));
//         // pubKeys.push(common.bintohex(point.getEncoded(true)));
//         return point;
//     });

//     const privKeyBN = BigInteger.fromHex(privSpendKey);
//     const I = hashToPoint(
//         basePoint.multiply(privKeyBN),
//     ).multiply(privKeyBN);

//     // Sign the message
//     const c = [];
//     const alpha = BigInteger.fromHex(crypto.randomHex(32));
//     L[index] = basePoint.multiply(alpha);
//     R[index] = hashToPoint(
//         basePoint.multiply(privKeyBN),
//     ).multiply(alpha);
//     c[index+1] = soliditySha3(
//         bintohex(bconcat([
//             message,
//             L[index].getEncoded(false),
//             R[index].getEncoded(false),
//         ])),
//     );

//     for (let i = 0; i < utxos.length; i++) {
//         if (i !== index) {
//             L[i] =
//         }
//     }
// };


// // export const MLSAG_Ver(pk, keyimage, c1, s ):
// //     rows = len(pk)
// //     cols = len(pk[0])
// //     print("verifying MLSAG sig of dimensions ",rows ,"x ", cols)
// //     L = [[None]*cols]
// //     R = [[None]*cols]
// //     pj = ''.join(pk[0])
// //     for i in range(1, rows):
// //       L.append([None] * cols)
// //       R.append([None] * cols)
// //       pj = pj + ''.join(pk[i])
// //     c= [None]*(cols+1) #you do an extra one, and then check the wrap around
// //     HP = [[MiniNero.hashToPoint_cn(i) for i in pk[0]]]
// //     for j in range(1, rows):
// //       HP.append([MiniNero.hashToPoint_cn(i) for i in pk[j]])
// //     c[0] = c1
// //     j = 0
// //     while j < cols:
// //       tohash = pj
// //       for i in range(0, rows):
// //         L[i][j] = MiniNero.addKeys(MiniNero.scalarmultBase(s[i][j]), MiniNero.scalarmultKey(pk[i][j], c[j]))
// //         R[i][j] = MiniNero.addKeys(MiniNero.scalarmultKey(HP[i][j], s[i][j]), MiniNero.scalarmultKey(keyimage[i], c[j]))
// //         tohash = tohash + L[i][j] + R[i][j]
// //       j = j + 1
// //       c[j] = MiniNero.cn_fast_hash(tohash)

// //     rv = (c[0] == c[cols])
// //     print("c", c)
// //     print("sig verifies?", rv)

// //     return rv
