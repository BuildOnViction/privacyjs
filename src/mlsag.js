
/**
 * Multilayered linkable spontaneous ad-hoc group signatures test
 * Generate key images and ring-signature from a group (size=11)
 */

import ecurve from 'ecurve';
import { keccak256 } from 'js-sha3';
import assert from 'assert';
import { BigInteger, hmacSha256 } from './crypto';
// import { soliditySha3, bintohex } from './common';

const ecparams = ecurve.getCurveByName('secp256k1');
// const { Point } = ecurve;
const hs = hmacSha256;
const basePoint = ecparams.G;

/**
 * Using secp256k1 to turn a public key to a point (utxo's one time address)
 * @param {string} hex public key in hex string
 * @returns {ecurve.Point} return a point in keccak256 ECC
 */
export const hashToPoint = (hex) => {
    assert(hex && hex.length === 66, 'Invalid hex input for hashtopoint');
    while (hex) {
        const newPoint = ecparams.G.multiply(BigInteger.fromHex(keccak256(hex)));
        if (ecparams.isOnCurve(newPoint)) {
            return newPoint;
        }
        hex = keccak256(hex);
    }
};

// export const keyVector = (rows) => _.fill(rows, null);

export const keyImage = (x, rows) => {
    const HP = [];
    const KeyImage = [];
    for (let i = 0; i < rows; i++) {
        HP[i] = BigInteger.fromBuffer(hs(basePoint.multiply(BigInteger.fromHex(x[i]))));
        KeyImage[i] = HP[i].multiply(BigInteger.fromHex(x[i]));
    }

    return KeyImage;
};

// const genPubKeylFromUTXO(utxos, index)

// const _generateRandomPoints = utxoLength => _.fill(Array(utxoLength), () => ec.genKeyPair());

export const UTXO_RING_SIZE = 11;

/**
 * Using MLSAG technique to apply ring-signature for spending utxos
 * base on a group 11 utxos
 * Notice that MLSAG in tomo using stealth address as public key in ringCT (Pj)
 * @param {string} privateKey - hs(ECDH) + private_spend_key, remember this is the ECDH of utxos[index]
 * @param {utxo array} utxos list utxo, refer src/utxo.js for more detail about data structure
 * @param {buffer} message Message that got signed
 * @param {number} index Index of real spended utxo
 */
// export const MLSAGSign = (privateKey, utxos, message, index) => {
//     const X = ;
//     const Hpj = ""; // hash to point of current public key of
//     const I = BiPrivKey.multiply(hashToPoint());

// };


// export const MLSAG_Ver(pk, keyimage, c1, s ):
//     rows = len(pk)
//     cols = len(pk[0])
//     print("verifying MLSAG sig of dimensions ",rows ,"x ", cols)
//     L = [[None]*cols]
//     R = [[None]*cols]
//     pj = ''.join(pk[0])
//     for i in range(1, rows):
//       L.append([None] * cols)
//       R.append([None] * cols)
//       pj = pj + ''.join(pk[i])
//     c= [None]*(cols+1) #you do an extra one, and then check the wrap around
//     HP = [[MiniNero.hashToPoint_cn(i) for i in pk[0]]]
//     for j in range(1, rows):
//       HP.append([MiniNero.hashToPoint_cn(i) for i in pk[j]])
//     c[0] = c1
//     j = 0
//     while j < cols:
//       tohash = pj
//       for i in range(0, rows):
//         L[i][j] = MiniNero.addKeys(MiniNero.scalarmultBase(s[i][j]), MiniNero.scalarmultKey(pk[i][j], c[j]))
//         R[i][j] = MiniNero.addKeys(MiniNero.scalarmultKey(HP[i][j], s[i][j]), MiniNero.scalarmultKey(keyimage[i], c[j]))
//         tohash = tohash + L[i][j] + R[i][j]
//       j = j + 1
//       c[j] = MiniNero.cn_fast_hash(tohash)

//     rv = (c[0] == c[cols])
//     print("c", c)
//     print("sig verifies?", rv)

//     return rv
