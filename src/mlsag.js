
/**
 * Multilayered linkable spontaneous ad-hoc group signatures test
 * Generate key images and ring-signature from a group (size=11)
 */

import ecurve from 'ecurve';
import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';
import { BigInteger, randomHex } from './crypto';
import { fastHash, bconcat, hextobin } from './common';
// import { soliditySha3, bintohex } from './common';

const secp256k1 = ecurve.getCurveByName('secp256k1');
// const { Point } = ecurve;
// const hs = hmacSha256;
// const basePoint = secp256k1.G;

/**
 * Using secp256k1 to turn a public key to a point (utxo's one time address)
 * in reality we actually convert a Point to short-form encoded (publickey)
 * so the the input is ecurve.Point.getEncoded(false).toString('hex')
 * We also need to ignore the first two bit indicate the odd or even if needed
 * @param {string} hex public key in hex string
 * @returns {ecurve.Point} return a point in Secp256k1
 */
export const hashToPoint = (shortFormPoint) => {
    assert(shortFormPoint && shortFormPoint.length, 'Invalid input public key to hash');
    let hex = shortFormPoint.substring(2); // ignore first two bit
    while (hex) {
        const newPoint = secp256k1.G.multiply(BigInteger.fromHex(keccak256(hex)));
        if (secp256k1.isOnCurve(newPoint)) {
            return newPoint;
        }
        hex = keccak256(hex);
    }
};

/**
 * A hash function for real message plus two more ring parameters for noising data
 * this function return a value in secp256k1 prime field Zp
 * Use internal inside MLSAG only
 * @param {Buffer} message Real data we want to compress
 * @param {Buffer} Lj
 * @param {Buffer} Rj
 */
function hashRingCT(message, Lj, Rj) {
    return BigInteger.fromBuffer(
        keccak256(
            bconcat([
                message,
                Lj,
                Rj,
            ]),
        ),
    );
}

// export const keyVector = (rows) => _.fill(rows, null);

/**
 * Generate key image for single stealth pair private/public
 * for using in RingCT
 * // TODO - give format, length of key image output and support multiple input
 * @param {string} privKey 32 bytes hex
 * @param {string} pubKey 32 bytes hex
 * @returns {ecurve.Point}
 */
export const keyImage = (privKey, pubKey) => {
    console.log('generating key image ', privKey);
    // const HP = [];
    // const KeyImage = [];
    // for (let i = 0; i < rows; i++) {
    //     HP[i] = BigInteger.fromBuffer(hs(basePoint.multiply(BigInteger.fromHex(x[i]))));
    //     KeyImage[i] = HP[i].multiply(BigInteger.fromHex(x[i]));
    // }

    // return KeyImage;
    return hashToPoint(pubKey).multiply(
        privKey,
    );
};

// const genPubKeylFromUTXO(utxos, index)

// const _generateRandomPoints = utxoLength => _.fill(Array(utxoLength), () => ec.genKeyPair());

export const UTXO_RING_SIZE = 11;

/**
 * TODO find a better way to implement and check benchmark
 * Using MLSAG technique to apply ring-signature for A spending utxo
 * multiple UTXOS input version is below
 * base on a group 11 utxos
 * Notice that MLSAG in tomo using stealth address as public key in ringCT (Pj)
 * stealth = Hs(r*public_view_key)*G + public_Spend_key
 * --> we got private key of stealth or called X = Hs(r*public_view_key) + private_spend_key
 * please read the getRingCTKeys of UTXO for more detail
 * @param {string} privKey - hs(ECDH) + private_spend_key, remember this is the ECDH of utxos[index]
 * @param {utxo array} utxos list utxo, refer src/utxo.js for more detail about data structure
 * @param {number} index Index of real spended utxo
 */
export default class MLSAG {
    // sign single utxo
    // the multiple utxos version is below
    static sign(privKey, utxos, index, targetAddress) {
        // do i need the utxo instance or just plain data of 11 utxos - TODO give solution and explain
        const sender = utxos[index].getRingCTKeys(privKey);

        // message should be something public
        const message = utxos[index].getHashData(targetAddress);


        const X = BigInteger.fromHex(sender.privKey); // the private key we use for signing the message in ringCT
        const I = keyImage(X, sender.pubKey.toString('hex')); // hash to point of current public key of
        const HP = hashToPoint(sender.pubKey.toString('hex'));
        const n = utxos.length;
        // console.log(X);
        // console.log(I);

        const alpha = BigInteger.fromHex(randomHex());
        const si = _.map(new Array(utxos.length), () => BigInteger.fromHex(randomHex()));
        const L = [];
        const R = [];
        const ci = [];

        // init value before generating ring
        L[index] = secp256k1.G.multiply(alpha);
        R[index] = HP.multiply(alpha);
        ci[(index + 1) % n] = BigInteger.fromHex(
            fastHash(
                hextobin(message),
                +L[index].getEncoded(true).toString('hex')
                + R[index].getEncoded(true).toString('hex'),
            ),
        );

        let j = (index + 1) % n;
        let isCalculatedAll = 1;

        while (isCalculatedAll < n) {
            L[j] = secp256k1.G.multiply(si[(j + 1) % n]).add(
                utxos[j].lfStealth.multiply(ci[j]),
            );
            R[j] = hashToPoint(utxos[j].lfStealth.getEncoded(true).toString('hex')).multiply(
                si[(j + 1) % n],
            ).add(
                I.multiply(ci[j]),
            );
            ci[(j + 1) % n] = hashRingCT(message, L[j].getEncoded(true), R[j].getEncoded(true));
            j = (j + 1) % n;

            isCalculatedAll++;
        }
        si[index] = alpha.subtract(
            ci[index].multiply(X).mod(secp256k1.n),
        );

        return {
            I,
            ci_zero: ci[0],
            si,
        };
    }

    static verify(utxos, I, c1, si) {
        const rows = utxos.length; // length of noising utxo, default is 11
        const cols = 1; // number of utxos you need to verify - now just support one input

        const L = [];
        const R = [];
        // pj = ''.join(pk[0])
        // for (var i = 0; i < rows; i++) {
        //     pj = pj + ''.join(pk[i])
        // }

        const ci = [];
        // const HP = _.map(utxos, ut => hashToPoint(ut.lfStealth.getEncoded(true).toString('hex')));

        ci[0] = c1;
        let j = 0;
        // const tohash = HP.join('');

        while (j < cols) {
            for (let i = 0; i < rows; i++) {
                L[j] = secp256k1.G.multiply(si[j + 1]).add(
                    utxos[j].lfStealth.multiply(ci[j]),
                );
                R[j] = hashToPoint(utxos[j].lfStealth.getEncoded(true).toString('hex')).multiply(
                    si[j + 1],
                ).add(
                    I.multiply(ci[j]),
                );
                ci[j] = hashRingCT(message, L[j].getEncoded(true), R[j].getEncoded(true));
                j += 1;
                // tohash = tohash + L[i][j] + R[i][j];
            }
            j += 1;
        }

        const rv = ci[0] === ci[cols];
        // print('c', c);
        // print('sig verifies?', rv);

        return rv;
    }
}
