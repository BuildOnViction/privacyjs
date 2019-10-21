/* eslint-disable no-loop-func */
import ecurve from 'ecurve';
import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';
// import web3 from 'web3';
import { BigInteger, randomHex } from './crypto';
// import { bconcat } from './common';

const secp256k1 = ecurve.getCurveByName('secp256k1');
const baseG = secp256k1.G;

// type LongFormPoint = string[66];
// TODO implement flow type
/**
 * Turn a hex into secp256k1 point, we do it by repeating hashing and multiply baseG
 * util got a correct point
 * @param {string} hex long-form format include x+y (without first bit)
 * @returns {ecurve.Point} return a point in Secp256k1
 */
export const hashToPoint = (longFormPoint) => {
    assert(longFormPoint && longFormPoint.length, 'Invalid input public key to hash');

    // while (longFormPoint) {
    let hashed = keccak256(Buffer.from(longFormPoint, 'hex'));

    if (hashed.length % 2 === 1) {
        hashed = '0' + hashed;
    }
    const newPoint = baseG.multiply(BigInteger.fromHex(hashed));
    return newPoint;
};

/**
 * Turn a buffer into a hex value in secp256k1 prime field Zp
 * Use internal inside MLSAG only
 * @param {Buffer} message
 * @returns {BigInteger}
 */
function hashRingCT(message) {
    return BigInteger.fromHex(
        keccak256(
            message,
        ),
    );
}

/**
 * Generate key image for single stealth pair private/public
 * keyImage = Hp(Public_key)*private_key
 * @param {string} privKey 32 bytes hex
 * @param {string} pubKey 32 bytes hex
 * @returns {ecurve.Point}
 */
export const keyImage = (privKey, pubKey) => hashToPoint(pubKey).multiply(
    privKey,
);

export const UTXO_RING_SIZE = 11;

/**
 * Using MLSAG technique to apply ring-signature for spending utxos
 * base on a group 11 utxos
 * Notice that MLSAG in tomo using stealth address as public key in ringCT (Pj)
 * stealth = Hs(r*public_view_key)*G + public_Spend_key
 * --> we got private key of stealth or called X = Hs(r*public_view_key) + private_spend_key
 * please read the getRingCTKeys of UTXO for more detail
 */
export default class MLSAG {
    /**
     * @param {string|Buffer|number} message whatever message you wanna sign
     * @param {string} userPrivateKey private key of user to decode the privatekey of stealth(one-time-address)
     * as stealth = Hs(r*public_view_key)*G + public_Spend_key
     * --> we got private key of stealth or called X = Hs(r*public_view_key) + private_spend_key
     * @param {Array} mixing an 2-d array, each rows is a mixing-ring(included the spending utxo itself) utxo
     * @param {number} index where you put the real spending utxo in each ring
     * @returns {Object} include keyImage list, c[0], s
     */
    static mulSign(message, userPrivateKey, mixing, index) {
        // number of spending utxos
        const numberOfRing = mixing.length;

        // mixing lengh, here we set default as 11
        const ringSize = mixing[0].length;
        const I = [];
        const HP = [];
        const L = [];
        const R = [];
        const s = [];
        const c = [];

        const pj = Buffer.from(BigInteger.ZERO.toHex(32).match(/.{2}/g));
        let i;
        const privKeys = [];

        // prepare HP
        for (i = 0; i < numberOfRing; i++) {
            L.push([]);
            R.push([]);
            const ringctKeys = mixing[i][index].getRingCTKeys(userPrivateKey);
            privKeys[i] = BigInteger.fromHex(ringctKeys.privKey); // ignore first two byte 02/03

            I[i] = keyImage(privKeys[i], mixing[i][index].lfStealth.getEncoded(false).toString('hex').slice(2));
            HP[i] = _.map(mixing[i], utxo => hashToPoint(utxo.lfStealth.getEncoded(false).toString('hex').slice(2)));

            s.push(_.map(new Array(mixing[i].length), () => BigInteger.fromHex(randomHex())));
        }

        for (i = 0; i < numberOfRing; i++) {
            L[i][index] = baseG.multiply(s[i][index]); // aG
            R[i][index] = HP[i][index].multiply(s[i][index]); // aH
        }

        let j = (index + 1) % ringSize;
        let tohash = _.cloneDeep(pj); // pj = message || all_pubkeys

        for (i = 0; i < numberOfRing; i++) {
            tohash = Buffer.concat([tohash, L[i][index].getEncoded(false).slice(1), R[i][index].getEncoded(false).slice(1)]);
        }

        // calculate c[index+1] first, used for calculating R,L next round
        c[j] = hashRingCT(tohash);
        while (j !== index) {
            tohash = _.cloneDeep(pj);
            for (i = 0; i < numberOfRing; i++) {
                L[i][j] = baseG.multiply(s[i][j]).add(
                    mixing[i][j].lfStealth.multiply(c[j]),
                ); // Lj = sG + cxG
                R[i][j] = HP[i][j].multiply(s[i][j]).add(
                    I[i].multiply(c[j]),
                ); // Rj = sH + cxH
                tohash = Buffer.concat([tohash, L[i][j].getEncoded(false).slice(1), R[i][j].getEncoded(false).slice(1)]);
            }
            j = (j + 1) % ringSize;
            c[j] = hashRingCT(tohash);
        }

        // si = a - c x so a = s + c x
        // actually here we should use an other random alpha
        // but s[i] is also random
        for (i = 0; i < numberOfRing; i++) {
            s[i][index] = s[i][index].subtract(
                c[index].multiply(
                    privKeys[i],
                ),
            ).mod(
                secp256k1.n,
            );
        }

        return {
            I,
            c1: c[0],
            s,
            privKeys,
        };
    }

    /**
     * @param {number} index where you put the real spending utxo in each ring
     * Verify the result of mlsag signing
     * @param {string|Buffer|number} message whatever message you wanna sign
     * @param {Array<UTXO>} mixing an 2-d array, each rows is a mixing-ring(included the spending utxo itself) utxo
     * @param {Array<Point>} I Key image list
     * @param {BigInteger} c1 the first item of commitment list
     * @param {Array<BigInteger>} s random array
     * @returns {Boolean} true if message is verify
     */
    static verifyMul(message, mixing, I, c1, s) {
        const numberOfRing = mixing.length;
        const ringSize = mixing[0].length;
        const L = [];
        const R = [];
        const HP = [];
        const pj = Buffer.from(BigInteger.ZERO.toHex(32).match(/.{2}/g));

        for (let i = 0; i < numberOfRing; i++) {
            L.push([]);
            R.push([]);
            HP[i] = _.map(mixing[i], utxo => hashToPoint(utxo.lfStealth.getEncoded(false).toString('hex').slice(2)));
        }

        const c = [c1];
        let j = 0;
        while (j < ringSize) {
            let tohash = _.cloneDeep(pj);
            let i;
            for (i = 0; i < numberOfRing; i++) {
                L[i][j] = baseG.multiply(s[i][j]).add(
                    mixing[i][j].lfStealth.multiply(c[j]),
                );
                R[i][j] = HP[i][j].multiply(s[i][j]).add(
                    I[i].multiply(c[j]),
                ); // Rj = sH + cxH
                tohash = Buffer.concat([tohash, L[i][j].getEncoded(false).slice(1), R[i][j].getEncoded(false).slice(1)]);
            }
            j++;
            c[j] = hashRingCT(tohash);
        }
        return (c[0].toString('16') === c[ringSize].toString('16'));
    }
}
