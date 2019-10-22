/* eslint-disable no-loop-func */
import ecurve from 'ecurve';
import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';
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
 * TODO: implement in general way for decoy utxos + additional commitment
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
     * @param {Array} decoys an 2-d array, each rows is a decoys-ring(included the spending utxo itself) utxo
     * @param {number} index where you put the real spending utxo in each ring
     * @returns {Object} include keyImage list, c[0], s
     */
    static mulSign(message, userPrivateKey, decoys, index) {
        // number of spending utxos
        const numberOfRing = decoys.length;

        // decoys lengh, here we set default as 11
        const ringSize = decoys[0].length;
        const I = [];
        const HP = [];
        const L = [];
        const R = [];
        const s = [];
        const c = [];

        const pj = message || Buffer.from(BigInteger.ZERO.toHex(32).match(/.{2}/g)); // 32 bytes
        let i;
        const privKeys = [];

        // prepare HP
        for (i = 0; i < numberOfRing; i++) {
            L.push([]);
            R.push([]);
            const ringctKeys = decoys[i][index].getRingCTKeys(userPrivateKey);
            privKeys[i] = BigInteger.fromHex(ringctKeys.privKey); // ignore first two byte 02/03

            I[i] = keyImage(privKeys[i], decoys[i][index].lfStealth.getEncoded(false).toString('hex').slice(2));
            HP[i] = _.map(decoys[i], utxo => hashToPoint(utxo.lfStealth.getEncoded(false).toString('hex').slice(2)));

            s.push(_.map(new Array(decoys[i].length), () => BigInteger.fromHex(randomHex())));
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
                    decoys[i][j].lfStealth.multiply(c[j]),
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
     * @param {Array<UTXO>} decoys an 2-d array, each rows is a decoys-ring(included the spending utxo itself) utxo
     * @param {Array<Point>} I Key image list
     * @param {BigInteger} c1 the first item of commitment list
     * @param {Array<BigInteger>} s random array
     * @returns {Boolean} true if message is verify
     */
    static verifyMul(message, decoys, I, c1, s) {
        const numberOfRing = decoys.length;
        const ringSize = decoys[0].length;
        const L = [];
        const R = [];
        const HP = [];
        const pj = message || Buffer.from(BigInteger.ZERO.toHex(32).match(/.{2}/g));

        for (let i = 0; i < numberOfRing; i++) {
            L.push([]);
            R.push([]);
            HP[i] = _.map(decoys[i], utxo => hashToPoint(utxo.lfStealth.getEncoded(false).toString('hex').slice(2)));
        }

        const c = [c1];
        let j = 0;
        while (j < ringSize) {
            let tohash = _.cloneDeep(pj);
            let i;
            for (i = 0; i < numberOfRing; i++) {
                L[i][j] = baseG.multiply(s[i][j]).add(
                    decoys[i][j].lfStealth.multiply(c[j]),
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

    /**
     * Implement confidential transaction part using MLSAG technique
     * We create one ring for CT that each parameter generated by:
     * private_key_of_ring = z = (sum_mask_in - sum_mask_out) mod n
     * public_key_of_ring = Pi + sum_C_in - sum_c_out (because sum value commits to zero)
     * index = index_of_ring_signature
     * @param {string} userPrivateKey private key of user to decode the privatekey of stealth(one-time-address)
     * as stealth = Hs(r*public_view_key)*G + public_Spend_key
     * --> we got private key of stealth or called X = Hs(r*public_view_key) + private_spend_key
     * @param {Array} decoys an 2-d array, each rows is a decoys-ring(included the spending utxo itself) utxo
     * @param {Array} outputUTXOs utxo output of transaction, always 2 items in tomoprivacy protocol
     * one for receiver, one for sender (value maybe zero)
     * @param {number} index where you put the real spending utxo in each ring
     * @returns {Object} include keyImage list, c[0], s
     */
    static signCommitment(userPrivateKey, decoys, outputUTXOs, index) {
        // number of spending utxos
        const numberOfRing = decoys.length;

        // decoys lengh, here we set default as 11
        const ringSize = decoys[0].length;
        const L = [];
        const R = [];
        const c = [];

        const pj = Buffer.from(BigInteger.ZERO.toHex(32).match(/.{2}/g));
        let i;

        let sumSpendingMask = BigInteger.ZERO; // for calculating private key in ring
        let sumOutputMask = BigInteger.ZERO; // big number
        let outputCommitment; // a point in seccp256k1

        // prepare sum of output mask
        outputUTXOs.forEach((utxo) => {
            sumOutputMask = sumOutputMask.add(utxo.mask);
        });
        // prepare sum of output commitment
        outputUTXOs.forEach((utxo) => {
            if (!outputCommitment) {
                outputCommitment = utxo.lfCommitment;
            } else {
                outputCommitment = outputCommitment.add(
                    utxo.lfCommitment,
                );
            }
        });

        // calculate sum of spending commitment and sum of spending mask
        const publicKeys = [];
        for (i = 0; i < numberOfRing; i++) {
            const decodedUTXO = decoys[i][index].checkOwnership(userPrivateKey);
            sumSpendingMask = sumSpendingMask.add(BigInteger.fromHex(decodedUTXO.mask));
            for (let j = 0; j < ringSize; j++) {
                publicKeys[j] = publicKeys[j] ? publicKeys[j].add(
                    decoys[i][j].lfCommitment,
                ) : decoys[i][j].lfCommitment;
            }
        }

        // prepare data for ring include private key, key image, HP, s
        const privKey = sumSpendingMask.subtract(sumOutputMask);
        const I = keyImage(privKey, publicKeys[index].getEncoded(false).toString('hex').slice(2));
        const HP = _.map(publicKeys, pubkey => hashToPoint(pubkey.getEncoded(false).toString('hex').slice(2)));
        const s = _.map(new Array(publicKeys.length), () => BigInteger.fromHex(randomHex()));

        L[index] = baseG.multiply(s[index]); // aG
        R[index] = HP[index].multiply(s[index]); // aH

        let j = (index + 1) % ringSize;
        let tohash = _.cloneDeep(pj); // pj = message || all_pubkeys

        tohash = Buffer.concat([tohash, L[index].getEncoded(false).slice(1), R[index].getEncoded(false).slice(1)]);

        // calculate c[index+1] first, used for calculating R,L next round
        c[j] = hashRingCT(tohash);
        while (j !== index) {
            tohash = _.cloneDeep(pj);
            L[j] = baseG.multiply(s[j]).add(
                decoys[j].lfStealth.multiply(c[j]),
            ); // Lj = sG + cxG
            R[j] = HP[j].multiply(s[j]).add(
                I.multiply(c[j]),
            ); // Rj = sH + cxH
            tohash = Buffer.concat([tohash, L[j].getEncoded(false).slice(1), R[j].getEncoded(false).slice(1)]);
            j = (j + 1) % ringSize;
            c[j] = hashRingCT(tohash);
        }

        // si = a - c x so a = s + c x
        // actually here we should use an other random alpha
        // but s[i] is also random
        s[index] = s[index].subtract(
            c[index].multiply(
                privKey,
            ),
        ).mod(
            secp256k1.n,
        );

        return {
            I,
            c1: c[0],
            s,
        };
    }

    /**
     * @param {number} index where you put the real spending utxo in each ring
     * Verify the result of mlsag signing
     * @param {string|Buffer|number} message whatever message you wanna sign
     * @param {Array<UTXO>} decoys an 2-d array, each rows is a decoys-ring(included the spending utxo itself) utxo
     * @param {Array<Point>} I Key image list
     * @param {BigInteger} c1 the first item of commitment list
     * @param {Array<BigInteger>} s random array
     * @returns {Boolean} true if message is verify
     */
    static verifyCommitment(decoys, I, c1, s) {
        const ringSize = decoys.length;
        const L = [];
        const R = [];
        const pj = Buffer.from(BigInteger.ZERO.toHex(32).match(/.{2}/g));
        const HP = _.map(decoys, pubkey => hashToPoint(pubkey.getEncoded(false).toString('hex').slice(2)));

        const c = [c1];
        let j = 0;
        while (j < ringSize) {
            let tohash = _.cloneDeep(pj);
            L[j] = baseG.multiply(s[j]).add(
                decoys[j].lfStealth.multiply(c[j]),
            );
            R[j] = HP[j].multiply(s[j]).add(
                I.multiply(c[j]),
            ); // Rj = sH + cxH
            tohash = Buffer.concat([tohash, L[j].getEncoded(false).slice(1), R[j].getEncoded(false).slice(1)]);
            j++;
            c[j] = hashRingCT(tohash);
        }
        return (c[0].toString('16') === c[ringSize].toString('16'));
    }
}
