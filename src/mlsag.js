/* eslint-disable no-loop-func */
// @flow
import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';
import { randomBI } from './crypto';

import { BigInteger } from './constants';

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

const baseG = secp256k1.g;

/**
 * Turn a hex into secp256k1 point, we do it by repeating hashing and mul baseG
 * util got a correct point
 * @param {string} hex long-form format include x+y (without first bit)
 * @returns {ecurve.Point} return a point in Secp256k1
 */
export const hashToPoint = (longFormPoint: string) => {
    assert(longFormPoint && longFormPoint.length, 'Invalid input public key to hash');

    let hashed = keccak256(Buffer.from(longFormPoint, 'hex'));

    if (hashed.length % 2 === 1) {
        hashed = '0' + hashed;
    }
    const newPoint = baseG.mul(BigInteger.fromHex(hashed));
    return newPoint;
};

/**
 * Turn a buffer into a hex value in secp256k1 prime field Zp
 * Use internal inside MLSAG only
 * @param {Buffer} message
 * @returns {BigInteger}
 */
function hashRingCT(message: Buffer) {
    return BigInteger.fromHex(
        keccak256(
            message,
        ),
    );
}

/**
 * Generate key image for single stealth pair private/public
 * keyImage = Hp(Public_key)*private_key
 * @param {BigInteger} privKey 32 bytes hex
 * @param {string} pubKey 32 bytes hex
 * @returns {ecurve.Point}
 */
export const keyImage = (privKey: BigInteger, pubKey: string) => hashToPoint(pubKey).mul(
    privKey,
);

/**
 * Using MLSAG technique to apply ring-signature for spending utxos
 * base on a group 11 utxos
 * Notice that MLSAG in tomo using stealth address as public key in ringCT (Pj)
 * stealth = Hs(r*public_view_key)*G + public_Spend_key
 * --> we got private key of stealth or called X = Hs(r*public_view_key) + private_spend_key
 * please read the getRingCTKeys of Point for more detail
 */
export default class MLSAG {
    /**
     * @param {Buffer} message whatever message you wanna sign in Buffer
     * @param {string} userPrivateKey private key of user to decode the privatekey of stealth(one-time-address)
     * as stealth = Hs(r*public_view_key)*G + public_Spend_key
     * --> we got private key of stealth or called X = Hs(r*public_view_key) + private_spend_key
     * @param {Array} decoys an 2-d array, each rows is a decoys-ring(included the spending utxo itself) utxo
     * @param {number} index where you put the real spending utxo in each ring
     * @returns {Object} include keyImage list, c[0], s
     */
    static mulSign(privKeys: Array<string>, decoys: Array<Array<secp256k1.curve.point>>, index: number, message: ?Buffer) {
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

        let pj = new Buffer([]);
        let i;

        // prepare HP
        for (i = 0; i < numberOfRing; i++) {
            L.push([]);
            R.push([]);
            // const ringctKeys = decoys[i][index].getRingCTKeys(userPrivateKey);
            // privKeys[i] = BigInteger.fromHex(ringctKeys.privKey); // ignore first two byte 02/03

            I[i] = keyImage(privKeys[i], decoys[i][index].encode('hex', false).slice(2));
            HP[i] = _.map(decoys[i], (utxo) => {
                pj = Buffer.concat([pj, Buffer.from(utxo.encode('array', true))]);
                return hashToPoint(utxo.encode('hex', false).slice(2));
            });
            // TODO compute probability of randomBI > secp256k1
            s.push(_.map(new Array(decoys[i].length), () => randomBI().umod(secp256k1.n)));
        }

        for (i = 0; i < numberOfRing; i++) {
            L[i][index] = baseG.mul(s[i][index]); // aG
            R[i][index] = HP[i][index].mul(s[i][index]); // aH
        }

        pj = message ? Buffer.concat([pj, message]) : pj;
        pj = Buffer.from(keccak256(pj), 'hex');

        let j = (index + 1) % ringSize;
        let tohash = _.cloneDeep(pj); // pj = message || all_pubkeys

        for (i = 0; i < numberOfRing; i++) {
            tohash = Buffer.concat([tohash,
                Buffer.from(L[i][index].encode('array', false).slice(1)),
                Buffer.from(R[i][index].encode('array', false).slice(1)),
            ]);
        }

        // calculate c[index+1] first, used for calculating R,L next round
        c[j] = hashRingCT(tohash);
        console.log(`c[${j}] `, c[j].toString(16));
        while (j !== index) {
            tohash = _.cloneDeep(pj);
            for (i = 0; i < numberOfRing; i++) {
                L[i][j] = baseG.mul(s[i][j]).add(
                    decoys[i][j].mul(c[j]),
                ); // Lj = sG + cxG
                R[i][j] = HP[i][j].mul(s[i][j]).add(
                    I[i].mul(c[j]),
                ); // Rj = sH + cxH
                console.log(`L[${i}][${j}] `, L[i][j].encode('hex', true));
                console.log(`R[${i}][${j}] `, R[i][j].encode('hex', true));
                tohash = Buffer.concat([tohash,
                    Buffer.from(L[i][j].encode('array', false).slice(1)),
                    Buffer.from(R[i][j].encode('array', false).slice(1)),
                ]);
            }
            j = (j + 1) % ringSize;
            c[j] = hashRingCT(tohash);
            console.log(`c[${j}] `, c[j].toString(16));
        }

        // si = a - c x so a = s + c x
        // actually here we should use an other random alpha
        // but s[i] is also random
        for (i = 0; i < numberOfRing; i++) {
            s[i][index] = s[i][index].sub(
                c[index].mul(
                    privKeys[i],
                ).umod(
                    secp256k1.n,
                ),
            ).umod(
                secp256k1.n,
            );
            console.log(s[i][index].toString(16));
        }

        return {
            I,
            c1: c[0],
            s,
            privKeys,
            message: pj,
        };
    }

    /**
     * @param {number} index where you put the real spending utxo in each ring
     * Verify the result of mlsag signing
     * @param {Buffer} message whatever message you wanna sign
     * @param {Array<Point>} decoys an 2-d array, each rows is a decoys-ring(included the spending utxo itself) utxo
     * @param {Array<Point>} I Key image list
     * @param {BigInteger} c1 the first item of commitment list
     * @param {Array<BigI>} s random array
     * @returns {Boolean} true if message is verify
     */
    static verifyMul(decoys: Array<Array<secp256k1.curve.point>>, I: secp256k1.curve.point, c1: BigInteger, s: Array<BigInteger>, message: ?Buffer) {
        const numberOfRing = decoys.length;
        const ringSize = decoys[0].length;
        const L = [];
        const R = [];
        const HP = [];
        // const pj = message || Buffer.from(BigInteger.ZERO().toString(16, 32).match(/.{2}/g));
        let pj = new Buffer([]);

        for (let i = 0; i < numberOfRing; i++) {
            L.push([]);
            R.push([]);
            HP[i] = _.map(decoys[i], (utxo) => {
                pj = Buffer.concat([pj,
                    Buffer.from(utxo.encode('array', true)),
                ]);
                return hashToPoint(utxo.encode('hex', false).slice(2));
            });
        }

        pj = message ? Buffer.concat([pj, message]) : pj;
        pj = Buffer.from(keccak256(pj), 'hex');

        const c = [c1];
        let j = 0;
        while (j < ringSize) {
            let tohash = _.cloneDeep(pj);
            let i;
            for (i = 0; i < numberOfRing; i++) {
                L[i][j] = baseG.mul(s[i][j]).add(
                    decoys[i][j].mul(c[j]),
                );
                R[i][j] = HP[i][j].mul(s[i][j]).add(
                    I[i].mul(c[j]),
                ); // Rj = sH + cxH
                tohash = Buffer.concat([tohash,
                    Buffer.from(L[i][j].encode('array', false).slice(1)),
                    Buffer.from(R[i][j].encode('array', false).slice(1)),
                ]);
                console.log(`L[${i}][${j}] `, L[i][j].encode('hex', true));
                console.log(`R[${i}][${j}] `, R[i][j].encode('hex', true));
            }
            j++;
            c[j] = hashRingCT(tohash);
            console.log('c[j] ', c[j].toString(16));
        }
        console.log('\n\n');
        return (c[0].toString(16) === c[ringSize].toString(16));
    }

    /**
     * Generate confidential transaction ring
     * We create one ring for CT that each parameter generated by:
     * private_key_of_ring = z = (utxo' private key + sum_mask_in - sum_mask_out) mod n
     * public_key_of_ring = Pi + sum_C_in - sum_c_out (because sum value commits to zero)
     * index = index_of_ring_signature
     * @param {string} userPrivateKey private key of user to decode the privatekey of stealth(one-time-address)
     * as stealth = Hs(r*public_view_key)*G + public_Spend_key
     * --> we got private key of stealth or called X = Hs(r*public_view_key) + private_spend_key
     * @param {Array} decoys an 2-d array, each rows is a decoys-ring(included the spending utxo itself) utxo
     * @param {Array} outputPoints utxo output of transaction, always 2 items in tomoprivacy protocol
     * one for receiver, one for sender (value maybe zero)
     * @param {number} index where you put the real spending utxo in each ring
     * @returns {Object} include keyImage list, c[0], s
     */
    static genCTRing(userPrivateKey: string, decoys: Array<Array<secp256k1.curve.point>>, outputPoints: Array<secp256k1.curve.point>, index: number) {
        // number of spending utxos
        const numberOfRing = decoys.length;

        // decoys lengh, here we set default as 11
        const ringSize = decoys[0].length;

        let sumSpendingMask = BigInteger.ZERO(); // for calculating private key in ring
        let sumOutputMask = BigInteger.ZERO(); // big number
        let outputCommitment; // a point in seccp256k1

        // prepare sum of output mask
        outputPoints.forEach((utxo) => {
            if (utxo.decodedMask.length % 2 === 1) {
                utxo.decodedMask = '0' + utxo.decodedMask;
            }
            sumOutputMask = sumOutputMask.add(
                BigInteger.fromHex(utxo.decodedMask),
            );
        });
        // prepare sum of output commitment
        outputPoints.forEach((utxo) => {
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
        for (let i = 0; i < numberOfRing; i++) {
            decoys[i][index].checkOwnership(userPrivateKey);
            sumSpendingMask = sumSpendingMask.add(BigInteger.fromHex(decoys[i][index].decodedMask));
            sumSpendingMask = sumSpendingMask.add(BigInteger.fromHex(decoys[i][index].privKey));

            for (let j = 0; j < ringSize; j++) {
                // + Commitment
                publicKeys[j] = publicKeys[j] ? publicKeys[j].add(
                    decoys[i][j].lfCommitment,
                ) : decoys[i][j].lfCommitment;

                // + publickey of utxo
                publicKeys[j] = publicKeys[j].add(
                    decoys[i][j].lfStealth,
                );
            }
        }

        outputCommitment = outputCommitment ? outputCommitment.neg() : outputCommitment;
        for (let j = 0; j < ringSize; j++) {
            publicKeys[j] = publicKeys[j].add(
                outputCommitment,
            );
        }

        // prepare data for ring include private key, key image, HP, s
        const privKey = sumSpendingMask
            .sub(sumOutputMask)
            .umod(secp256k1.n);

        return {
            privKey,
            publicKeys,
        };
    }
}
