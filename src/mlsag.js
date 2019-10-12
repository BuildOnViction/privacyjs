/* eslint-disable no-loop-func */
// @flow
import ecurve from 'ecurve';
import { keccak256 } from 'js-sha3';
import assert from 'assert';
import * as _ from 'lodash';
import { BigInteger, randomHex } from './crypto';
import { fastHash, bconcat, hextobin } from './common';
// import { baseH, baseH2 } from './commitment';
// import { soliditySha3, bintohex } from './common';

const secp256k1 = ecurve.getCurveByName('secp256k1');
// const { Point } = ecurve;
// const hs = hmacSha256;
const baseG = secp256k1.G;

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
        const newPoint = baseG.multiply(BigInteger.fromHex(keccak256(hex)));
        if (secp256k1.isOnCurve(newPoint)) {
            return newPoint;
        }
        hex = keccak256(hex);
    }
};

/**
 * A hash function for real message plus two more ring parameters for decoy data
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
    ).mod(secp256k1.p);
}

// function hashToScalar(point) {
//     return hashToPoint(point).getEncoded(true).toString('hex').slice(2); // ignore first byte (04, 02, 03)
// }

// export const keyVector = (numberOfSendingUTXOs) => _.fill(numberOfSendingUTXOs, null);

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
    // for (let i = 0; i < numberOfSendingUTXOs; i++) {
    //     HP[i] = BigInteger.fromBuffer(hs(baseG.multiply(BigInteger.fromHex(x[i]))));
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
    static sign(message, privKey, utxos, index) {
        const sender = utxos[index].getRingCTKeys(privKey);

        // message here represent for tx_hash
        // we concat all utxo_pubkey and hash to 32 character
        // const message = sha3(_.map(utxos, ut => {
        //     return ut.lfStealth.getEncoded(true).toString('hex');
        // }).join(""));

        const X = BigInteger.fromHex(sender.privKey); // the private key we use for signing the message in ringCT
        const I = keyImage(X, sender.pubKey.toString('hex'));
        const HP = hashToPoint(sender.pubKey.toString('hex'));// hash to point of current public key of
        const n = utxos.length;
        // console.log(X);
        // console.log(I);

        const alpha = BigInteger.fromHex(randomHex());
        const si = _.map(new Array(utxos.length), () => BigInteger.fromHex(randomHex()));
        const L = [];
        const R = [];
        const ci = [];

        // init value before generating ring
        L[index] = baseG.multiply(alpha);
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
            L[j] = baseG.multiply(si[(j + 1) % n]).add(
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

    static mulSign(message, privKeys, mixing, index) {
        // input spending utxos
        const numberOfUTXOs = privKeys.length;

        // mixing lengh, here we set default as 11
        const decoysEachRing = mixing[0].length;

        const X = [];
        const I = [];
        const HP = [];
        const L = [];
        const R = [];
        const s = [];
        const c = [];

        let pj = message;
        let i;
        for (i = 0; i < mixing.length; i++) {
            L.push([]);
            R.push([]);
            const sender = mixing[i][index].getRingCTKeys(privKeys[i]);
            X[i] = BigInteger.fromHex(sender.privKey); // the private key we use for signing the message in ringCT
            I[i] = keyImage(X, sender.pubKey.toString('hex'));
            HP[i] = _.map(mixing[i], (utxo) => {
                pj = bconcat(pj, utxo.lfStealth.getEncoded(true));
                return hashToPoint(utxo.lfStealth.getEncoded(true).toString('hex'));
            });
            s.push(_.map(new Array(mixing[i].length), () => BigInteger.fromHex(randomHex())));
        }

        for (i = 0; i < numberOfUTXOs; i++) {
            L[i][index] = baseG.multiply(s[i][index]); // aG
            R[i][index] = HP[i][index].multiply(s[i][index]); // aH
        }

        let j = (index + 1) % decoysEachRing;
        let tohash = pj;

        for (i = 0; i < numberOfUTXOs; i++) {
            tohash = bconcat(tohash, L[i][index].getEncoded(true), R[i][index].getEncoded(true));
        }

        c[j] = BigInteger.fromHex(fastHash(tohash));

        while (j !== index) {
            tohash = pj;
            for (i = 0; i < numberOfUTXOs; i++) {
                L[i][j] = baseG.multiply(s[i][j]).add(
                    mixing[i][j].lfStealth.multiply(c[j]),
                ); // Lj = sG + cxG
                R[i][j] = HP[i][j].multiply(s[i][j]).add(
                    I[i].multiply(c[j]),
                ); // Rj = sH + cxH
                tohash = bconcat(tohash, L[i][j].getEncoded(true), R[i][j].getEncoded(true));
            }
            j = (j + 1) % decoysEachRing;
            c[j] = BigInteger.fromHex(fastHash(tohash));
            for (i = 0; i < numberOfUTXOs; i++) {
                s[i][index] = s[i][index].subtract(
                    c[index].multiply(privKeys[i]),
                ); // si = a - c x so a = s + c x
            }
        }
        return {
            I,
            c1: c[0],
            s,
        };
    }

    static verifyMul(message, mixing, I, c1, s) {
        const numberOfUTXOs = mixing.length;

        // mixing lengh, here we set default as 11
        const decoysEachRing = mixing[0].length;

        const L = [];
        const R = [];
        const HP = [];
        let pj = message;
        for (let i = 0; i < numberOfUTXOs; i++) {
            L.push([]);
            R.push([]);
            HP[i] = _.map(mixing[i], (utxo) => {
                pj = bconcat(pj, utxo.lfStealth.getEncoded(true));
                return hashToPoint(utxo.lfStealth.getEncoded(true).toString('hex'));
            });
            s.push(_.map(new Array(mixing[i].length), () => BigInteger.fromHex(randomHex())));
        }

        const c = []; // you do an extra one, and then check the wrap around
        c[0] = c1;
        let j = 0;
        while (j < decoysEachRing) {
            let tohash = pj;
            let i;
            for (i = 0; i < numberOfUTXOs; i++) {
                L[i][j] = baseG.multiply(s[i][j]).add(
                    mixing[i][j].lfStealth.multiply(c[j]),
                );
                R[i][j] = HP[i][j].multiply(s[i][j]).add(
                    I[i].multiply(c[j]),
                ); // Rj = sH + cxH
                tohash = bconcat(tohash, L[i][j].getEncoded(true), R[i][j].getEncoded(true));
            }
            j += 1;
            c[j] = BigInteger.fromHex(fastHash(tohash));
        }
        const rv = (c[0] === c[decoysEachRing]);

        return rv;
    }

    /**
     * Verify the MLSAG result, this will be done in SC, we just do it ourself for unit-testing
     * @param {utxo array} utxos list utxo, refer src/utxo.js for more detail about data structure
     * @param {ecurve.Point} I keyImage -> represent for who actually signs
     * @param {BigInteger} c1 first commitment for generating commiment list
     * @param {BigInteger} si list generated private keys
     */
    static verify(message, utxos, I, c1, si) {
        const numberOfDecoy = utxos.length; // length of decoy utxos, default is 11
        // const numberOfSendingUTXOs = 1; // number of utxos you need to verify - now just support one input
        // const message = sha3(_.map(utxos, ut => {
        //     return ut.lfStealth.getEncoded(true).toString('hex');
        // }).join(""));

        const L = [];
        const R = [];
        const ci = [];

        ci[0] = _.cloneDeep(c1);

        for (let j = 0; j < numberOfDecoy; j++) {
            L[j] = baseG.multiply(si[j + 1]).add(
                utxos[j].lfStealth.multiply(ci[j]),
            );
            R[j] = hashToPoint(utxos[j].lfStealth.getEncoded(true).toString('hex')).multiply(
                si[j + 1],
            ).add(
                I.multiply(ci[j]),
            );
            ci[j] = hashRingCT(message, L[j].getEncoded(true), R[j].getEncoded(true));
            j += 1;
        }

        const rv = ci[0] === ci[numberOfDecoy];
        return rv;
    }
}
