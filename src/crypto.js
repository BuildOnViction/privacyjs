import { BigInteger as BN } from './constants';

const crypto = require('crypto');
const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

// TODO will be remove after finishing adapting elliptic
const ecurve = require('ecurve');

const ecparams = ecurve.getCurveByName('secp256k1');
export const BigInteger = ecparams.n.constructor;

export function hash160(buffer) {
    const sha256 = crypto.createHash('sha256').update(buffer).digest();
    return crypto.createHash('rmd160').update(sha256).digest();
}

export function hmacSha256(buffer) {
    return crypto.createHmac('sha256', new Buffer([])).update(buffer).digest();
}

export function sha256x2(buffer) {
    const sha256 = crypto.createHash('sha256').update(buffer).digest();
    return crypto.createHash('sha256').update(sha256).digest();
}

export function encode(plaintext, key) {
    const sha256sum = crypto.createHash('sha256');
    const _key = sha256sum.update(key).digest().toString('hex');

    const res = BN.fromHex(_key)
        .umod(secp256k1.n).add(
            BN.fromHex(plaintext).umod(secp256k1.n),
        ).umod(secp256k1.n);

    return res.toString(16);
}

export function decode(encrypted, key) {
    const sha256sum = crypto.createHash('sha256');
    const _key = sha256sum.update(key).digest().toString('hex');
    const res = BN.fromHex(encrypted).sub(
        BN.fromHex(_key),
    ).umod(secp256k1.n).toString(16);

    return res;
}

/**
 * Random a hex string with size bytes, no prefix 0x, add it yourself if needed
 * a common private key (length 64) = 32 bytes
 * @returns {string} Hex string without prefix 0x
 */
export function randomHex(n) {
    let result = secp256k1.genKeyPair().getPrivate().toString('hex');

    if (n && result.length * 4 > n) { // each hex = 4 bit
        return result.slice(0, n / 4);
    }

    if (result.length % 2 === 1) {
        result = '0' + result;
    }

    if (n % 2 === 1) n++;
    return BN.fromHex(result).umod(secp256k1.n).toString(16, n);
}

/**
 * Random a 32 bits BN
 */
export function randomBI() {
    return secp256k1.genKeyPair().getPrivate().umod(secp256k1.n);
}
