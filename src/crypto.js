const crypto = require('crypto');
const ecurve = require('ecurve');
const EC = require('elliptic').ec;

const ec = new EC('secp256k1');

// hack to get bigi without including it as a dep
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
    let _key = sha256sum.update(key).digest().toString('hex');

    if (plaintext.length % 2 === 1) {
        plaintext = '0' + plaintext;
    }

    if (_key.length % 2 === 1) {
        _key = '0' + _key;
    }

    const res = BigInteger.fromHex(_key)
        .mod(ecparams.n).add(
            BigInteger.fromHex(plaintext).mod(ecparams.n),
        ).mod(ecparams.n)
        .toHex();

    return res;
}

export function decode(encrypted, key) {
    const sha256sum = crypto.createHash('sha256');
    let _key = sha256sum.update(key).digest().toString('hex');

    if (encrypted.length % 2 === 1) {
        encrypted = '0' + encrypted;
    }

    if (_key.length % 2 === 1) {
        _key = '0' + _key;
    }

    return BigInteger.fromHex(encrypted).subtract(
        BigInteger.fromHex(_key).mod(ecparams.n),
    ).mod(ecparams.n).toHex();
}

/**
 * Random a hex string with size bytes, no prefix 0x, add it yourself if needed
 * a common private key (length 64) = 32 bytes
 * @returns {string} Hex string without prefix 0x
 */
export function randomHex() {
    const result = ec.genKeyPair().getPrivate().toString('hex');
    if (result.length % 2 === 1) {
        return '0' + result;
    }

    return result;
}
