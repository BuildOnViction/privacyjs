import BN from 'bn.js';

const crypto = require('crypto');
const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

BN.fromHex = hexstring => new BN(hexstring, 16);
BN.fromBuffer = buffer => new BN(buffer.toString('hex'), 16);

BN.toHex = () => this.toString(16);

export const BigI = BN;

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
    let _key = sha256sum.update(key).digest().toString('hex');

    if (plaintext.length % 2 === 1) {
        plaintext = '0' + plaintext;
    }

    if (_key.length % 2 === 1) {
        _key = '0' + _key;
    }

    const res = BN.fromHex(_key)
        .mod(secp256k1.n).add(
            BN.fromHex(plaintext).mod(secp256k1.n),
        ).mod(secp256k1.n);

    return res.toString(16);
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

    return BN.fromHex(encrypted).subtract(
        BN.fromHex(_key).mod(secp256k1.n),
    ).mod(secp256k1.n).toString(16);
}

/**
 * Random a hex string with size bytes, no prefix 0x, add it yourself if needed
 * a common private key (length 64) = 32 bytes
 * @returns {string} Hex string without prefix 0x
 */
export function randomHex() {
    const result = secp256k1.genKeyPair().getPrivate().toString('hex');
    if (result.length % 2 === 1) {
        return '0' + result;
    }

    return result;
}
