import { keccak256 } from 'js-sha3';
import { BigInteger } from './common';

const crypto = require('crypto');
const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

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

    return BigInteger.fromHex(_key)
        .umod(secp256k1.n).add(
            BigInteger.fromHex(plaintext).umod(secp256k1.n),
        ).umod(secp256k1.n)
        .toString(16);
}

export function decode(encrypted, key) {
    // const _key = sha256sum.update(key).digest().toString('hex');
    const sha256sum = crypto.createHash('sha256');
    const _key = sha256sum.update(key).digest().toString('hex');

    return BigInteger.fromHex(encrypted).sub(
        BigInteger.fromHex(_key),
    ).umod(secp256k1.n).toString(16);
}

export function encodeTx(plaintext, key) {
    let _key = key;

    do {
        const sha256sum = crypto.createHash('sha256');
        _key = sha256sum.update(_key).digest().toString('hex');
    } while (_key[0] === '0');

    // create a BI from _key that satisfy
    // bit number = plaintext's bit by
    // create realkey = truncate_to_plaintext_length(_key + _key + key)
    let realKey = _key;
    while (realKey.length < plaintext.length) {
        realKey += keccak256(_key);
    }

    realKey = realKey.slice(0, plaintext.length);

    return BigInteger.fromHex(realKey)
        .add(
            BigInteger.fromHex(plaintext),
        )
        .toString(16);
}

export function decodeTx(encrypted, key) {
    // const _key = sha256sum.update(key).digest().toString('hex');
    let _key = key;

    do {
        const sha256sum = crypto.createHash('sha256');
        _key = sha256sum.update(_key).digest().toString('hex');
    } while (_key[0] === '0');

    let realKey = _key;

    while (encrypted[0] === '0') encrypted = encrypted.substr(1, encrypted.length - 1);

    while (realKey.length < encrypted.length) {
        realKey += keccak256(_key);
    }
    realKey = realKey.slice(0, encrypted.length);

    if (BigInteger.fromHex(realKey).cmp(
        BigInteger.fromHex(encrypted),
    ) > 0) {
        realKey = realKey.slice(0, realKey.length - 1);
    }

    return BigInteger.fromHex(encrypted).sub(
        BigInteger.fromHex(realKey),
    ).toString(16);
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
    return BigInteger.fromHex(result).umod(secp256k1.n).toString(16, n);
}

/**
 * Random a 32 bits BN
 */
export function randomBI() {
    return secp256k1.genKeyPair().getPrivate().umod(secp256k1.n);
}
