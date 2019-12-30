import assert from 'assert';
import * as common from './common';

const Base58 = require('bs58');

const EC = require('elliptic').ec;
// type Point = Curve.short.ShortPoint;

const secp256k1 = new EC('secp256k1');

/**
 * Generate public key from a private key
 * @param {string} Any private key
 * @returns {string} Public key in hex string using secp256k1
 */
export const privateKeyToPub = privKey => secp256k1.keyFromPrivate(privKey).getPublic().encodeCompressed('hex');

/**
 * Generate privacy address from public spend key, public view key
 * privacy address = base58_encode(public_spend_key + public_view_key + checksum)
 * @param {string} public spend key
 * @param {string} public view key
 * @returns {string} base58-check format for privacy address
 */
export const generateAddress = function (pubSk, pubVk) {
    const preAddr = pubSk + pubVk;
    const hash = common.fastHash(preAddr);
    const addrHex = preAddr + hash.slice(0, 8);

    return Base58.encode(common.hextobin(addrHex));
};

/**
 * Generate keys for privacy base on secret key (also called private spend key)
 * @param {string} secretKey The wallet secret key of Tomochain account
 * @return {object} private spend key, private view key, public view key,
 * public spend key, privacy address
 */
export const generateKeys = function (secretKey) {
    const privSk = secretKey;
    const privVk = common.fastHash(privSk);
    const pubSk = privateKeyToPub(privSk);
    const pubVk = privateKeyToPub(privVk);

    return {
        privSpendKey: privSk,
        pubSpendKey: pubSk,
        privViewKey: privVk,
        pubViewKey: pubVk,
        pubAddr: generateAddress(pubSk, pubVk),
    };
};

export const validatePrivacyAddress = function (address) {
    // length after using base58 should reduce from 140 to 95
    assert.equal(address.length, 95);

    // decode the public address to get public spend key and public view key - length 140
    const decodedPrivacyAddress = common.bintohex(Base58.decode(address));

    // get first 33 bytes - 66 hex string of public spend key
    const publicSpendKey = decodedPrivacyAddress.substr(0, 66);
    assert.equal(publicSpendKey.length, 66);

    // get first 33 bytes - 66 hex string of public view key
    const publicViewKey = decodedPrivacyAddress.substr(66, 66);
    assert.equal(publicViewKey.length, 66);

    // double test check sum
    const preAddr = publicSpendKey + publicViewKey;
    const hash = common.fastHash(preAddr).slice(0, 8);
    assert.equal(hash, decodedPrivacyAddress.substr(132, 8));
};
