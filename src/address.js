import { BigInteger } from './crypto';

const Base58 = require('bs58');
const ecurve = require('ecurve');
const common = require('./common');

const ecparams = ecurve.getCurveByName('secp256k1');

/**
 * Generate public key from a private key
 * @param {string} Any private key
 * @returns {string} Public key in hex string using secp256k1
 */
export const privateKeyToPub = function (privKey) {
    return ecparams.G.multiply(
        BigInteger.fromHex(privKey),
    ).getEncoded(true).toString('hex');
};

/**
 * Generate privacy address from public spend key, public view key
 * stealth address = base58_encode(public_spend_key + public_view_key + checksum)
 * @param {string} public spend key
 * @param {string} public view key
 * @returns {string} base58-check format for stealth address
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
