const elliptic = require('elliptic');

const EC = elliptic.ec;
const ECDSA = new EC('secp256k1');
const Base58 = require('bs58');
const common = require('./common');

const addressUtils = {};

/**
 * Generate public key from a private key
 * // TODO: remove elliptic and replace by privatekey*base_point
 * @param {string} Any private key
 * @returns {string} Public key in hex string using ECDSA
 */
addressUtils.privateKeyToPub = function (privKey) {
    // Then generate the public point/key corresponding to your privKey.
    return ECDSA.keyFromPrivate(privKey).getPublic().encodeCompressed('hex');
};

/**
 * Generate privacy address from public spend key, public view key
 * stealth address = base58_encode(public_spend_key + public_view_key + checksum)
 * @param {string} public spend key
 * @param {string} public view key
 * @returns {string} base58-check format for stealth address
 */
addressUtils.generateAddress = function (pubSk, pubVk) {
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
addressUtils.generateKeys = function (secretKey) {
    const privSk = secretKey;
    const privVk = common.fastHash(privSk);
    const pubSk = addressUtils.privateKeyToPub(privSk);
    const pubVk = addressUtils.privateKeyToPub(privVk);

    return {
        privSpendKey: privSk,
        pubSpendKey: pubSk,
        privViewKey: privVk,
        pubViewKey: pubVk,
        pubAddr: addressUtils.generateAddress(pubSk, pubVk),
    };
};

module.exports = addressUtils;
