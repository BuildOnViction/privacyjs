const elliptic = require('elliptic')
const EC = elliptic.ec
const ECDSA = new EC('secp256k1')
const Base58 = require('bs58')
const common = require('./common')

let addressUtils = {}

/**
 * Generate public key from a private key
 * @param {string} Any private key
 * @returns {string} Public key in hex string using ECDSA
 */
addressUtils.privateKeyToPub = function (privKey) {
    // Then generate the public point/key corresponding to your privKey.
    return ECDSA.keyFromPrivate(privKey).getPublic().encodeCompressed('hex')
}

/**
 * Generate Stealth address from public spend key, public view key
 * stealth address = base58_encode(public_spend_key + public_view_key + checksum)
 * TODO: move to stealth module
 * @param {string} public spend key
 * @param {string} public view key
 * @returns {string} base58-check format for stealth address
 */
addressUtils.generateAddress = function (pubSk, pubVk) {
    var preAddr = pubSk + pubVk
    var hash = common.fastHash(preAddr)
    var addrHex = preAddr + hash.slice(0, 8)
    return Base58.encode(common.hextobin(addrHex))
}

/**
 * Generate keys for privacy base on secret key (also called private spend key)
 * @param {string} secret_key The wallet secret key of Tomochain account
 * @return {object} private spend key, private view key, public view key, public spend key, privacy address
 */
addressUtils.generateKeys = function (secret_key) {
    var privSk = secret_key
    var privVk = common.fastHash(privSk)
    var pubSk = addressUtils.privateKeyToPub(privSk)
    var pubVk = addressUtils.privateKeyToPub(privVk)

    return {
        privSpend: privSk,
        pubSpend: pubSk,
        privView: privVk,
        pubView: pubVk,
        pubAddr: addressUtils.generateAddress(pubSk, pubVk)
    }
}

module.exports = addressUtils