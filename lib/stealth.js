var assert = require('assert')
var bs58 = require('bs58')
var ecurve = require('ecurve')
var crypto = require('./crypto')
var common = require('./common')
var ecparams = ecurve.getCurveByName('secp256k1')
var Point = ecurve.Point
var BigInteger = crypto.BigInteger

function Stealth(config) {
    // required
    this.pubViewKey = typeof config.pubViewKey === "string" ? new Buffer(config.pubViewKey, "hex") : config.pubViewKey
    this.pubSpendKey = typeof config.pubSpendKey === "string" ? new Buffer(config.pubSpendKey, "hex") : config.pubSpendKey

    // only makes sense if you're the receiver, i.e. you own the stealth addresss
    this.privViewKey = typeof config.privViewKey === "string" ? new Buffer(config.privViewKey, "hex") : config.privViewKey
    this.privSpendKey = typeof config.privSpendKey === "string" ? new Buffer(config.privSpendKey, "hex") : config.privSpendKey

    assert(Buffer.isBuffer(this.pubViewKey), 'pubViewKey must be a buffer')
    assert(Buffer.isBuffer(this.pubSpendKey), 'pubSpendKey must be a buffer')
}

Stealth.fromBuffer = function (buffer) {
    const pkLen = 33
    var pos = 0

    var pubSpendKey = buffer.slice(pos, pos += pkLen)
    var pubViewKey = buffer.slice(pos, pos += pkLen)

    return new Stealth({
        pubViewKey: pubViewKey,
        pubSpendKey: pubSpendKey
    })
}

/**
 * genTransactionProof generates one-time address (stealth address) and tx public key
 * read https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-part-2-stealth-addresses for further information
 * to prove the asset belongs the receiver with known pair (public spend key/public view key of receiver)
 * @returns {object} onetimeAddress and txPublicKey
 */
Stealth.prototype.genTransactionProof = function (pubSpendKey, pubViewKey) {
    var hs = crypto.hmacSha256 // hasing function return a scalar
    var basePoint = ecparams.G //secp256k1 standard base point
    var receiverPubViewKey = Point.decodeFrom(ecparams, pubViewKey || this.pubViewKey)
    var receiverPubSpendKey = Point.decodeFrom(ecparams, pubSpendKey || this.pubSpendKey)

    var blindingFactor = BigInteger.fromBuffer(new Buffer(crypto.randomHex(32), "hex"))

    var ECDHSharedSerect = receiverPubViewKey.multiply(blindingFactor)

    var f = BigInteger.fromBuffer(hs(ECDHSharedSerect.getEncoded(true)))

    var F = basePoint.multiply(f)

    var onetimeAddress = receiverPubSpendKey.add(F).getEncoded(true)

    var txPublicKey = basePoint.multiply(blindingFactor).getEncoded(true)

    return {
        onetimeAddress,
        txPublicKey
    }
}

/**
 * checkTransactionProof check if this user owns the UTXO or not
 * @param {string} onetimeAddress UTXO's steal address
 * @param {string} txPublicKey UTXO's transaction public key
 * @returns {object} amount
 */
Stealth.prototype.checkTransactionProof = function (txPublicKey, onetimeAddress) {
    assert(this.privViewKey, 'privViewKey required')
    assert(this.privSpendKey, 'privSpendKey required')

    if (txPublicKey.length !== 33) return null

    var hs = crypto.hmacSha256

    var B = Point.decodeFrom(ecparams, txPublicKey)

    var ECDHSharedSerect = B.multiply(BigInteger.fromBuffer(this.privViewKey))

    var d = hs(ECDHSharedSerect.getEncoded(true))
    var e = BigInteger.fromBuffer(this.privSpendKey).add(BigInteger.fromBuffer(d)).mod(ecparams.n)

    var E = ecparams.G.multiply(e)

    var onetimeAddressCalculated = E.getEncoded(true)
    if (onetimeAddressCalculated.toString('hex') !== onetimeAddress.toString('hex')) {
        return null
    }

    return {
        privKey: e.toBuffer(32),
        pubKey: E.getEncoded(true)
    }
}

/**
 * Build Stealth address from privacy address of receiver
 * stealth address = 33 bytes (public spend key) + 33 bytes (public view key) + 4 bytes (checksum)
 * @param {string}  str Privacy address of receiver
 * @returns {Object} Stealth instance
 */
Stealth.fromString = function (str) {
    // uncompress base58 address
    var buffer = new Buffer(bs58.decode(str))

    // validate the checksum
    var decodedPrivacyAddress = common.bintohex(buffer)
    var payload = decodedPrivacyAddress.slice(0, -8) // payload from 0 to length -8 (each hex = 4 bit)

    var newChecksum = common.fastHash(payload).slice(0, 8)
    var checksum = decodedPrivacyAddress.slice(-8) // real checksum

    assert.deepEqual(newChecksum, checksum, 'Invalid checksum')

    return Stealth.fromBuffer(buffer.slice(0, -4))
}

function bconcat(arr) {
    arr = arr.map(function (item) {
        return Buffer.isBuffer(item) ? item : new Buffer([item])
    })
    return Buffer.concat(arr)
}

module.exports = Stealth