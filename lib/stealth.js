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
    this.viewPubKey = config.viewPubKey
    this.spendPubKey = config.spendPubKey

    // only makes sense if you're the receiver, i.e. you own the stealth addresss
    this.viewPrivKey = config.viewPrivKey
    this.spendPrivKey = config.spendPrivKey

    assert(Buffer.isBuffer(this.viewPubKey), 'viewPubKey must be a buffer')
    assert(Buffer.isBuffer(this.spendPubKey), 'spendPubKey must be a buffer')

    // default to bitcoin
    this.version = config.version || Stealth.MAINNET
}

Stealth.fromBuffer = function (buffer) {
    const pkLen = 33
    var pos = 0

    var spendPubKey = buffer.slice(pos, pos += pkLen)
    var viewPubKey = buffer.slice(pos, pos += pkLen)

    return new Stealth({
        viewPubKey: viewPubKey,
        spendPubKey: spendPubKey
    })
}

/**
 * genTransactionProof generates one-time address (stealth address) and tx public key
 * to prove the asset belongs the receiver with known pair (public spend key/public view key of receiver)
 * @returns {object} onetimeAdress and txPublicKey
 */
Stealth.prototype.genTransactionProof = function () {
    var kdf = crypto.hmacSha256
    var Ap = Point.decodeFrom(ecparams, this.spendPubKey)
    var A = Point.decodeFrom(ecparams, this.viewPubKey)

    var blindingFactor = BigInteger.fromBuffer(new Buffer(crypto.randomHex(32).slice(3), "hex"))
    
    var S = Ap.multiply(blindingFactor)

    var d = BigInteger.fromBuffer(kdf(S.getEncoded(true)))
    
    var D = ecparams.G.multiply(d)

    var E = A.add(D)

    var onetimeAdress = E.getEncoded(true)
    var txPublicKey = ecparams.G.multiply(blindingFactor).getEncoded(true)

    return {
        onetimeAdress,
        txPublicKey
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
    let decodedPrivacyAddress = common.bintohex(buffer)
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