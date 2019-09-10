var assert = require('assert')
var bs58 = require('bs58')
var ecurve = require('ecurve')
var crypto = require('./crypto')
var common = require('./common')
var ecparams = ecurve.getCurveByName('secp256k1')
var Point = ecurve.Point
var BigInteger = crypto.BigInteger

Stealth.MAINNET = 42
Stealth.TESTNET = 43

function Stealth(config) {
    // required
    this.payloadPubKey = config.payloadPubKey
    this.scanPubKey = config.scanPubKey

    // only makes sense if you're the receiver, i.e. you own the stealth addresss
    this.payloadPrivKey = config.payloadPrivKey
    this.scanPrivKey = config.scanPrivKey

    assert(Buffer.isBuffer(this.payloadPubKey), 'payloadPubKey must be a buffer')
    assert(Buffer.isBuffer(this.scanPubKey), 'scanPubKey must be a buffer')

    // default to bitcoin
    this.version = config.version || Stealth.MAINNET
}

Stealth.prototype.toBuffer = function () {
    return bconcat([
        this.version,
        0, // options
        this.scanPubKey,
        1, // number of payload keys, only 1 atm
        this.payloadPubKey,
        1, // number of sigs, only 1 atm
        0 // prefix length, not supported (actually, don't even know what the hell it is)
    ])
}

Stealth.prototype.toJSON = function () {
    // sucky converting to hex, but want to still support Node v0.10
    var o = {
        payloadPrivKey: this.payloadPrivKey ? this.payloadPrivKey.toString('hex') : undefined,
        payloadPubKey: this.payloadPubKey.toString('hex'),
        scanPrivKey: this.scanPrivKey ? this.scanPrivKey.toString('hex') : undefined,
        scanPubKey: this.scanPubKey.toString('hex'),
        version: this.version
    }

    // remove undefineds, when we use to return JSON string, stringify did this
    if (!o.payloadPrivKey) delete o.payloadPrivKey
    if (!o.scanPrivKey) delete o.scanPrivKey

    return o
}

Stealth.prototype.toString = function () {
    var payload = this.toBuffer()
    var checksum = crypto.sha256x2(payload).slice(0, 4)

    return bs58.encode(Buffer.concat([
        payload,
        checksum
    ]))
}

Stealth.fromBuffer = function (buffer) {
    const pkLen = 33
    var pos = 0

    var scanPubKey = buffer.slice(pos, pos += pkLen)
    var nPayloadPubkeys = buffer.readUInt8(pos++)

    var payloadPubkeys = []
    for (var i = 0; i < nPayloadPubkeys; i++) {
        payloadPubkeys.push(buffer.slice(pos, pos += pkLen))
    }

    return new Stealth({
        payloadPubKey: payloadPubkeys[0],
        scanPubKey: scanPubKey
    })
}

Stealth.fromRandom = function (config) {
    config = config || {}
    var rng = config.rng || require('crypto').randomBytes // blinding factor
    var version = config.version || Stealth.MAINNET

    var payloadPrivKey = new Buffer(rng(32))
    var scanPrivKey = new Buffer(rng(32))

    var payloadPubKey = ecparams.G.multiply(BigInteger.fromBuffer(payloadPrivKey)).getEncoded(true)
    var scanPubKey = ecparams.G.multiply(BigInteger.fromBuffer(scanPrivKey)).getEncoded(true)

    return new Stealth({
        scanPrivKey: scanPrivKey,
        scanPubKey: scanPubKey,
        payloadPrivKey: payloadPrivKey,
        payloadPubKey: payloadPubKey,
        version: version
    })
}

// https://gist.github.com/ryanxcharles/1c0f95d0892b4a92d70a
Stealth.prototype.genPaymentPubKeyHash = function (senderPrivKey) {
    var kdf = crypto.hmacSha256

    var Ap = Point.decodeFrom(ecparams, this.scanPubKey)
    var A = Point.decodeFrom(ecparams, this.payloadPubKey)

    var S = Ap.multiply(BigInteger.fromBuffer(senderPrivKey))

    var d = BigInteger.fromBuffer(kdf(S.getEncoded(true)))
    var D = ecparams.G.multiply(d)

    var E = A.add(D)

    var pubKeyHash = crypto.hash160(E.getEncoded(true))
    return pubKeyHash
}

Stealth.prototype.genPaymentAddress = function (senderPrivKey, version) {
    var pubKeyHash = this.genPaymentPubKeyHash(senderPrivKey)
    var payload = Buffer.concat([new Buffer([version || 0x0]), pubKeyHash])
    var checksum = crypto.sha256x2(payload).slice(0, 4)

    return bs58.encode(Buffer.concat([
        payload,
        checksum
    ]))
}

// https://gist.github.com/ryanxcharles/1c0f95d0892b4a92d70a
Stealth.prototype.checkPaymentPubKeyHash = function (opReturnPubKey, pubKeyHashToCompare) {
    assert(this.payloadPrivKey, 'payloadPrivKey must be set if you use this method. i.e. Must be owner / receiver.')
    assert(this.scanPrivKey, 'scanPrivKey must be set if you use this method. i.e. Must be owner / receiver.')

    if (opReturnPubKey.length !== 33) return null

    var kdf = crypto.hmacSha256

    var a = this.payloadPrivKey
    var ap = this.scanPrivKey
    var B = Point.decodeFrom(ecparams, opReturnPubKey)

    var S = B.multiply(BigInteger.fromBuffer(ap))

    var d = kdf(S.getEncoded(true))
    var e = BigInteger.fromBuffer(a).add(BigInteger.fromBuffer(d)).mod(ecparams.n)

    var E = ecparams.G.multiply(e)

    var pubKeyHash = crypto.hash160(E.getEncoded(true))
    if (pubKeyHash.toString('hex') !== pubKeyHashToCompare.toString('hex')) {
        return null
    }

    return {
        privKey: e.toBuffer(32),
        pubKey: E.getEncoded(true)
    }
}

Stealth.fromJSON = function (json) {
    var o
    if (typeof json === 'string') {
        o = JSON.parse(json)
    } else {
        o = json
    }

    return new Stealth({
        payloadPubKey: new Buffer(o.payloadPubKey, 'hex'),
        scanPubKey: new Buffer(o.scanPubKey, 'hex'),
        payloadPrivKey: o.payloadPrivKey ? new Buffer(o.payloadPrivKey, 'hex') : undefined,
        scanPrivKey: o.scanPrivKey ? new Buffer(o.scanPrivKey, 'hex') : undefined,
        version: o.version
    })
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

    return Stealth.fromBuffer(buffer)
}

function bconcat(arr) {
    arr = arr.map(function (item) {
        return Buffer.isBuffer(item) ? item : new Buffer([item])
    })
    return Buffer.concat(arr)
}

module.exports = Stealth