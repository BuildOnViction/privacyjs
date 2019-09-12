const assert = require('assert');
const bs58 = require('bs58');
const ecurve = require('ecurve');
const aes256 = require('aes256');
const crypto = require('./crypto');
const common = require('./common');

const ecparams = ecurve.getCurveByName('secp256k1');
const { Point } = ecurve;
const { BigInteger } = crypto;

function Stealth(config) {
    // required
    this.pubViewKey = typeof config.pubViewKey === 'string' ? new Buffer(config.pubViewKey, 'hex') : config.pubViewKey;
    this.pubSpendKey = typeof config.pubSpendKey === 'string' ? new Buffer(config.pubSpendKey, 'hex') : config.pubSpendKey;

    // only makes sense if you're the receiver, i.e. you own the stealth addresss
    this.privViewKey = typeof config.privViewKey === 'string' ? new Buffer(config.privViewKey, 'hex') : config.privViewKey;
    this.privSpendKey = typeof config.privSpendKey === 'string' ? new Buffer(config.privSpendKey, 'hex') : config.privSpendKey;

    assert(Buffer.isBuffer(this.pubViewKey), 'pubViewKey must be a buffer');
    assert(Buffer.isBuffer(this.pubSpendKey), 'pubSpendKey must be a buffer');
}

Stealth.fromBuffer = function (buffer) {
    const pkLen = 33;
    let pos = 0;

    const pubSpendKey = buffer.slice(pos, pos += pkLen);
    const pubViewKey = buffer.slice(pos, pos += pkLen);

    return new Stealth({
        pubViewKey,
        pubSpendKey,
    });
};

/**
 * genTransactionProof generates one-time address (stealth address) and
 * tx public key - base on ECDH algorithm for sharing serect_key
 * read https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-part-2-stealth-addresses
 * for further information
 * to prove the asset belongs the receiver with known pair
 * (public spend key/public view key of receiver)
 * @returns {object} onetimeAddress and txPublicKey
 */
Stealth.prototype.genTransactionProof = function (amount, pubSpendKey, pubViewKey) {
    const hs = crypto.hmacSha256; // hasing function return a scalar
    const basePoint = ecparams.G; // secp256k1 standard base point
    const receiverPubViewKey = Point.decodeFrom(ecparams, pubViewKey || this.pubViewKey);
    const receiverPubSpendKey = Point.decodeFrom(ecparams, pubSpendKey || this.pubSpendKey);

    const blindingFactor = BigInteger.fromBuffer(new Buffer(crypto.randomHex(32), 'hex'));

    const ECDHSharedSerect = receiverPubViewKey.multiply(blindingFactor);

    const f = BigInteger.fromBuffer(hs(ECDHSharedSerect.getEncoded(true)));

    const F = basePoint.multiply(f);

    const onetimeAddress = receiverPubSpendKey.add(F).getEncoded(true);

    const txPublicKey = basePoint.multiply(blindingFactor).getEncoded(true);

    const mask = aes256.encrypt(common.bintohex(ECDHSharedSerect.getEncoded(true)),
        amount.toString());

    return {
        onetimeAddress,
        txPublicKey,
        mask,
    };
};

/**
 * checkTransactionProof check if this user owns the UTXO or not
 * @param {string} onetimeAddress UTXO's steal address
 * @param {string} txPublicKey UTXO's transaction public key
 * @param {string} mask optional = aes256(sharedSecret, amount)
 * @returns {object} amount
 */
Stealth.prototype.checkTransactionProof = function (txPublicKey, onetimeAddress, mask) {
    assert(this.privViewKey, 'privViewKey required');
    assert(this.privSpendKey, 'privSpendKey required');

    if (txPublicKey.length !== 33) return null;

    const hs = crypto.hmacSha256;

    const B = Point.decodeFrom(ecparams, txPublicKey);

    const ECDHSharedSerect = B.multiply(BigInteger.fromBuffer(this.privViewKey));

    const d = hs(ECDHSharedSerect.getEncoded(true));
    const e = BigInteger.fromBuffer(this.privSpendKey)
        .add(BigInteger.fromBuffer(d))
        .mod(ecparams.n);

    const E = ecparams.G.multiply(e);

    const onetimeAddressCalculated = E.getEncoded(true);
    if (onetimeAddressCalculated.toString('hex') !== onetimeAddress.toString('hex')) {
        return null;
    }

    const amount = aes256.decrypt(common.bintohex(ECDHSharedSerect.getEncoded(true)), mask);

    return {
        privKey: common.bintohex(e.toBuffer(32)),
        pubKey: E.getEncoded(true),
        amount,
    };
};

/**
 * Generate Pedersen-commitment for hiding amount in  transaction,
 * used in Smart-contract to verify money flow
 * @param {number} amount You want to hide
 * @returns {object} commitment
 */
Stealth.prototype.genCommitment = function (amount) {
    const basePoint = ecparams.G; // secp256k1 standard base point
    const receiverPubViewKey = Point.decodeFrom(ecparams, this.pubViewKey);
    const blindingFactor = BigInteger.fromBuffer(new Buffer(crypto.randomHex(32), 'hex'));
    const ECDHSharedSerect = receiverPubViewKey.multiply(blindingFactor);

    const commitment = basePoint.multiply(blindingFactor).add(ECDHSharedSerect.add(amount));

    return commitment.getEncoded(true);
};

/**
 * Verify Pedersen-commitment
 * @param {string} amount You want to hide
 */
Stealth.prototype.verifyCommitment = function () {
    return true;
};

/**
 * Build Stealth address from privacy address of receiver - normally for sender
 * stealth address = 33 bytes (public spend key) + 33 bytes(public view key) +
 * 4 bytes (checksum)
 * @param {string}  str Privacy address of receiver
 * @returns {Object} Stealth instance
 */
Stealth.fromString = function (str) {
    // uncompress base58 address
    const buffer = new Buffer(bs58.decode(str));

    // validate the checksum
    const decodedPrivacyAddress = common.bintohex(buffer);

    // payload from 0 to length -8 (each hex = 4 bit)
    const payload = decodedPrivacyAddress.slice(0, -8);

    const newChecksum = common.fastHash(payload).slice(0, 8);
    const checksum = decodedPrivacyAddress.slice(-8); // real checksum

    assert.deepEqual(newChecksum, checksum, 'Invalid checksum');

    return Stealth.fromBuffer(buffer.slice(0, -4));
};

// function bconcat(arr) {
//     arr = arr.map(item => (Buffer.isBuffer(item) ? item : new Buffer([item])));
//     return Buffer.concat(arr);
// }

module.exports = Stealth;
