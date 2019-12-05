import {
    encode, decode, hmacSha256, randomBI,
} from './crypto';
import { BigInteger } from './constants';
// eslint-disable-next-line import/no-cycle
import Commitment from './commitment';
import * as common from './common';

const assert = require('assert');
const bs58 = require('bs58');

// const ecparams = ecurve.getCurveByName('secp256k1');
// const { Point } = ecurve;
const EC = require('elliptic').ec;

// type Point = Curve.short.ShortPoint;

const secp256k1 = new EC('secp256k1');

export const toPoint = (data: Buffer | Array | String) : secp256k1.curve.point => {
    if (typeof (data) !== 'string') {
        data = data.toString('hex');
    }

    // just X + Y as input, add prefix 04
    if (data.length === 128) {
        data = '04' + data;
    }

    // short form
    if (data.length === 66) {
        return secp256k1.curve.pointFromX(
            data.substr(2, 64),
            parseInt(data.substr(0, 2)) % 2 === 1,
        );
    }

    // long form
    if (data.length === 130) {
        return secp256k1.curve.pointFromJSON([
            data.substr(2, 64),
            data.substr(66, 64),
        ]);
    }
};

class Stealth {
    constructor(config) {
        // required
        this.pubViewKey = typeof config.pubViewKey === 'string' ? new Buffer(config.pubViewKey, 'hex') : config.pubViewKey;
        this.pubSpendKey = typeof config.pubSpendKey === 'string' ? new Buffer(config.pubSpendKey, 'hex') : config.pubSpendKey;

        // only makes sense if you're the receiver, i.e. you own the stealth addresss
        this.privViewKey = typeof config.privViewKey === 'string' ? new Buffer(config.privViewKey, 'hex') : config.privViewKey;
        this.privSpendKey = typeof config.privSpendKey === 'string' ? new Buffer(config.privSpendKey, 'hex') : config.privSpendKey;

        assert(Buffer.isBuffer(this.pubViewKey), 'pubViewKey must be a buffer');
        assert(Buffer.isBuffer(this.pubSpendKey), 'pubSpendKey must be a buffer');
    }

    static fromBuffer(buffer) {
        const pkLen = 33;
        let pos = 0;

        const pubSpendKey = buffer.slice(pos, pos += pkLen);
        const pubViewKey = buffer.slice(pos, pos += pkLen);

        return new Stealth({
            pubViewKey,
            pubSpendKey,
        });
    }


    /**
     * GenTransactionProof generates one-time address (stealth address) and
     * tx public key - base on ECDH algorithm for sharing serect_key
     * read https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-part-2-stealth-addresses
     * for further information
     * to prove the asset belongs the receiver with known pair
     * If there is input publickeys -> make transaction for other
     * If there is no input -> deposit yourself to privacy account
     * (public spend key/public view key of receiver)
     * @param {number} amount Plain money
     * @param {string} [pubSpendKey] Public spend key in hex (without 0x)
     * @param {string} [pubViewKey] Public view key in hex (without 0x)
     * @param {buffer} [predefinedMask] Optional, in case you got mask already and don't want to generate again
     * @returns {object} onetimeAddress and txPublicKey
     */
    genTransactionProof(amount, pubSpendKey, pubViewKey, predefinedMask) {
        const hs = hmacSha256; // hasing function return a scalar
        const basePoint = secp256k1.g; // secp256k1 standard base point

        pubViewKey = pubViewKey || this.pubViewKey;
        pubSpendKey = pubSpendKey || this.pubSpendKey;

        const receiverPubViewKey = toPoint(pubViewKey);
        const receiverPubSpendKey = toPoint(pubSpendKey);

        const hexAmount = common.numberToHex(amount.toString());
        // console.log('hexAmount ', hexAmount);
        // const randomHex = 'f042298df7ea67d6bd8cf8e32537f23656ae36d3d9e04955f86997addb2dc4ee';

        const blindingFactor = randomBI();

        const ECDHSharedSerect = receiverPubViewKey.mul(blindingFactor);

        const f = BigInteger.fromBuffer(
            hs(
                Buffer.from(ECDHSharedSerect.encode('array', true)),
            ),
        );

        const F = basePoint.mul(f);

        const onetimeAddress = receiverPubSpendKey.add(F).encode('hex', false);

        const txPublicKey = basePoint.mul(blindingFactor).encode('hex', false);
        // encoded return format: 1 byte (odd or even of ECC) + X (32 bytes)
        // so we generate a hash 32 bytes from 33 bytes
        const aesKey = hs(
            Buffer.from(ECDHSharedSerect.encode('array', false)),
        );

        const encryptedAmount = encode(hexAmount, aesKey);

        // generate mask for sc managing balance
        let mask;
        let commitment;

        // TODO refactor this calculating mask
        /**
         * We always want the mask is 32 bytes
         * so if the prefix is 00 -> turn to 10
         */
        if (!predefinedMask) {
            mask = hs(
                Buffer.from(ECDHSharedSerect.encode('hex', true)),
            ).toString('hex'); // for smart contract only

            // Work around: mask should be a strictly hex 32 bytes
            if (mask.indexOf('00') === 0) {
                mask = '1' + mask.slice(1);
            }

            commitment = Commitment.genCommitment(amount, mask, false);
        } else {
            mask = predefinedMask;
            if (mask.indexOf('00') === 0) {
                mask = '1' + mask.slice(1);
            }
            commitment = Commitment.genCommitment(amount, mask, false);
        }

        const encryptedMask = encode(mask.toString('hex'), aesKey);

        return {
            onetimeAddress,
            txPublicKey,
            encryptedAmount,
            mask,
            commitment,
            encryptedMask,
        };
    }

    /**
     * checkTransactionProof check if this user owns the UTXO or not
     * @param {string} onetimeAddress UTXO's steal address
     * @param {string} txPublicKey UTXO's transaction public key
     * @param {string} [encryptedAmount] optional = aes256(sharedSecret, amount)
     * @param {string} [encryptedMask] optional = aes256(sharedSecret, mask)
     * @returns {object} amount
     */
    checkTransactionProof(txPublicKey, onetimeAddress, encryptedAmount, encryptedMask) {
        assert(this.privViewKey, 'privViewKey required');
        assert(this.privSpendKey, 'privSpendKey required');

        if (txPublicKey.length !== 130) return null;

        const hs = hmacSha256;

        const B = toPoint(txPublicKey);

        const ECDHSharedSerect = B.mul(BigInteger.fromBuffer(this.privViewKey));

        const d = hs(Buffer.from(ECDHSharedSerect.encode('array', true)));
        const e = BigInteger.fromBuffer(this.privSpendKey)
            .add(BigInteger.fromBuffer(d))
            .umod(secp256k1.n);

        const E = secp256k1.g.mul(e);

        const onetimeAddressCalculated = E.encode('hex', false);

        if (onetimeAddressCalculated !== onetimeAddress) {
            return null;
        }

        const returnValue = {
            privKey: common.bintohex(e.toBuffer(32)),
            pubKey: E.encode('hex', true),
        };
        const aesKey = hmacSha256(Buffer.from(ECDHSharedSerect.encode('array', false)));

        if (encryptedAmount) {
            const amount = decode(encryptedAmount, aesKey);
            returnValue.amount = common.hexToNumberString(amount);
        }

        if (encryptedMask) {
            const mask = decode(encryptedMask, aesKey);
            returnValue.mask = mask;
        }

        return returnValue;
    }

    /**
     * encryptedAmount decode the ecdh secretkey and encrypted for new amount
     * we would use this many times for withdraw money from utxo
     * You can use checkTransactionProof above to decode the amount
     * @param {string} onetimeAddress UTXO's steal address
     * @param {string} txPublicKey UTXO's transaction public key
     * @param {string} newAmount plain amount for encrypting
     * @returns {object} encrypted amount
     */
    encryptedAmount(txPublicKey, onetimeAddress, newAmount) {
        assert(this.privViewKey, 'privViewKey required');
        assert(this.privSpendKey, 'privSpendKey required');

        if (txPublicKey.length !== 130) return null;

        const hs = hmacSha256;

        // const B = secp256k1.curve.decodePoint(txPublicKey);
        const B = secp256k1.curve.pointFromJSON([
            txPublicKey.substr(2, 64),
            txPublicKey.substr(66, 64),
        ]);

        const ECDHSharedSerect = B.mul(BigInteger.fromBuffer(this.privViewKey));

        const d = hs(Buffer.from(ECDHSharedSerect.encode('array', true)));
        const e = BigInteger.fromBuffer(this.privSpendKey)
            .add(BigInteger.fromBuffer(d))
            .umod(secp256k1.n);

        const E = secp256k1.g.mul(e);

        const onetimeAddressCalculated = E.encode('hex', false);

        if (onetimeAddressCalculated.toString('hex') !== onetimeAddress.toString('hex')) {
            return null;
        }

        const aesKey = hmacSha256(Buffer.from(ECDHSharedSerect.encode('array', false)));
        const ecptAmount = encode(
            common.numberToHex(newAmount.toString()),
            aesKey,
        );

        return ecptAmount;
    }

    /**
     * Build Stealth address from privacy address of receiver - normally for sender
     * stealth address = 33 bytes (public spend key) + 33 bytes(public view key) +
     * 4 bytes (checksum)
     * @param {string}  str Privacy address of receiver
     * @returns {Object} Stealth instance
     */
    static fromString(str) {
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
    }
}

export default Stealth;
