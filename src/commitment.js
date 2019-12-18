import toBN from 'number-to-bn';
import { baseH } from './constants';
import { numberToHex, BigInteger } from './common';

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

/**
 * Pedersen commitment constant
 * G is a universally agreed-upon base point.
 * H is an agreed-upon base point within Tomochain's implementation of the Pedersen commitment scheme.
 * It is chosen arbitrarily such that it is impossible to know the discrete log with respect to G
 * (i.e. there is some x such that xG == H, but x will never be known).
 * The security of Pedersen commitments relies on x being unknowable.
 * G = ecparams.G
 */
class Commitment {
    /**
     * Generate Pedersen-commitment for hiding amount in  transaction,
     * used in Smart-contract to verify money flow
     * @param {number} amount Decimal You want to hide
     * @param {string} mask Hash(ECDH_Share_secret)
     * @param {boolean} expected output in long-form or short-form,
     * encoded = true -> short-form, encoded = false -> long-form
     * @returns {object} commitment = mask*G + amount*H
     */
    static genCommitment(amount, mask, encoded = true) {
        const baseG = secp256k1.g;

        if (!amount || amount.toString() === '0') {
            return baseG.mul(
                BigInteger.fromHex(mask),
            ).encode('hex', encoded);
        }

        if (!mask || mask.toString() === '0') {
            return baseH.mul(
                BigInteger.fromHex(
                    numberToHex(amount),
                ),
            ).encode('hex', encoded);
        }

        return baseG.mul(
            BigInteger.fromHex(mask),
        )
            .add(baseH.mul(
                BigInteger.fromHex(
                    numberToHex(amount),
                ),
            )).encode('hex', encoded);
    }

    /**
     * Sum commitments calculated from generateProof
     * @param {array} commitments array in full length
     * @returns {Point} result from sum
     */
    static sumCommitments(commitments) {
        let sumInput = null;
        for (let index = 0; index < commitments.length; index++) {
            const commitment = secp256k1.curve.decodePoint(commitments[index]);

            if (!sumInput) {
                sumInput = commitment;
            } else {
                sumInput = sumInput.add(commitment);
            }
        }

        return sumInput;
    }

    /**
     * Verify Pedersen-commitment
     * @param {number} amount You want to hide
     * @param {string} mask Hash(ECDH_Share_secret)
     * @param {commitment} commitment object
     * @returns {boolean} true if this is my signed commitment elsewise return false
     */
    static verifyCommitment(amount, mask, commitment) {
        const lfCommitment = secp256k1.curve.pointFromX(
            toBN(commitment.X), parseInt(commitment.YBit) % 2 === 1,
        );
        return this.genCommitment(amount, mask) === lfCommitment.encode('hex', true);
    }
}

export default Commitment;
