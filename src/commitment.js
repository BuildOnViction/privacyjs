import { BigI } from './crypto';
import * as common from './common';
// import { baseH } from './constants';

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');
const baseH = secp256k1.curve.point(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    '31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904',
);
// const { Point } = ecurve;

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
        const basePointG = secp256k1.g;

        if (!amount || amount.toString() === '0') {
            return basePointG.mul(
                BigI.fromHex(mask),
            ).encode('hex', encoded);
        }

        if (!mask || mask.toString() === '0') {
            return baseH.mul(
                BigI.fromHex(
                    common.numberToHex(amount),
                ),
            ).encode('hex', encoded);
        }

        return basePointG.mul(
            BigI.fromHex(mask),
        )
            .add(baseH.mul(
                BigI.fromHex(
                    common.numberToHex(amount),
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
            BigI(commitment.X), parseInt(commitment.YBit) % 2 === 1,
        );
        return this.genCommitment(amount, mask) === lfCommitment.encode('hex', true);
    }
}

export default Commitment;
