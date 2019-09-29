import crypto from './crypto';
import * as common from './common';

const ecurve = require('ecurve');

const ecparams = ecurve.getCurveByName('secp256k1');
const { Point } = ecurve;
const { BigInteger } = crypto;

/**
 * Pedersen commitment constant
 * G is a universally agreed-upon base point.
 * H is an agreed-upon base point within Monero's implementation of the Pedersen commitment scheme.
 * It is chosen arbitrarily such that it is impossible to know the discrete log with respect to G
 * (i.e. there is some x such that xG == H,
 * but x will never be known).
 * The security of Pedersen commitments relies on x being unknowable.
 * G = ecparams.G
 */
const PEDERSON_COMMITMENT_H = [
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    '31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904',
];
// must create the H ourself because it's not in the ecurve lib
const basePointH = new Point.fromAffine(ecparams,
    new BigInteger(PEDERSON_COMMITMENT_H[0], 16),
    new BigInteger(PEDERSON_COMMITMENT_H[1], 16));

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
        const basePointG = ecparams.G;
        const commitment = basePointG.multiply(
            BigInteger.fromHex(mask),
        )
            .add(basePointH.multiply(
                BigInteger.fromHex(
                    common.numberToHex(amount),
                ),
            ));

        return commitment.getEncoded(encoded);
    }

    /**
     * Generate Pedersen-commitment from transaction public key
     * this use will be use when you don't have
     * mask - normally base on utxo return from smart-contract
     * @param {number} amount You want to hide
     * @param {object} txpub Object includes X and YBit returns from utxo
     * @param {Buffer} privateViewKey Hex string private view key
     * @param {boolean} expected output in long-form or short-form,
     * encoded = true -> short-form, encoded = false -> long-form
     * @returns {object} commitment = hs(txpub*private_view_key)*G + amount*H
     */
    static genCommitmentFromTxPub(amount, txpub, privateViewKey, encoded = true) {
        const lfTx = ecparams.pointFromX(parseInt(txpub.YBit) % 2 === 1,
            BigInteger(txpub.X)).getEncoded(false);

        const B = Point.decodeFrom(ecparams, lfTx);

        const ECDHSharedSerect = B.multiply(BigInteger.fromBuffer(privateViewKey));

        const basePointG = ecparams.G;
        const commitment = basePointG.multiply(
            BigInteger.fromBuffer(
                crypto.hmacSha256(ECDHSharedSerect.getEncoded(true)),
            ),
        )
            .add(basePointH.multiply(
                BigInteger.fromHex(
                    common.numberToHex(amount),
                ),
            ));

        return commitment.getEncoded(encoded);
    }

    /**
     * Sum commitments from a set of UTXO instance
     * @param {object - UTXO} UTXO instance
     * @param {string} privateKey privatekey for decode amount, ecdh and prove those utxo
     * belonging
     * @returns {Point} result from sum
     */
    static sumCommitmentsFromUTXOs(inputUtxos, privateKey) {
        let sumInput = null;
        for (let index = 0; index < inputUtxos.length; index++) {
            const UTXOIns = inputUtxos[index];
            const decodedData = UTXOIns.isMineUTXO(privateKey);
            const basePointG = ecparams.G;

            const commitment = basePointG.multiply(
                BigInteger.fromHex(decodedData.mask),
            )
                .add(basePointH.multiply(
                    BigInteger.fromHex(
                        common.numberToHex(decodedData.amount),
                    ),
                ));

            if (!sumInput) {
                sumInput = commitment;
            } else {
                sumInput = sumInput.add(commitment);
            }
        }

        return sumInput;
    }

    /**
     * Sum commitments calculated from generateProof
     * @param {array} commitments array in full length
     * @returns {Point} result from sum
     */
    static sumCommitments(commitments) {
        let sumInput = null;
        for (let index = 0; index < commitments.length; index++) {
            const commitment = Point.decodeFrom(ecparams, commitments[index]);

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
        const lfCommitment = ecparams.pointFromX(parseInt(commitment.YBit) % 2 === 1,
            BigInteger(commitment.X));
        return this.genCommitment(amount, mask).toString('hex') === lfCommitment.getEncoded(true).toString('hex');
    }
}

export default Commitment;
