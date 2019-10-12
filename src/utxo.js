import ecurve from 'ecurve';
// import Web3 from 'web3';
// import { keccak256 } from 'js-sha3';
import { generateKeys } from './address';
import Stealth from './stealth';
import { BigInteger } from './crypto';
import {
    numberToHex,
    bconcat,
    hextobin,
    bintohex,
    soliditySha3,
} from './common';

const ecparams = ecurve.getCurveByName('secp256k1');
const EC = require('elliptic').ec;

/**
 * TXO stands for the unspent output from bitcoin transactions.
 * Each transaction begins with coins used to balance the smart contrat.
 * UTXOs are processed continuously and are responsible for beginning and ending each transaction.
 * Confirmation of transaction results in the removal of spent coins from the UTXO smart-contract.
 * But a record of the spent coins still exists on the smart contrat.
 */

/* UTXO structure input
    * 0 - [commitmentX, pubkeyX, txPubX],
    * 1 - [commitmentYBit, pubkeyYBit, txPubYBit],
    * 2 - [amount, mask],
    * 3 - _index
    *
*/

class UTXO {
    /**
     *
     * @param {object} utxo
     * @param {privateKey} Optional
     */
    constructor(utxo) {
        this.commitmentX = utxo['0']['0'];
        this.commitmentYBit = utxo['1']['0'];
        this.pubkeyX = utxo['0']['1'];
        this.pubkeyYBit = utxo['1']['1'];
        this.amount = numberToHex(utxo['2'][0]);
        this.mask = numberToHex(utxo['2'][1]);
        this.txPubX = utxo['0']['2'];
        this.txPubYBit = utxo['1']['2'];
        this.index = utxo['3'];

        this.lfStealth = ecparams.pointFromX(parseInt(this.pubkeyYBit) % 2 === 1,
            BigInteger(this.pubkeyX));

        this.lfTxPublicKey = ecparams.pointFromX(parseInt(this.txPubYBit) % 2 === 1,
            BigInteger(this.txPubX));

        this.lfCommitment = ecparams.pointFromX(parseInt(this.commitmentYBit) % 2 === 1,
            BigInteger(this.commitmentX));
    }

    /**
     * Check if this utxo belong to account base on a secretkey
     * @param {string} privateSpendKey Hex string of private spend key - in other word serectkey
     * @returns {object} amount, keys
     */
    checkOwnership(privateSpendKey) {
        const receiver = new Stealth({
            ...generateKeys(privateSpendKey),
        });

        return receiver.checkTransactionProof(
            this.lfTxPublicKey.getEncoded(false),
            this.lfStealth.getEncoded(false),
            this.amount,
            this.mask,
        );
    }

    /**
     * Generate hash data as signing input to claim this utxo belongs to who owns privatekey
     * // TODO take note about the length of output
     * @param {string} targetAddress targetAddress who you're sending this utxo for
     * @returns {string} delegate data of utxo
     */
    getHashData(targetAddress) {
        return soliditySha3(
            bintohex(bconcat([
                this.lfCommitment.getEncoded(false),
                this.lfStealth.getEncoded(false),
                hextobin(targetAddress),
            ])),
        );
    }

    /**
     * create signature of an UTXO to send to smart-contract to withdraw
     * TODO: future we need to implement ring-signatureCT (monero-like) to prove
     * @param {string} privateKey
     * @results {ec.Signature} include the ec.Signature you can convert to anyform after that
     */
    sign(privateKey, targetAddress) {
        const secp256k1 = new EC('secp256k1');

        // Generate keys
        const key = secp256k1.keyFromPrivate(privateKey);

        const context = this.getHashData(targetAddress);

        const signature = key.sign(context);

        // Export DER encoded signature in Array
        // this.derSign = signature.toDER();

        return signature;
    }

    /** Return the secret value use for RingCT
     * value = hs(ECDH) + private_spend_key
     * @param {string} privateSpendKey of the owner - length 32 bytes
     * @returns {string} ringCTPrivateKey in 32 bytes format
     */
    getRingCTKeys(privateSpendKey) {
        const decodedUTXO = this.checkOwnership(privateSpendKey);
        return {
            privKey: decodedUTXO.privKey,
            pubKey: decodedUTXO.pubKey,
        };
    }
}

export default UTXO;
