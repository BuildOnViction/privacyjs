import ecurve from 'ecurve';
// import Web3 from 'web3';
// import { keccak256 } from 'js-sha3';
import Address from './address';
import Stealth from './stealth';
import crypto from './crypto';
import {
    numberToHex,
    bconcat,
    hextobin,
    bintohex,
    soliditySha3,
} from './common';

const { BigInteger } = crypto;
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
    * 0 - _pubkeyX: stealth_address_X, short form of a point in ECC
    * 1 - _pubkeyYBit: '', // bit indicate odd or even of stealth_address_Y
    * 2 - _amount: encrypt_AES(shared_ECDH, amount),
    *_3 - _txPubX: transation_public_key_X, short form of a point in ECC
    * 4 - _txPubYBit
    * 5 - _index
    * 6 - _mask
    *
*/

class UTXO {
    /**
     *
     * @param {object} utxo
     */
    constructor(utxo) {
        // this.commitmentX = utxo['0'];
        // this.commitmentYBit = utxo['1'];
        this.pubkeyX = utxo['0'];
        this.pubkeyYBit = utxo['1'];
        this.amount = numberToHex(utxo['2']);
        this.txPubX = utxo['3'];
        this.txPubYBit = utxo['4'];
        this.index = utxo['5'];
        this.mask = numberToHex(utxo['6']);
    }

    /**
     * Check if this utxo belong to account base on a secretkey
     * @param {string} privateSpendKey Hex string of private spend key - in other word serectkey
     * @returns {object} amount, keys
     */
    isMineUTXO(privateSpendKey) {
        const receiver = new Stealth({
            ...Address.generateKeys(privateSpendKey),
        });
        const isYStealthOdd = parseInt(this.pubkeyYBit) % 2 === 1;
        const longFormStealth = ecparams.pointFromX(isYStealthOdd,
            BigInteger(this.pubkeyX));

        const isYTxPublicKeyOdd = parseInt(this.txPubYBit) % 2 === 1;
        const longFormTxPublicKey = ecparams.pointFromX(isYTxPublicKeyOdd,
            BigInteger(this.txPubX));

        return receiver.checkTransactionProof(
            longFormTxPublicKey.getEncoded(false),
            longFormStealth.getEncoded(false),
            this.amount,
            this.mask,
        );
    }

    /**
     * Generate hash data as signing input to claim this utxo belongs to who owns privatekey
     * @param {string} targetAddress targetAddress who you're sending this utxo for
     * @returns {string} delegate data of utxo
     */
    getHashData(targetAddress) {
        const lfCommitment = ecparams.pointFromX(parseInt(this.commitmentYBit) % 2 === 1,
            BigInteger(this.commitmentX));
        const longFormStealth = ecparams.pointFromX(parseInt(this.pubkeyYBit) % 2 === 1,
            BigInteger(this.pubkeyX));

        // return keccak256(
        // return Web3.utils.soliditySha3(
        return soliditySha3(
            bintohex(bconcat([
                lfCommitment.getEncoded(false),
                longFormStealth.getEncoded(false),
                hextobin(targetAddress),
            ])),
        );
    }

    /**
     * create signature of an UTXO to send to smart-contract to withdraw
     * TODO: future we need to implement ring-signatureCT (monero-like) to prove
     * @param {string} privateKey
     * @results {array} DER encoded signature in array
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

    /**
     * From direct getUTXO rpc
     * //TODO uniform return data
     * the data structure is a bit different to the event data when deposit
     * ['4'] store the encryptedAmount and encryptedMask perspectively
     * UTXO structure input
     * 0 - _commitmentX:
     * 1 - _commitmentYBit: ,
     * 2 - _pubkeyX: stealth_address_X, short form of a point in ECC
     * 3 - _pubkeyYBit: '', // bit indicate odd or even of stealth_address_Y
     * 4 - [_amount, mask]: encrypt_AES(shared_ECDH, amount),
     *_5 - _txPubX: transation_public_key_X, short form of a point in ECC
     * 6 - _txPubYBit
     */
    static fromRPCGetUTXO(utxo, index) {
        return new UTXO({
            0: utxo['2'],
            1: utxo['3'],
            2: utxo['4'][0],
            3: utxo['5'],
            4: utxo['6'],
            5: index || -1,
            6: numberToHex(utxo['4'][1]),
        });
    }
}

export default UTXO;
