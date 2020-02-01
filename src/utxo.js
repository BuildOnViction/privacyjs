/* eslint-disable quote-props */
// @flow
import assert from 'assert';
import toBN from 'number-to-bn';
import { generateKeys } from './address';
import Stealth from './stealth';

// import { BigInteger } from './constants';
import {
    numberToHex,
    bconcat,
    hextobin,
    bintohex,
    soliditySha3,
    // toBN,
} from './common';

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');
type Signature = EC.Signature;

// type Signature = require('elliptic').Signature;

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
    * 2 - [EncryptedAmount, EncryptedMask],
    * 3 - _index
    * 4 - txID
*/

type UTXOType = {
    '0': {
        '0': string,
        '1': string,
        '2': string
    },
    '1': {
        '0': string,
        '1': string,
        '2': string
    },
    '2': {
        '0': string,
        '1': string
    },
    '3': number
}

class UTXO {
    commitmentX: string;

    commitmentYBit: string;

    pubkeyX: string;

    pubkeyYBit: string;

    amount: string;

    mask: string;

    txPubX: string;

    txPubYBit: string;

    index: number;

    lfStealth: secp256k1.curve.point;

    lfTxPublicKey: secp256k1.curve.point;

    lfCommitment: secp256k1.curve.point;

    decodedAmount: string;

    decodedMask: string;

    privKey: string;

    /**
     * @param {UTXOType} utxo
     */
    constructor(utxo: UTXOType) {
        this.commitmentX = utxo['0']['0'];
        this.commitmentYBit = utxo['1']['0'];
        this.pubkeyX = utxo['0']['1'];
        this.pubkeyYBit = utxo['1']['1'];
        this.amount = numberToHex(utxo['2'][0]);
        this.mask = numberToHex(utxo['2'][1]);
        this.txPubX = utxo['0']['2'];
        this.txPubYBit = utxo['1']['2'];
        this.index = parseInt(utxo['3']);
        this.txID = parseInt(utxo['4']);

        assert(this.txID >= 0, 'TxId not found');

        assert(this.index >= 0, 'utxos\'index not found');

        this.lfStealth = secp256k1.curve.pointFromX(
            toBN(this.pubkeyX),
            parseInt(this.pubkeyYBit) % 2 === 1,
        );

        this.lfTxPublicKey = secp256k1.curve.pointFromX(
            toBN(this.txPubX),
            parseInt(this.txPubYBit) % 2 === 1,
        );

        this.lfCommitment = secp256k1.curve.pointFromX(
            toBN(this.commitmentX),
            parseInt(this.commitmentYBit) % 2 === 1,
        );
    }

    /**
     * Check if this utxo belong to account base on a secretkey
     * @param {string} privateSpendKey Hex string of private spend key - in other word serectkey
     * @returns {object} amount, keys
     */
    checkOwnership(privateSpendKey: string) {
        const receiver = new Stealth({
            ...generateKeys(privateSpendKey),
        });

        const decodedData = receiver.checkTransactionProof(
            this.lfTxPublicKey.encode('hex', false),
            this.lfStealth.encode('hex', false),
            this.amount,
            this.mask,
        );

        if (decodedData) {
            this.decodedAmount = decodedData.amount;
            this.decodedMask = decodedData.mask;
            this.privKey = decodedData.privKey;
        }

        return decodedData;
    }

    /**
     * Generate hash data as signing input to claim this utxo belongs to who owns privatekey
     * @param {string} targetAddress targetAddress who you're sending this utxo for
     * @returns {string} delegate data of utxo
     */
    getHashData(targetAddress: string) {
        return soliditySha3(
            bintohex(bconcat([
                this.lfCommitment.encode('array', false),
                this.lfStealth.encode('array', false),
                hextobin(targetAddress),
            ])),
        );
    }

    /**
     * Create signature of an UTXO to send to smart-contract to withdraw
     * @deprecated since version 0.3
     * @param {string} privateKey
     * @results {ec.Signature} include the ec.Signature you can convert to anyform after that
     */
    sign(privateKey: string, targetAddress: string): Signature {
        // Generate keys
        const key = secp256k1.keyFromPrivate(privateKey);

        const context = this.getHashData(targetAddress);

        const signature = key.sign(context);

        // Export DER encoded signature in Array
        // this.derSign = signature.toDER();

        return signature;
    }

    /** Return the secret value use for RingCT in long form
     * value = hs(ECDH) + private_spend_key
     * @param {string} privateSpendKey of the owner - length 32 bytes
     * @returns {string} ringCTPrivateKey in 32 bytes format
     */
    getRingCTKeys(privateSpendKey: string) {
        const decodedUTXO = this.checkOwnership(privateSpendKey);
        assert(decodedUTXO, " Can't decode utxo that not belongs");

        return {
            privKey: decodedUTXO.privKey,
            pubKey: decodedUTXO.pubKey,
        };
    }

    // static toRawFormat(proof: Proof): UTXOType {
    //     return {
    //         '0': {
    //             '0': proof.commitment.slice(1, 33).join(''),
    //             '1': proof.onetimeAddress.slice(1, 33).join(''),
    //             '2': proof.txPublicKey.slice(1, 33).join(''),
    //         },
    //         '1': {
    //             '0': BigInteger.fromBuffer(proof.commitment.slice(-33)).isEven() ? '0' : '1',
    //             '1': BigInteger.fromBuffer(proof.onetimeAddress.slice(-33)).isEven() ? '0' : '1',
    //             '2': BigInteger.fromBuffer(proof.txPublicKey.slice(-33)).isEven() ? '0' : '1',
    //         },
    //         '2': {
    //             '0': proof.encryptedAmount,
    //             '1': proof.encryptedMask,
    //         },
    //         '3': proof.index,
    //     };
    // }
}

export default UTXO;
