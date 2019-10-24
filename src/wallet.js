/* eslint-disable class-methods-use-this */
// @flow

/**
 * High-level api for thirdparty using tomoprivacy token
 * to privately send money.
 * This is not intended support when this lib created
 * because those action strongly depends on web3.js - a very big
 * and heavy library but not many people understand the flow
 * and definition of Zero-knowledge terms (commitment, one time address
 * ring-signature, ring confidential transaction, bulletproof, rang proof)
 * so they might pass wrong data cause losing money
 *
 * // TODO what happen if the server passing different methods in abi
 * // we need to find a way to specify it in construction
 */

import Web3 from 'web3';
import EventEmitter from 'eventemitter3';
import HDWalletProvider from 'truffle-hdwallet-provider';
import assert from 'assert';
import * as CONSTANT from './constants';
import * as Address from './address';
import Stealth from './stealth';
import UTXO from './utxo';
import { BigInteger } from './crypto';
import { toBN } from './common';

// TODO find way to specify the length of each field, address
type SmartContractOpts = {
    RPC_END_POINT: string,
    ADDRESS: string,
    ABI: Array<Object>,
    gasPrice: number | string, // js suport number 3 bit so number here is acceptable
    gas: number | string,
    from: string,
    methodsMapping: ?{
        deposit: string,
        send: string,
        withdraw: string,
        getTX: string,
    }
};

type DecodedProof = {
    privKey: string, // private key of one-time-address
    pubKey: Buffer, // public key of one-time-address in encoded form
    amount: ?string,
    mask: ?string
};

export default class Wallet extends EventEmitter {
    addresses: {
        privSpendKey: string,
        pubSpendKey: string,
        privViewKey: string,
        pubViewKey: string,
        pubAddr: string,
    }

    stealth: Stealth;

    // smart contract options for signing tx using web3js
    scOpts: SmartContractOpts;

    privacyContract: Web3.eth.Contract

    // always store in bignumber for easier calculation
    balance: BigInteger;

    // unspent transaction outputs
    utxos: Array<UTXO>;

    /**
     *
     * @param {string} privateKey
     * @param {Object} scOpts
     */
    constructor(privateKey: string, scOpts: SmartContractOpts, address: string) {
        super();
        assert(privateKey && privateKey.length === CONSTANT.PRIVATE_KEY_LENGTH, 'Malform private key !!');
        assert(address && address.length === 42, 'Malform address !!');

        this.addresses = Address.generateKeys(privateKey);
        this.stealth = new Stealth({
            ...this.addresses,
        });
        this.scOpts = scOpts;
        this.scOpts.gasPrice = this.scOpts.gasPrice || CONSTANT.DEFAULT_GAS_PRICE;
        this.scOpts.gas = this.scOpts.gas || CONSTANT.DEFAULT_GAS;
        this.scOpts.from = this.scOpts.from || address;
        this.scOpts.methodsMapping = this.scOpts.methodsMapping || {
            deposit: 'deposit',
            send: 'send',
            withdraw: 'withdraw',
            getTX: 'getUTXO',
        };
        const provider = new HDWalletProvider(privateKey, scOpts.RPC_END_POINT);
        const web3 = new Web3(provider);

        // TODO address will be dynamic generated in the future for hiding sender private
        // because sc extending TRC21
        this.privacyContract = new web3.eth.Contract(
            scOpts.ABI, scOpts.ADDRESS,
        );
    }

    /**
     * Generate
     * - tx_publickey, oneTimeAddress ==> for proving ownership of utxo
     * - commitment => for hiding the transaction value
     * - encryptedAmount = AES(amount, ECDH) for checking balance
     * - encryptedMask = AES(amount, mask) for future generating ringct
     * @param {number} amount balance of new utxo
     * @param {string} [pubSpendKey] Public spend key in hex (without 0x)
     * @param {string} [pubViewKey] Public view key in hex (without 0x)
     * @param {buffer} [predefinedMask] Optional, in case you got mask already and don't want to generate again
     * @returns {Array<string>} onetimeAdressX, onetimeAddressY, txPublicKeyX, txPublicKeyY,
     * mask, encryptedAmount, encryptedMask in hex string
     */
    _genUTXOProof(amount: number, pubSpendKey: ?string, pubViewKey: ?string, predefinedMask: ?Buffer): Array<string> {
        const proof = this.stealth.genTransactionProof(amount, pubSpendKey, pubViewKey, predefinedMask);

        return [
            `0x${proof.onetimeAddress.toString('hex').substr(2, 64)}`, // the X part of point
            `0x${proof.onetimeAddress.toString('hex').substr(-64)}`, // the Y part of point
            `0x${proof.txPublicKey.toString('hex').substr(2, 64)}`, // the X part of point
            `0x${proof.txPublicKey.toString('hex').substr(-64)}`, // the Y par of point,
            `0x${proof.mask}`,
            `0x${proof.encryptedAmount}`, // encrypt of amount using ECDH,
            `0x${proof.encryptedMask}`,
        ];
    }

    /**
     * Send money normal address to privacy address
     * @param {number} amount Plain money to send to privacy address
     * @returns {Object} TxObject includes UTXO and original proof
     */
    deposit(amount: number): Promise<any> {
        return new Promise((resolve, reject) => {
            const proof = this._genUTXOProof(amount);

            this.privacyContract.methods.deposit(...proof)
                .send({
                    from: this.scOpts.from,
                    value: amount,
                })
                .on('error', (error) => {
                    reject(error);
                })
                .then((receipt) => {
                    try {
                        resolve({
                            utxo: receipt.events.NewUTXO.returnValues,
                            proof,
                        });
                    } catch (error) {
                        reject(error);
                    }
                });
        });
    }

    scan() {
        throw Error('Not implemented yet');
    }

    store() {
    }

    qrUTXOData() {
    }

    async send(privacyAddress: string, amount: string | number) {
        if (!this.balance) {
            this.emit('PRIVACY_WALLET_START_SCANNING');

            await this.scan();

            this.emit('PRIVACY_WALLET_STOP_SCANNING');
        }
        const biAmount = toBN(amount);

        assert(biAmount.compareTo(this.balance) === '+', 'Balance is not enough');

        const selectedUTXOs = this._selectUTXOs(biAmount);

        const {
            spendings, outputs, ringct, bulletproof,
        } = this._generateTX(biAmount, selectedUTXOs);

        const proof = this._makePrivateSendProof(spendings, outputs, ringct, bulletproof);

        return new Promise((resolve, reject) => {
            this.privacyContract.methods[this.scOpts.methodsMapping.send](proof)
                .send({
                    from: this.scOpts.from,
                })
                .on('error', (error) => {
                    reject(error);
                })
                .then((receipt) => {
                    try {
                        resolve({
                            utxo: receipt.events.NewUTXO.returnValues,
                            proof,
                        });
                    } catch (error) {
                        reject(error);
                    }
                });
        });
    }

    _makePrivateSendProof(spendings, outputs, ringct, bulletproof) {

    }

    fromStorage() {

    }

    withdraw() {

    }

    getUTXOs() {

    }

    getBalance() {

    }

    isSpend() {

    }

    /**
     * Check utxo's proof belongs
     * consider changing input format
     * @param {Buffer} txPubkey long-form point = Point.getEncoded(false)
     * @param {*} stealth long-form point = Point.getEncoded(false)
     * @param {*} encryptedAmount AES(ECDH, amount) in hex string
     * @returns {Object} stealth_private_key, stealth_public_key, real amount
     */
    isMine(txPubkey: Buffer, stealth: Buffer, encryptedAmount: string): DecodedProof {
        return this.stealth.checkTransactionProof(
            txPubkey, stealth, encryptedAmount,
        );
    }

    /**
     * Check utxo belongs
     * @param {UTXO} utxo UTXO instance
     * @returns {Object} stealth_private_key, stealth_public_key, real amount
     */
    isMineUTXO(utxo: UTXO): DecodedProof {
        return utxo.checkOwnership(this.addresses.privSpendKey);
    }

    decimalBalance() {
        return this.balance ? Web3.utils.toBN('0x' + this.balance.toHex()).toString() : '0';
    }

    hexBalance() {
        return this.balance ? '0x' + this.balance.toHex() : '0x0';
    }
}
