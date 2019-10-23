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
 */

import Web3 from 'web3';
import HDWalletProvider from 'truffle-hdwallet-provider';
import assert from 'assert';
import * as CONSTANT from './constants';
import * as Address from './address';
import Stealth from './stealth';
// import UTXO from './utxo';

// TODO find way to specify the length of each field, address

type SmartContractOpts = {
    RPC_END_POINT: string,
    ADDRESS: string,
    ABI: Array<Object>,
    gasPrice: number | string, // js suport number 3 bit so number here is acceptable
    gas: number | string,
    from: string
};

export default class Wallet {
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

    /**
     *
     * @param {string} privateKey
     * @param {Object} scOpts
     */
    constructor(privateKey: string, scOpts: SmartContractOpts, address: string) {
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
                    receipt.events.NewUTXO.should.be.a('object');
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

    send() {
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
}
