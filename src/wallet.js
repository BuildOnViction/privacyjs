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
import * as _ from 'lodash';
import numberToBN from 'number-to-bn'; // this is converter to bn.js, this lib support more utils than bigi
import * as CONSTANT from './constants';
import * as Address from './address';
import Stealth from './stealth';
import UTXO from './utxo';
import { BigInteger } from './crypto';
import { toBN } from './common';
import MLSAG from './mlsag';

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
        this.emit('START_DEPOSIT');
        return new Promise((resolve, reject) => {
            const proof = this._genUTXOProof(amount);

            this.privacyContract.methods.deposit(...proof)
                .send({
                    from: this.scOpts.from,
                    value: amount,
                })
                .on('error', (error) => {
                    this.emit('STOP_DEPOSIT', error);
                    reject(error);
                })
                .then((receipt) => {
                    this.emit('FINISH_DEPOSIT', receipt.events);
                    resolve({
                        utxo: receipt.events.NewUTXO.returnValues,
                        proof,
                    });
                });
        });
    }

    scan() {
        this.emit('START_SCANNING');
        try {
            this.emit('FINISH_SCANNING');
            throw new Error('Not implemeted yet');
        } catch (ex) {
            this.emit('STOP_SCANNING');
        }
    }

    store() {
    }

    qrUTXOsData() {
    }

    /**
     * Private send money to privacy address
     * @param {string} privacyAddress
     * @param {string|number} amount
     * @returns {object} includes new utxos and original created proof
     * on some very first version, we store the proof locally to help debugging if error happens
     */
    async send(privacyAddress: string, amount: string | number) {
        assert(privacyAddress.length === CONSTANT.PRIVACY_ADDRESS_LENGTH, 'Malform privacy address !!');

        if (!this.balance) {
            await this.scan();
        }

        const biAmount = toBN(amount);

        assert(biAmount.compareTo(this.balance) === '+', 'Balance is not enough');

        const proof = this._makePrivateSendProof(privacyAddress, biAmount);

        const res = await this._send(proof);

        return res;
    }

    /**
     * Use Web3 to sign and make tx to smart-contract
     * @param {Object} proof
     * @returns {object} new utxos and proof
     */
    _send(proof: Object): Promise<any> {
        return new Promise((resolve, reject) => {
            // ugly syntax
            this.privacyContract.methods[
                this.scOpts.methodsMapping
                && this.scOpts.methodsMapping.send](proof)
                .send({
                    from: this.scOpts.from,
                })
                .on('error', (error) => {
                    reject(error);
                })
                .then((receipt) => {
                    resolve({
                        utxo: receipt.events.NewUTXO.returnValues,
                        proof,
                    });
                });
        });
    }

    // fake decoys by now
    getDecoys(numberOfRing: number): Array<Array<UTXO>> {
        return [
            _.map(Array(numberOfRing), () => []),
        ];
    }

    /**
     * Generate ring confidental transaction proof
     * 1. Generate ring-signature from spending utxos
     * 2. generate additional ring for proof commitment_input = commitment_output
     */
    _genRingCT(spendingUTXOs: Array<UTXO>, outputUTXOs: Array<UTXO>) {
        const numberOfRing = spendingUTXOs.length;
        const ringSize = 12; // 11 decoys + one spending

        // get random utxos for making ring from network
        // number of random utxo = spendingUTXOs * 11 (maximum decoys per ring)
        let decoys = this.getDecoys(numberOfRing);

        // random index each time generating ringct
        const index = Math.round(Math.random() * ringSize);

        // TODO need rewrite - not optimized
        const pubkeys = []; // public keys of utxo
        decoys = _.map(decoys, (decoyRing, counter) => decoyRing.splice(index, 0, spendingUTXOs[counter]));
        _.each(_.flatten(decoys), (decoy) => {
            pubkeys.push(decoy.lfStealth);
        });

        // generating message = Buffer.from([pubOfDecoy1, pubOfDecoy2, ..., pubOfDecoyN])
        const ringSignature = MLSAG.mulSign(
            this.addresses.privSpendKey,
            decoys,
            index,
        );
        const ctSignature = MLSAG.signCommitment(
            this.addresses.privSpendKey,
            decoys,
            outputUTXOs,
            index,
        );

        return Buffer.from(
            // ring signature part
            `${numberToBN(numberOfRing).toString(16, 16)
            }${numberToBN(ringSize).toString(16, 16)
            }${ringSignature.message.toString('hex')
            }${ringSignature.c1.toHex(32)
            }${_.map(_.flatten(ringSignature.s), element => element.toHex(32)).join('')
            }${_.map(_.flatten(pubkeys), pubkey => pubkey.getEncoded(true).toString('hex')).join('')
            }${_.map(_.flatten(ringSignature.I), element => element.getEncoded(true).toString('hex')).join('')
            }${numberToBN(1).toString(16, 16) // start ct part
            }${numberToBN(ringSize).toString(16, 16)
            }${ctSignature.message.toString('hex') // should be ctSignature.message
            }${ctSignature.c1.toHex(32)
            }${_.map(_.flatten(ctSignature.s), element => element.toHex(32)).join('')
            }${_.map(_.flatten(pubkeys), pubkey => pubkey.getEncoded(true).toString('hex')).join('')
            }${_.map(_.flatten(ctSignature.I), element => element.getEncoded(true).toString('hex')).join('')}`,
            'hex',
        );
    }

    /**
     * Generate range proof to prove a number in a range
     * in tomo system, the range from 0 to 2^64
     * we can choose what kind of range proof to use here
     * two supported are bulletproof and aggregate schnorr
     * @param {BigInteger} amount
     * @returns {Buffer} Proof
     */
    _genRangeProof(amount: BigInteger):Buffer {
        return amount.toBuffer();
    }

    /**
     * Generate utxos afer transaction, one for sender (even balance = 0), one for receiver
     * @param {Array<UTXO>} spendingUTXOs spending utxos
     * @param {string} receiver privacy address of receiver
     * @param {BigInteger} amount sending amount
     */
    _genOutputUTXOs(spendingUTXOs: Array<UTXO>, receiver: string, amount: BigInteger): Array<Object> {
        // let sumOfSpendingMasks = BigInteger.ZERO;
        const UTXOs = spendingUTXOs;
        let balance = BigInteger.ZERO;

        _.each(UTXOs, (utxo) => {
            // TODO when scan utxo, calculated and store this so we don't need this step
            utxo.checkOwnership(this.addresses.privSpendKey);

            // sumOfSpendingMasks = sumOfSpendingMasks.add(
            //     BigInteger.fromHex(utxo.decodedMask),
            // ).mod(secp256k1.n);

            balance = balance.add(
                toBN(utxo.decodedAmount),
            );
        });

        assert(amount.compareTo(balance) === '+', 'Balance is not enough');

        const receiverStealth = Stealth.fromString(receiver);
        const proofOfReceiver = receiverStealth.genTransactionProof(
            Web3.utils.hexToNumberString(amount.toHex()),
        );

        const proofOfMe = this.stealth.genTransactionProof(
            Web3.utils.hexToNumberString(balance.subtract(amount).toHex()),
        );

        return [proofOfReceiver, proofOfMe];
    }

    /**
     *
     * @param {BigInteger} amount
     * @returns {Object} proof output
     */
    _makePrivateSendProof(receiver: string, amount: BigInteger): Object {
        const outputUTXOs = this._genOutputUTXOs(this.utxos, receiver, amount);
        const ringct = this._genRingCT(this.utxos, outputUTXOs);
        const rangeProof = this._genRangeProof(amount);

        return {
            outputUTXOs,
            ringct,
            rangeProof,
        };
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

    decBalance() {
        return this.balance ? Web3.utils.toBN('0x' + this.balance.toHex()).toString() : '0';
    }

    hexBalance() {
        return this.balance ? '0x' + this.balance.toHex() : '0x0';
    }
}
