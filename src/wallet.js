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
 */

import Web3 from 'web3';
import ecurve from 'ecurve';
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
import MLSAG, { keyImage } from './mlsag';

const ecparams = ecurve.getCurveByName('secp256k1');

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

const UTXO_RING_SIZE = 11;

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

    // scanned to
    scannedTo: number;

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
            scOpts.ABI, this.scOpts.ADDRESS, {
                gasPrice: '250000000',
                gas: '2000000',
            },
        );

        // TODO get/set thru localstrage
        this.scannedTo = 0;
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

    getUTXO(index: number): Promise<Object> {
        return new Promise((resolve, reject) => {
            this.privacyContract.methods.getUTXO(index)
                .call({
                    from: this.scOpts.from,
                })
                // eslint-disable-next-line quote-props
                .then(utxo => resolve({ ...utxo, '3': index })).catch((exception) => {
                    reject(exception);
                });
        });
    }

    async scan() {
        this.emit('START_SCANNING');
        let index = this.scannedTo;
        let utxo = {};
        let balance = BigInteger.ZERO;
        const utxos = [];

        do {
            try {
                // eslint-disable-next-line no-await-in-loop
                utxo = await this.getUTXO(index);
                console.log('getting utxo for index ', index);
                const utxoInstance = new UTXO(utxo);

                const isMine = utxoInstance.checkOwnership(this.addresses.privSpendKey);

                if (isMine && parseFloat(isMine.amount).toString() === isMine.amount) {
                    // check if utxo is spent already
                    // eslint-disable-next-line no-await-in-loop
                    const res = await this.isSpent(utxoInstance);

                    if (!res) {
                        balance = balance.add(
                            toBN(isMine.amount),
                        );
                        utxos.push(utxoInstance);
                    }
                }
                index++;

                // for testing, dont do this in real time
                if (utxos.length > 3) {
                    break;
                }
            } catch (exception) {
                utxo = null;
                break;
            }
        } while (utxo);

        this.emit('FINISH_SCANNING');
        this.balance = balance;
        this.utxos = utxos;
        this.scannedTo = index;
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

        assert(biAmount.compareTo(this.balance) <= 0, 'Balance is not enough');

        this.emit('START_SENDING');

        const proof = await this._makePrivateSendProof(privacyAddress, biAmount);

        console.log('proof ', proof);

        let res;
        try {
            res = await this._send(proof);
            this.emit('FINISH_SENDING');
        } catch (ex) {
            console.log(ex);
            this.emit('STOP_SENDING', ex);
        }

        return res;
    }

    /**
     * Use Web3 to sign and make tx to smart-contract
     * @param {Array} proof
     * @returns {object} new utxos and proof
     */
    _send(proof: Array<any>): Promise<any> {
        return new Promise((resolve, reject) => {
            // ugly syntax
            this.privacyContract.methods.privateSend(...proof)
                .send({
                    from: this.scOpts.from,
                })
                .on('error', (error) => {
                    reject(error);
                })
                .then((receipt) => {
                    resolve({
                        utxo: receipt.events,
                        proof,
                    });
                });
        });
    }

    /**
     * Generate decoys for ring
     * we get random 15 UTXOs then select a random numberOfRing set with size = UTXO_RING_SIZE
     * @param {number} numberOfRing
     * @param {Array<number>} spendingIndexes
     * @returns {Array<Array<UTXO>>} two dimension array of decoys,
     * actually we just need the commitment and public_key of decoys here
     */
    async _getDecoys(numberOfRing: number, spendingIndexes: Array<number>): Promise<Array<Array<UTXO>>> {
        // the total decoys we need to get from smart-contract = UTXO_RING_SIZE * ring_size
        let utxos = [];

        // we can't use Promise All in web3.methods.call because of memory leak
        // so let resolve one by one
        let counter = 0;

        while (counter < UTXO_RING_SIZE + 4) {
            let rd;
            do {
                rd = Math.round(Math.random() * this.scannedTo);
            } while (rd in spendingIndexes);

            // eslint-disable-next-line no-await-in-loop
            const utxo = await this.getUTXO(rd);
            utxos.push(
                new UTXO(utxo),
            );
            counter++;
        }

        return _.map(Array(numberOfRing), () => {
            utxos = _.shuffle(utxos);
            return utxos.slice(0, 11);
        });
    }

    /**
     * Generate ring confidental transaction proof
     * 1. Generate ring-signature from spending utxos
     * 2. generate additional ring for proof commitment_input = commitment_output
     */
    async _genRingCT(spendingUTXOs: Array<UTXO>, proofs: Array<Object>) {
        const numberOfRing = spendingUTXOs.length;
        const ringSize = 12; // 11 decoys + one spending

        // get random utxos for making ring from network
        // number of random utxo = spendingUTXOs * 11 (maximum decoys per ring)
        let decoys = await this._getDecoys(numberOfRing, _.map(spendingUTXOs, utxo => utxo.index));

        // random index each time generating ringct
        const index = Math.round(Math.random() * (ringSize - 1));

        // TODO need rewrite - not optimized
        const pubkeys = []; // public keys of utxo

        decoys = _.map(decoys, (decoyRing, counter) => {
            decoyRing.splice(index, 0, spendingUTXOs[counter]);
            return decoyRing;
        });
        _.each(_.flatten(decoys), (decoy) => {
            pubkeys.push(decoy.lfStealth);
        });

        let totalSpending = BigInteger.ZERO;

        const privkeys = [];

        _.each(spendingUTXOs, (utxo) => {
            const utxoIns = utxo;
            // utxoIns.checkOwnership(this.addresses.privSpendKey);
            totalSpending = totalSpending.add(
                toBN(utxoIns.decodedAmount),
            );
            privkeys.push(
                toBN(utxoIns.privKey),
            );
        });

        // ct ring
        const {
            privKey,
            publicKeys,
        } = MLSAG.genCTRing(
            this.addresses.privSpendKey,
            decoys,
            _.map(proofs, proof => ({
                lfCommitment: ecurve.Point.decodeFrom(ecparams, proof.commitment),
                decodedMask: proof.mask,
            })),
            index,
        );

        // put ct ring to ring-signature to make ringct
        privkeys.push(privKey);
        // decoys.push(publicKeys);

        const ringctDecoys = [..._.map(decoys, ring => _.map(ring, utxo => utxo.lfStealth)), publicKeys];
        // ring-signature of utxos
        const ringSignature = MLSAG.mulSign(
            privkeys,
            ringctDecoys,
            index,
        );

        return {
            decoys,
            signature: Buffer.from(
                `${numberToBN(numberOfRing + 1).toString(16, 16)
                }${numberToBN(ringSize).toString(16, 16)
                }${ringSignature.message.toString('hex')
                }${ringSignature.c1.toHex(32)
                }${_.map(_.flatten(ringSignature.s), element => element.toHex(32)).join('')
                }${_.map(_.flatten(ringctDecoys), pubkey => pubkey.getEncoded(true).toString('hex')).join('')
                }${_.map(_.flatten(ringSignature.I), element => element.getEncoded(true).toString('hex')).join('')}`,
                'hex',
            ),
        };
    }

    /**
     * Generate range proof to prove a number in a range
     * in tomo system, the range from 0 to 2^64
     * we can choose what kind of range proof to use here
     * two supported are bulletproof and aggregate schnorr
     * @param {BigInteger} amount
     * @returns {Buffer} Proof
     */
    _genRangeProof(amount: BigInteger): Buffer {
        return amount.toBuffer();
    }

    /**
     * Generate utxos afer transaction, one for sender (even balance = 0), one for receiver
     * @param {Array<UTXO>} spendingUTXOs spending utxos
     * @param {string} receiver privacy address of receiver
     * @param {BigInteger} amount sending amount
     * @returns {Array<Proof>} [proofOfReceiver, proofOfMe]
     */
    _genOutputProofs(spendingUTXOs: Array<UTXO>, receiver: string, amount: BigInteger): Array<Object> {
        // let sumOfSpendingMasks = BigInteger.ZERO;
        const UTXOs = spendingUTXOs;
        const { balance } = this;

        _.each(UTXOs, (utxo) => {
            // TODO when scan utxo, calculated and store this so we don't need this step
            utxo.checkOwnership(this.addresses.privSpendKey);

            // sumOfSpendingMasks = sumOfSpendingMasks.add(
            //     BigInteger.fromHex(utxo.decodedMask),
            // ).mod(secp256k1.n);

            // balance = balance.add(
            //     toBN(utxo.decodedAmount),
            // );
        });

        // assert(amount.compareTo(balance) <= 0, 'Balance is not enough');
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
    async _makePrivateSendProof(receiver: string, amount: BigInteger): Object {
        const outputProofs = this._genOutputProofs(this.utxos, receiver, amount);
        const { signature, decoys } = await this._genRingCT(this.utxos, outputProofs);
        // const rangeProof = this._genRangeProof(amount);

        return [
            // [ring_element_index_00,ring_element_index_01,ring_element_index_02,ring_element_index_11...]
            _.map(_.flatten(decoys), decoy => decoy.index),
            [
                `0x${outputProofs[1].commitment.toString('hex').substr(2, 64)}`,
                `0x${outputProofs[1].commitment.toString('hex').substr(-64)}`,
                `0x${outputProofs[0].commitment.toString('hex').substr(2, 64)}`,
                `0x${outputProofs[0].commitment.toString('hex').substr(-64)}`,
                `0x${outputProofs[1].onetimeAddress.toString('hex').substr(2, 64)}`,
                `0x${outputProofs[1].onetimeAddress.toString('hex').substr(-64)}`,
                `0x${outputProofs[0].onetimeAddress.toString('hex').substr(2, 64)}`,
                `0x${outputProofs[0].onetimeAddress.toString('hex').substr(-64)}`,
                `0x${outputProofs[1].txPublicKey.toString('hex').substr(2, 64)}`,
                `0x${outputProofs[1].txPublicKey.toString('hex').substr(-64)}`,
                `0x${outputProofs[0].txPublicKey.toString('hex').substr(2, 64)}`,
                `0x${outputProofs[0].txPublicKey.toString('hex').substr(-64)}`,
            ],
            [
                `0x${outputProofs[1].encryptedAmount}`, // encrypt of amount using ECDH],
                `0x${outputProofs[0].encryptedAmount}`, // encrypt of amount using ECDH],
                `0x${outputProofs[1].encryptedMask}`, // encrypt of mask using ECDH],
                `0x${outputProofs[0].encryptedMask}`, // encrypt of mask using ECDH],
            ],
            signature,
        ];
    }

    fromStorage() {

    }

    withdraw() {

    }

    isSpent(utxo: UTXO): Promise<any> {
        const ringctKeys = utxo.getRingCTKeys(this.addresses.privSpendKey);

        return new Promise((resolve, reject) => {
            this.privacyContract.methods.isSpent(
                `0x${keyImage(
                    BigInteger.fromHex(ringctKeys.privKey),
                    utxo.lfStealth.getEncoded(false).toString('hex').slice(2),
                ).getEncoded(true).toString('hex')}`,
            )
                .call({
                    from: this.scOpts.from,
                })
                .then(isspent => resolve(isspent)).catch((exception) => {
                    reject(exception);
                });
        });
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

    listenNewUTXO() {
        throw new Error('not implemented yet');
    }
}
