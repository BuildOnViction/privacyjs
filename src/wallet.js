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

const UTXO_RING_SIZE = 12;
const MAXIMUM_ALLOWED_RING_NUMBER = 5;

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
     * @param {Object} scOpts smart-contract options include address, abi, gas, gasPrice
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
                gas: '20000000',
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

    /**
     * Request UTXO data from smart-contract
     * @param {number} index
     * @returns {Object} utxo data
     */
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

    /**
     * Scan all belong UTXOs
     * this is recursive version, the old async/await inside loop throw Exception sometimes
     * maybe the babel compiler is not optimized when using async, await inside loop
     * @param {number} fromIndex start scanning utxos on smart-contract for find your balance
     */
    async scan(fromIndex: number) {
        const _self = this;
        return new Promise((resolve, reject) => {
            _self.emit('START_SCANNING');
            const index = fromIndex || _self.scannedTo;
            let scannedTo = 0;
            let utxo = {};
            let balance = BigInteger.ZERO;
            const utxos = [];

            async function getUTXO(i) {
                try {
                    utxo = await _self.getUTXO(i);
                } catch (ex) {
                    scannedTo = i - 1;
                    return false;
                }

                const utxoInstance = new UTXO(utxo);
                const isMine = utxoInstance.checkOwnership(_self.addresses.privSpendKey);

                if (isMine && parseFloat(isMine.amount).toString() === isMine.amount) {
                    let res;

                    try {
                        res = await _self.isSpent(utxoInstance);
                    } catch (ex) {
                        console.log(ex);
                    }

                    console.log(i, ' ', res, ' ', isMine.amount);

                    if (!res) {
                        balance = balance.add(
                            toBN(isMine.amount),
                        );
                        utxos.push(utxoInstance);
                    }
                }

                await getUTXO(i + 1);
            }

            getUTXO(index).then(() => {
                _self.emit('FINISH_SCANNING');
                _self.balance = balance;
                _self.utxos = utxos;
                _self.scannedTo = scannedTo;

                console.log('Total Balance : ', Web3.utils.hexToNumberString(
                    _self.balance.toHex(),
                ));
                resolve(_self.utxos);
            }).catch((ex) => {
                reject(ex);
            });
        });
    }

    store() {
    }

    qrUTXOsData() {
    }

    _getSpendingUTXO(amount: BigInteger): Array<UTXO> {
        const spendingUTXOS = [];
        let i = 0;
        let justEnoughBalance = BigInteger.ZERO;
        while (amount.compareTo(justEnoughBalance) > 0) {
            justEnoughBalance = justEnoughBalance.add(
                toBN(
                    this.utxos[i].decodedAmount, // TODO convert decoded amount to BigInteger
                ),
            );
            spendingUTXOS.push(this.utxos[i]);
            i++;
        }

        return spendingUTXOS;
    }

    /**
     * Sum amount of a group utxos
     * @param {Array<UTXO>} utxos
     * @returns {BigInteger}
     */
    _calTotal(utxos: Array<UTXO>): BigInteger {
        let balance = BigInteger.ZERO;
        _.each(utxos, (utxo) => {
            balance = balance.add(
                toBN(
                    utxo.decodedAmount,
                ),
            );
        });
        return balance;
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

        const spendingUTXOs = this._getSpendingUTXO(biAmount);
        const totalResponse = [];
        const totalSpent = spendingUTXOs.length;

        if (spendingUTXOs.length > MAXIMUM_ALLOWED_RING_NUMBER) {
            try {
                while (spendingUTXOs.length > 0) {
                    const spentThisRound = spendingUTXOs.splice(0, MAXIMUM_ALLOWED_RING_NUMBER);
                    // eslint-disable-next-line no-await-in-loop
                    const proof = await this._makePrivateSendProof(
                        privacyAddress,
                        this._calTotal(spentThisRound),
                        spentThisRound,
                        true, // flag for indicating spent all
                    );

                    // eslint-disable-next-line no-await-in-loop
                    const res = await this._send(proof);
                    totalResponse.push(res.NewUTXO);

                    if (!spendingUTXOs.length) this.emit('FINISH_SENDING');
                }
            } catch (ex) {
                console.log('ex ', ex);
                this.emit('STOP_SENDING', ex);
            }

            this.utxos.splice(0, totalSpent);

            _.each(_.flatten(totalResponse), (utxo) => {
                const utxoInstance = new UTXO(utxo.returnValues);
                const isMine = utxoInstance.checkOwnership(this.addresses.privSpendKey);
                if (isMine) {
                    this.utxos.push(utxoInstance);
                }
            });
            return totalResponse;
        }

        const proof = await this._makePrivateSendProof(
            privacyAddress,
            biAmount,
            spendingUTXOs,
        );

        try {
            // eslint-disable-next-line no-await-in-loop
            const res = await this._send(proof);
            this.utxos.splice(0, totalSpent);

            _.each(res.NewUTXO, (utxo) => {
                const utxoInstance = new UTXO(utxo.returnValues);
                const isMine = utxoInstance.checkOwnership(this.addresses.privSpendKey);
                if (isMine) {
                    this.utxos.push(utxoInstance);
                }
            });

            totalResponse.push(res.NewUTXO);
            this.emit('FINISH_SENDING');
        } catch (ex) {
            console.log(ex);
            this.emit('STOP_SENDING', ex);
        }

        return totalResponse;
    }

    /**
     * Use Web3 to sign and make tx to smart-contract
     * @param {Array} proof
     * @returns {object} new utxos and proof
     */
    _send(proof: Array<any>): Promise<any> {
        return new Promise((resolve, reject) => {
            this.privacyContract.methods.privateSend(...proof)
                .send({
                    from: this.scOpts.from,
                })
                .on('error', (error) => {
                    reject(error);
                })
                .then((receipt) => {
                    resolve(receipt.events);
                });
        });
    }

    /**
     * Private send money to privacy address
     * @param {string} privacyAddress
     * @param {string|number} amount
     * @returns {object} includes new utxos and original created proof
     * on some very first version, we store the proof locally to help debugging if error happens
     */
    async withdraw(address: string, amount: string | number) {
        assert(address.length === CONSTANT.ETH_ADDRESS_LENGTH, 'Malform privacy address !!');

        if (!this.balance) {
            await this.scan();
        }

        const biAmount = toBN(amount);

        assert(biAmount.compareTo(BigInteger.ZERO) > 0, 'Amount should be larger than zero');
        assert(biAmount.compareTo(this.balance) <= 0, 'Balance is not enough');

        this.emit('START_SENDING');

        const spendingUTXOs = this._getSpendingUTXO(biAmount);
        const totalResponse = [];
        const totalSpent = spendingUTXOs.length;

        if (spendingUTXOs.length > MAXIMUM_ALLOWED_RING_NUMBER) {
            try {
                while (spendingUTXOs.length > 0) {
                    const spentThisRound = spendingUTXOs.splice(0, MAXIMUM_ALLOWED_RING_NUMBER);
                    // eslint-disable-next-line no-await-in-loop
                    const proof = await this._makeWithdrawProof(
                        address,
                        this._calTotal(spentThisRound),
                        spentThisRound,
                        true, // flag for indicating spent all
                    );

                    // eslint-disable-next-line no-await-in-loop
                    const res = await this._withdraw(proof);
                    totalResponse.push(res.NewUTXO);

                    if (!spendingUTXOs.length) this.emit('FINISH_SENDING');
                }
            } catch (ex) {
                console.log('ex ', ex);
                this.emit('STOP_SENDING', ex);
            }

            this.utxos.splice(0, totalSpent);
            return totalResponse;
        }

        const proof = await this._makeWithdrawProof(
            address,
            biAmount,
            spendingUTXOs,
        );

        try {
            // eslint-disable-next-line no-await-in-loop
            const res = await this._withdraw(proof);
            this.utxos.splice(0, totalSpent);
            totalResponse.push(res.NewUTXO);
            this.emit('FINISH_SENDING');
        } catch (ex) {
            this.emit('STOP_SENDING', ex);
        }

        return totalResponse;
    }

    /**
     * Use Web3 to sign and make tx to smart-contract
     * @param {Array} proof
     * @returns {object} new utxos and proof
     */
    _withdraw(proof: Array<any>): Promise<any> {
        return new Promise((resolve, reject) => {
            this.privacyContract.methods.withdrawFunds(...proof)
                .send({
                    from: this.scOpts.from,
                })
                .on('error', (error) => {
                    reject(error);
                })
                .then((receipt) => {
                    resolve(receipt.events);
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
        const decoysIndex = [];

        // TODO cache decoys when scan
        // we can't use Promise All in web3.methods.call because of memory leak
        // so let resolve one by one
        let counter = 0;
        const MAXIMUM_RANDOMIZATION_TIMES = 50;
        let randomizationTimes = 0;

        // should stop if after 50 randomization times can't get all decoys
        while (counter < UTXO_RING_SIZE + 4) {
            let rd;
            do {
                rd = Math.round(Math.random() * this.scannedTo);
                randomizationTimes++;
            } while ((rd in spendingIndexes || rd in decoysIndex) && randomizationTimes < MAXIMUM_RANDOMIZATION_TIMES);

            decoysIndex.push(rd);

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
     * @param {Array<UTXO>} spendingUTXOs
     * @param
     */
    async _genRingCT(spendingUTXOs: Array<UTXO>, proofs: Array<Object>) {
        const numberOfRing = spendingUTXOs.length;
        const ringSize = UTXO_RING_SIZE; // 11 decoys + one spending

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

        let message = new Buffer([]);

        // ct ring
        const {
            privKey,
            publicKeys,
        } = MLSAG.genCTRing(
            this.addresses.privSpendKey,
            decoys,
            _.map(proofs, (proof) => {
                const lfCommitment = ecurve.Point.decodeFrom(ecparams, proof.commitment);
                message = Buffer.concat([
                    message,
                    proof.onetimeAddress.slice(-64),
                ]);
                return {
                    lfCommitment,
                    decodedMask: proof.mask,
                };
            }),
            index,
        );

        // put ct ring to ring-signature to make ringct
        privkeys.push(privKey);

        const ringctDecoys = [..._.map(decoys, ring => _.map(ring, utxo => utxo.lfStealth)), publicKeys];
        const ringSignature = MLSAG.mulSign(
            privkeys,
            ringctDecoys,
            index,
            message,
        );

        assert(
            MLSAG.verifyMul(
                ringctDecoys,
                ringSignature.I,
                ringSignature.c1,
                ringSignature.s,
                message,
            ) === true, 'Wrong signature !!',
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
     * Generate utxos for withdrawing transaction, one for sender (even balance = 0), one for receiver (balance = 0)
     * @param {Array<UTXO>} spendingUTXOs spending utxos
     * @param {BigInteger} amount sending amount
     * @param {boolean} [isSpentAll]
     * @returns {Array<Proof>} [proofOfReceiver, proofOfMe]
     */
    _genWithdrawProofs(spendingUTXOs: Array<UTXO>, amount: BigInteger, isSpentAll: ?boolean): Array<Object> {
        const UTXOs = spendingUTXOs;

        if (isSpentAll) {
            const proofOfReceiver = this.stealth.genTransactionProof(
                Web3.utils.hexToNumberString(amount.toHex()),
                null,
                null,
                '0',
            );

            const proofOfMe = this.stealth.genTransactionProof(
                '0',
            );
            return [proofOfReceiver, proofOfMe];
        }

        const balance = this._calTotal(UTXOs);

        assert(amount.compareTo(balance) <= 0, 'Balance is not enough');

        const proofOfReceiver = this.stealth.genTransactionProof(
            Web3.utils.hexToNumberString(amount.toHex()), null, null, '0',
        );

        const proofOfMe = this.stealth.genTransactionProof(
            Web3.utils.hexToNumberString(balance.subtract(amount).toHex()),
        );

        return [proofOfReceiver, proofOfMe];
    }

    /**
     * Generate utxos for sending transaction, one for sender (even balance = 0), one for receiver
     * @param {Array<UTXO>} spendingUTXOs spending utxos
     * @param {string} receiver privacy address of receiver
     * @param {BigInteger} amount sending amount
     * @param {boolean} [isSpentAll]
     * @returns {Array<Proof>} [proofOfReceiver, proofOfMe]
     */
    _genOutputProofs(spendingUTXOs: Array<UTXO>, receiver: string, amount: BigInteger, isSpentAll: ?boolean): Array<Object> {
        const UTXOs = spendingUTXOs;
        const receiverStealth = Stealth.fromString(receiver);

        if (isSpentAll) {
            const proofOfReceiver = receiverStealth.genTransactionProof(
                Web3.utils.hexToNumberString(amount.toHex()),
            );

            const proofOfMe = this.stealth.genTransactionProof(
                '0',
            );
            return [proofOfReceiver, proofOfMe];
        }

        const balance = this._calTotal(UTXOs);

        assert(amount.compareTo(balance) <= 0, 'Balance is not enough');

        const proofOfReceiver = receiverStealth.genTransactionProof(
            Web3.utils.hexToNumberString(amount.toHex()),
        );

        const proofOfMe = this.stealth.genTransactionProof(
            Web3.utils.hexToNumberString(balance.subtract(amount).toHex()),
        );

        return [proofOfReceiver, proofOfMe];
    }

    /**
     * Create proof base on amount and privacy_addres
     * @param {string} receiver privacy address
     * @param {BigInteger} amount
     * @param {boolean} [isSpentAll]
     * @returns {Object} proof output
     */
    async _makePrivateSendProof(receiver: string, amount: BigInteger, spendingUTXOs: Array<UTXO>, isSpentAll: ?boolean): Array {
        const outputProofs = this._genOutputProofs(spendingUTXOs, receiver, amount, isSpentAll);
        const { signature, decoys } = await this._genRingCT(spendingUTXOs, outputProofs);
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

    /**
     * Create proof base on amount and privacy_addres
     * @param {string} receiver privacy address
     * @param {BigInteger} amount
     * @param {boolean} [isSpentAll]
     * @returns {Object} proof output
     */
    async _makeWithdrawProof(receiver: string, amount: BigInteger, spendingUTXOs: Array<UTXO>, isSpentAll: ?boolean): Array {
        const outputProofs = this._genWithdrawProofs(spendingUTXOs, amount, isSpentAll);
        const { signature, decoys } = await this._genRingCT(spendingUTXOs, outputProofs);

        return [
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
            '0x' + amount.toHex(),
            [
                `0x${outputProofs[1].encryptedAmount}`, // encrypt of amount using ECDH],
                `0x${outputProofs[1].encryptedMask}`, // encrypt of mask using ECDH],
            ],
            receiver,
            signature,
        ];
    }

    fromStorage() {
    }

    /**
     * Check if the utxo spent or not by KeyImage (refer MLSAG)
     * @param {UTXO} utxo
     * @returns {boolean}
     */
    isSpent(utxo: UTXO): Promise<boolean> {
        const ringctKeys = utxo.getRingCTKeys(this.addresses.privSpendKey);

        return new Promise((resolve, reject) => {
            this.privacyContract.methods.isSpent(
                _.map(keyImage(
                    BigInteger.fromHex(ringctKeys.privKey),
                    utxo.lfStealth.getEncoded(false).toString('hex').slice(2),
                ).getEncoded(true).toString('hex').match(/.{1,2}/g), num => '0x' + num),
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
