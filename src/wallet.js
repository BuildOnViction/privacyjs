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
import EventEmitter from 'eventemitter3';
import HDWalletProvider from '@truffle/hdwallet-provider';
import assert from 'assert';
import * as _ from 'lodash';
import toBN from 'number-to-bn'; // this is converter to bn.js, this lib support more utils than bigi
import * as CONSTANT from './constants';
import * as Address from './address';
import Stealth, { toPoint } from './stealth';
import UTXO from './utxo';
import MLSAG, { keyImage } from './mlsag';
import BulletProof from './bullet_proof';
import randomBI from './crypto';

const BigInteger = CONSTANT.BigInteger;

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');

type SmartContractOpts = {
    RPC_END_POINT: string,
    SOCKET_END_POINT: string,
    ADDRESS: string,
    ABI: Array<Object>,
    gasPrice: number | string,
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
const MAXIMUM_ALLOWED_RING_NUMBER = 4;
const PRIVACY_FLAT_FEE = toBN(
    '10000000',
); // 0.01 TOMO

const DEPOSIT_FEE_WEI = toBN(
    '1000000',
); // 0.001 TOMO

const PRIVACY_TOKEN_UNIT = toBN(
    '1000000000',
); // use gwei as base unit for reducing size of rangeproof


const STORAGE_PREFIX = '@TOMOPRIVACY/';

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
    constructor(privateKey: string, scOpts: SmartContractOpts, address: string, localStorage: any) {
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

        if (scOpts.SOCKET_END_POINT) {
            this.listenNewUTXO(scOpts);
        }

        this.localStorage = localStorage;
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
            `0x${proof.onetimeAddress.substr(2, 64)}`, // the X part of point
            `0x${proof.onetimeAddress.substr(-64)}`, // the Y part of point
            `0x${proof.txPublicKey.substr(2, 64)}`, // the X part of point
            `0x${proof.txPublicKey.substr(-64)}`, // the Y par of point,
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
            const proof = this._genUTXOProof(
                toBN(amount)
                    .div(PRIVACY_TOKEN_UNIT)
                    .sub(DEPOSIT_FEE_WEI)
                    .toString(10),
            );
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
     * Request single UTXO data from smart-contract
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
     * Request UTXOs data from smart-contract
     * @param {number} index
     * @returns {Object} utxo data
     */
    getUTXOs(utxosIndexs: Array<number>): Promise<Object> {
        return new Promise((resolve, reject) => {
            this.privacyContract.methods.getUTXOs(
                utxosIndexs,
            )
                .call()
                .then((utxos) => {
                    utxos = _.map(utxos, (raw, index) => {
                        raw['3'] = utxosIndexs[parseInt(index)];
                        return raw;
                    });
                    resolve(utxos);
                }).catch((exception) => {
                    reject(exception);
                });
        });
    }

    async _verifyUsableUTXO(rawUTXO) {
        let utxoInstance = new UTXO(rawUTXO);
        const isMine = utxoInstance.checkOwnership(this.addresses.privSpendKey);

        if (isMine
            && toBN(isMine.amount).toString(10) === isMine.amount
            && toBN(isMine.amount).cmp(BigInteger.ZERO()) > 0) {
            let res;
            try {
                res = await this.isSpent(utxoInstance);
            } catch (ex) {
                return false;
            }

            return res ? false : isMine.amount; // unspent amount
        }

        // free up memory
        utxoInstance = null;

        return false;
    }

    /**
     * Scan all belong UTXOs
     * // TODO remove storing UTXO instance, add checking commitment
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
            let balance = BigInteger.ZERO();
            // const utxos = [];
            const rawUTXOs = [];

            async function getUTXO(i) {
                let utxos = [];
                try {
                    utxos = await _self.getUTXOs(_.range(i, i + 49));
                } catch (ex) {
                    scannedTo = i - 1;
                    // return false;
                }

                if (!utxos.length) {
                    return false;
                }

                for (let ct = 0; ct < utxos.length; ct++) {
                    const utxo = utxos[ct];

                    // console.log('...Scanned to ', utxo[3]);

                    // when meet the flag one, return
                    if (utxo[0][0] === '0') {
                        scannedTo = utxo[3] - 1;
                        return;
                    }

                    // eslint-disable-next-line no-await-in-loop
                    const usableAmount = await _self._verifyUsableUTXO(utxo);

                    if (usableAmount) {
                        balance = balance.add(
                            toBN(usableAmount),
                        );

                        // for storing in cache
                        rawUTXOs.push({
                            ...utxo,
                            decodedAmount: usableAmount, // we don't need to double check again this value, TODO considering add decoded mask
                        });
                    }
                }

                await getUTXO(i + 50);
            }

            getUTXO(index).then(() => {
                _self.emit('FINISH_SCANNING');
                _self.balance = balance;
                _self.scannedTo = scannedTo;
                _self.utxos = rawUTXOs;

                /**
                 * Store balance, scannedTo, raw utxos to cache
                 * TODO ad qr generator for those data
                 */
                this.updateWalletState(rawUTXOs, _self.balance, _self.scannedTo);

                console.log('Total Balance : ', _self.balance.toString(10));
                resolve({
                    utxos: rawUTXOs,
                    balance: this.decimalBalance(),
                });
            }).catch((ex) => {
                reject(ex);
            });
        });
    }

    updateWalletState(rawUTXOs: Array<Object>, balance: BigInteger, scannedTo: number) {
        // this._addNewUTXOS(rawUTXOs, true);
        this._updateStorage('UTXOS', this.utxos);
        this._updateStorage('BALANCE', balance.toString(16));
        this._updateStorage('SCANNEDTO', scannedTo);
    }

    restoreWalletState() {
        this.balance = BigInteger.fromHex(
            this._fromStorage('BALANCE') || '00',
        );

        this.scannedTo = parseInt(this._fromStorage('SCANNEDTO')) || 0;

        // Load all UTXO object
        // TODO just load decodedAmount and index so the memory is very light
        this.utxos = this._fromStorage('UTXOS');
    }

    qrUTXOsData() {
    }

    /**
     * Get UTXOs for making transaction with amount
     * @param {BigInteger} amount
     * @returns {Object} needed utxos, number of transaction to send all the amount
     */
    _getSpendingUTXO(amount: BigInteger): Array<UTXO> {
        const spendingUTXOS = [];
        let i = 0;
        let justEnoughBalance = BigInteger.ZERO();
        let txTimes = 1;

        while (amount.cmp(
            justEnoughBalance.sub(
                toBN(txTimes).mul(PRIVACY_FLAT_FEE),
            ),
        ) > 0 && this.utxos[i]) {
            justEnoughBalance = justEnoughBalance.add(
                toBN(
                    this.utxos[i].decodedAmount,
                ),
            );
            spendingUTXOS.push(this.utxos[i]);

            if (spendingUTXOS.length / MAXIMUM_ALLOWED_RING_NUMBER > txTimes) {
                txTimes++;
            }

            i++;
        }

        console.log('... Doing TX with ', spendingUTXOS.length, ' UTXOs');
        console.log('... Split into ', txTimes, ' sub-tx');

        // not enough balance to pay fee + amount
        if (amount.cmp(
            justEnoughBalance.sub(
                toBN(txTimes).mul(PRIVACY_FLAT_FEE),
            ),
        ) > 0) {
            return {
                utxos: null,
            };
        }

        return {
            utxos: spendingUTXOS,
            totalAmount: justEnoughBalance,
            txTimes,
            totalFee: toBN(txTimes).mul(PRIVACY_FLAT_FEE),
        };
    }

    /**
     * Split a complex transaction (with utxos number > MAXIMUM_ALLOWED_RING_NUMBER)
     * into multiple sub-transaction with utxos number <= MAXIMUM_ALLOWED_RING_NUMBER
     * @param {Array<UTXO>} utxos all utxos need for this tx
     * @param {number} txTimes number of transactions need to do
     * @param {BigInteger} txAmount total amount need to transfer
     * @returns {Array<Object>} list transaction each include needed utxos, remain amount, receiver amount
     */
    _splitTransaction(utxos: Array<UTXO>, txTimes: number, txAmount: BigInteger) : Array<Object> {
        const txs = [];
        let sentAmount = BigInteger.ZERO();

        for (let index = 0; index < txTimes - 1; index++) {
            // TODO pick MAXIMUM_ALLOWED_RING_NUMBER utxos each round while total > PRIVACY_FLAT_FEE
            const spendingUTXO = utxos.splice(0, MAXIMUM_ALLOWED_RING_NUMBER);
            const totalThisRound = this._calTotal(spendingUTXO);
            if (totalThisRound.cmp(PRIVACY_FLAT_FEE) > 0) {
                const sentAmountThisTx = this._calTotal(spendingUTXO).sub(PRIVACY_FLAT_FEE);
                txs.push({
                    utxos: spendingUTXO,
                    receivAmount: sentAmountThisTx,
                    remainAmount: BigInteger.ZERO(),
                });
                sentAmount = sentAmount.add(sentAmountThisTx);
            }
        }

        const remain = this._calTotal(utxos);
        txs.push({
            utxos,
            receivAmount: txAmount.sub(sentAmount),
            remainAmount: remain.add(sentAmount).sub(PRIVACY_FLAT_FEE).sub(txAmount),
        });

        return txs;
    }

    /**
     * Sum amount of a group utxos
     * @param {Array<UTXO>} utxos
     * @returns {BigInteger}
     */
    _calTotal(utxos: Array<UTXO>): BigInteger {
        let balance = BigInteger.ZERO();
        _.each(utxos, (utxo) => {
            if (!utxo.decodedAmount) {
                utxo.decodedAmount = new UTXO(utxo).checkOwnership(this.addresses.privSpendKey).amount;
            }
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
     * TODO code look ugly on utxo.checkOwnership
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

        const biAmount = toBN(amount).div(PRIVACY_TOKEN_UNIT);

        assert(biAmount.cmp(this.balance) <= 0, 'Balance is not enough');
        assert(biAmount.cmp(BigInteger.ZERO()) > 0, 'Amount should be larger than zero');

        this.emit('START_SENDING');

        const {
            utxos, txTimes,
        } = this._getSpendingUTXO(
            biAmount,
        );

        assert(utxos !== null, 'Balance is not enough');

        const utxoInstances = _.map(utxos, (raw) => {
            const utxo = new UTXO(raw);
            utxo.checkOwnership(this.addresses.privSpendKey);
            return utxo;
        });

        const txs = this._splitTransaction(utxoInstances, txTimes, biAmount);

        const totalResponse = [];
        const totalSpent = utxoInstances.length;

        let currentTx = 0;
        try {
            while (txs[currentTx]) {
                // eslint-disable-next-line no-await-in-loop
                const proof = await this._makePrivateSendProof(
                    privacyAddress,
                    txs[currentTx].receivAmount,
                    txs[currentTx].utxos,
                    txs[currentTx].remainAmount,
                );

                // eslint-disable-next-line no-await-in-loop
                const res = await this._send(proof);
                totalResponse.push(res.NewUTXO);
                currentTx++;
            }
            this.emit('FINISH_SENDING');
        } catch (ex) {
            this.emit('STOP_SENDING', ex);
            this.utxos.splice(0, totalSpent - txs.length);
            this.balance = this._calTotal(this.utxos);
            this.updateWalletState(this.utxos, this.balance, this.scannedTo);

            throw ex;
        }

        // we don't add the response here because of listening to SC-event already
        console.log('totalSpent ', totalSpent);
        this.utxos.splice(0, totalSpent);
        this.balance = this._calTotal(this.utxos);
        this.updateWalletState(this.utxos, this.balance, this.scannedTo);

        return totalResponse;
    }

    /**
     * Use Web3 to sign and make tx to smart-contract
     * because we don't need to pay the tx fee directly (TRC21)
     * so we randomizing privatekey each time sending
     * @param {Array} proof
     * @returns {object} new utxos and proof
     */
    _send(proof: Array<any>): Promise<any> {
        const randomPrivatekey = secp256k1.genKeyPair().getPrivate().toString('hex');
        const provider = new HDWalletProvider(randomPrivatekey, this.scOpts.RPC_END_POINT);
        const web3 = new Web3(provider);
        const { address } = web3.eth.accounts.privateKeyToAccount('0x' + randomPrivatekey);
        const privacyContract = new web3.eth.Contract(
            this.scOpts.ABI, this.scOpts.ADDRESS, {
                gasPrice: '250000000',
                gas: '20000000',
            },
        );
        return new Promise((resolve, reject) => {
            privacyContract.methods.privateSend(...proof)
                .send({
                    from: address,
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
        assert(address.length === CONSTANT.ETH_ADDRESS_LENGTH, 'Malform address !!');

        if (!this.balance) {
            await this.scan();
        }

        const biAmount = toBN(amount).div(PRIVACY_TOKEN_UNIT);

        assert(biAmount.cmp(BigInteger.ZERO()) > 0, 'Amount should be larger than zero');
        assert(biAmount.cmp(this.balance) <= 0, 'Balance is not enough');

        this.emit('START_WITHDRAW');

        const {
            utxos, txTimes,
        } = this._getSpendingUTXO(
            biAmount,
        );

        assert(utxos !== null, 'Balance is not enough');

        const utxoInstances = _.map(utxos, (raw) => {
            const utxo = new UTXO(raw);
            utxo.checkOwnership(this.addresses.privSpendKey);
            return utxo;
        });

        const txs = this._splitTransaction(utxoInstances, txTimes, biAmount);
        const totalResponse = [];
        const totalSpent = utxoInstances.length;

        try {
            let txIndex = 0;
            while (txs[txIndex]) {
                // eslint-disable-next-line no-await-in-loop
                const proof = await this._makeWithdrawProof(
                    address,
                    txs[txIndex].receivAmount,
                    txs[txIndex].utxos,
                    txs[txIndex].remainAmount,
                );

                // eslint-disable-next-line no-await-in-loop
                const res = await this._withdraw(proof);
                totalResponse.push(res.NewUTXO);
                txIndex++;
            }
            this.emit('FINISH_WITHDRAW');
        } catch (ex) {
            this.emit('STOP_WITHDRAW', ex);
            this.utxos.splice(0, totalSpent - txs.length);
            this.balance = this._calTotal(this.utxos);
            this.updateWalletState(this.utxos, this.balance, this.scannedTo);

            throw ex;
        }

        this.utxos.splice(0, totalSpent);
        this.balance = this._calTotal(this.utxos);
        this.updateWalletState(this.utxos, this.balance, this.scannedTo);

        return totalResponse;
    }

    /**
     * Use Web3 to sign and make tx to smart-contract
     * @param {Array} proof
     * @returns {object} new utxos and proof
     */
    _withdraw(proof: Array<any>): Promise<any> {
        const randomPrivatekey = secp256k1.genKeyPair().getPrivate().toString('hex');
        const provider = new HDWalletProvider(randomPrivatekey, this.scOpts.RPC_END_POINT);
        const web3 = new Web3(provider);
        const { address } = web3.eth.accounts.privateKeyToAccount('0x' + randomPrivatekey);
        const privacyContract = new web3.eth.Contract(
            this.scOpts.ABI, this.scOpts.ADDRESS, {
                gasPrice: '250000000',
                gas: '20000000',
            },
        );

        return new Promise((resolve, reject) => {
            privacyContract.methods.withdrawFunds(...proof)
                .send({
                    from: address,
                })
                .on('error', (error) => {
                    console.log('error ', error);
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
        const decoysIndex = [];

        const MAXIMUM_RANDOMIZATION_TIMES = 50;
        let randomizationTimes = 0;

        // should stop if after 50 randomization times can't get all decoys
        for (let counter = 0; counter < UTXO_RING_SIZE + 1; counter++) {
            let rd;
            do {
                rd = Math.round(Math.random() * this.scannedTo);
                randomizationTimes++;
            } while ((spendingIndexes.indexOf(rd) >= 0 || decoysIndex.indexOf(rd) >= 0) && randomizationTimes < MAXIMUM_RANDOMIZATION_TIMES);
            decoysIndex.push(rd);
        }

        // eslint-disable-next-line no-await-in-loop
        let utxos = await this.getUTXOs(decoysIndex);
        utxos = _.map(utxos, raw => new UTXO(raw));

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
     * @param {Array<Object>} UTXOs's proof generated for this tx
     * @returns {Object} RingCT
     */
    async _genRingCT(spendingUTXOs: Array<UTXO>, proofs: Array<Object>) {
        const numberOfRing = spendingUTXOs.length;
        const ringSize = UTXO_RING_SIZE; // 11 decoys + one spending

        let decoys = await this._getDecoys(numberOfRing, _.map(spendingUTXOs, utxo => utxo.index));

        // random index each time generating ringct
        const index = Math.round(Math.random() * (ringSize - 1));

        const pubkeys = []; // public keys of utxo

        decoys = _.map(decoys, (decoyRing, counter) => {
            decoyRing.splice(index, 0, spendingUTXOs[counter]);
            return decoyRing;
        });
        _.each(_.flatten(decoys), (decoy) => {
            pubkeys.push(decoy.lfStealth);
        });

        let totalSpending = BigInteger.ZERO();

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
                // console.log(
                //     proof,
                // );
                const lfCommitment = toPoint(proof.commitment);
                // console.log('lf Commitment ', lfCommitment);
                message = Buffer.concat([
                    message,
                    Buffer.from(proof.onetimeAddress.slice(-128), 'hex'),
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
                `${toBN(numberOfRing + 1).toString(16, 16)
                }${toBN(ringSize).toString(16, 16)
                }${ringSignature.message.toString('hex')
                }${ringSignature.c1.toString(16, 32)
                }${_.map(_.flatten(ringSignature.s), element => element.toString(16, 32)).join('')
                }${_.map(_.flatten(ringSignature.I), element => element.encode('hex', true)).join('')}`,
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
     * @returns {Object} Proof
     */
    _genRangeProof(amount: BigInteger): Buffer {
        let result = BulletProof.prove([
            amount,
        ], [
            randomBI(),
        ]);

        result = BulletProof.proofToHex(result);

        return [
            result.Comms,
            result.A,
            result.S,
            result.T1,
            result.T2,
            result.Tau,
            result.Th,
            result.Mu,
            [
                result.IPP.L,
                result.IPP.R,
                result.IPP.A,
                result.IPP.B,
                result.IPP.Challenges,
            ],
            // result,
            result.Cy,
            result.Cz,
            result.Cx,
        ];
    }

    /**
     * Generate utxos for sending transaction, one for sender (even balance = 0), one for receiver
     * @param {string} receiver privacy address of receiver
     * @param {BigInteger} amount sending amount
     * @param {BigInteger} remain remaining
     * @param {boolean} isWithdraw
     * @returns {Array<Proof>} [proofOfReceiver, proofOfMe]
     */
    _genOutputProofs(receiver: string, amount: BigInteger, remain: BigInteger, isWithdraw: boolean): Array<Object> {
        const receiverStealth = Stealth.fromString(receiver);
        let proofOfReceiver;

        if (isWithdraw) {
            // When withdraw, we set mask = 0, so commitment  = value*H
            proofOfReceiver = this.stealth.genTransactionProof(
                amount.toString(10), null, null, '0',
            );
        } else {
            proofOfReceiver = receiverStealth.genTransactionProof(
                amount.toString(10),
            );
        }

        const proofOfMe = this.stealth.genTransactionProof(
            remain.toString(10),
        );

        const proofOfFee = this.stealth.genTransactionProof(
            PRIVACY_FLAT_FEE.toString(10), null, null, '0',
        );

        return [proofOfReceiver, proofOfMe, proofOfFee];
    }

    /**
     * Create proof base on amount and privacy_addres
     * @param {string} receiver privacy address
     * @param {BigInteger} amount
     * @param {BigInteger} remain
     * @returns {Object} proof output
     */
    async _makePrivateSendProof(receiver: string, amount: BigInteger, spendingUTXOs: Array<UTXO>, remain: BigInteger): Array {
        const outputProofs = this._genOutputProofs(receiver, amount, remain);
        const { signature, decoys } = await this._genRingCT(spendingUTXOs, outputProofs);

        return [
            // [ring_element_index_00,ring_element_index_01,ring_element_index_02,ring_element_index_11...]
            _.map(_.flatten(decoys), decoy => decoy.index),
            [
                `0x${outputProofs[1].commitment.substr(2, 64)}`,
                `0x${outputProofs[1].commitment.substr(-64)}`,
                `0x${outputProofs[0].commitment.substr(2, 64)}`,
                `0x${outputProofs[0].commitment.substr(-64)}`,
                `0x${outputProofs[1].onetimeAddress.substr(2, 64)}`,
                `0x${outputProofs[1].onetimeAddress.substr(-64)}`,
                `0x${outputProofs[0].onetimeAddress.substr(2, 64)}`,
                `0x${outputProofs[0].onetimeAddress.substr(-64)}`,
                `0x${outputProofs[1].txPublicKey.substr(2, 64)}`,
                `0x${outputProofs[1].txPublicKey.substr(-64)}`,
                `0x${outputProofs[0].txPublicKey.substr(2, 64)}`,
                `0x${outputProofs[0].txPublicKey.substr(-64)}`,
            ],
            [
                `0x${outputProofs[1].encryptedAmount}`, // encrypt of amount using ECDH],
                `0x${outputProofs[0].encryptedAmount}`, // encrypt of amount using ECDH],
                `0x${outputProofs[1].encryptedMask}`, // encrypt of mask using ECDH],
                `0x${outputProofs[0].encryptedMask}`, // encrypt of mask using ECDH],
            ],
            signature,
            [
                this._genRangeProof(remain),
                this._genRangeProof(amount),
            ],
        ];
    }

    /**
     * Create proof base on amount and privacy_addres
     * @param {string} receiver privacy address
     * @param {BigInteger} amount
     * @param {Array<UTXO>} spendingUTXOs
     * * @param {BigInteger} remain
     * @returns {Object} proof output
     */
    async _makeWithdrawProof(receiver: string, amount: BigInteger, spendingUTXOs: Array<UTXO>, remain: BigInteger): Array {
        const outputProofs = this._genOutputProofs(receiver, amount, remain, true);
        const { signature, decoys } = await this._genRingCT(spendingUTXOs, outputProofs);

        return [
            _.map(_.flatten(decoys), decoy => decoy.index),
            [
                `0x${outputProofs[1].commitment.substr(2, 64)}`,
                `0x${outputProofs[1].commitment.substr(-64)}`,
                `0x${outputProofs[1].onetimeAddress.substr(2, 64)}`,
                `0x${outputProofs[1].onetimeAddress.substr(-64)}`,
                `0x${outputProofs[1].txPublicKey.substr(2, 64)}`,
                `0x${outputProofs[1].txPublicKey.substr(-64)}`,
            ],
            '0x' + amount.mul(PRIVACY_TOKEN_UNIT).toString(16), // withdaw need multiple with 10^9, convert gwei to wei
            [
                `0x${outputProofs[1].encryptedAmount}`, // encrypt of amount using ECDH],
                `0x${outputProofs[1].encryptedMask}`, // encrypt of mask using ECDH],
            ],
            receiver,
            signature,
            [
                this._genRangeProof(remain),
                this._genRangeProof(amount),
            ],
        ];
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
                    utxo.lfStealth.encode('hex', false).slice(2),
                ).encode('hex', true).match(/.{1,2}/g), num => '0x' + num),
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
     * @param {Buffer | string} txPubkey transaction public key
     * @param {Buffer | string} stealth one time address or public key of UTXO
     * @param {string} encryptedAmount AES(ECDH, amount) in hex string
     * @returns {Object} stealth_private_key, stealth_public_key, real amount
     */
    isMine(txPubkey: Buffer | string, stealth: Buffer | string, encryptedAmount: string): DecodedProof {
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
        return this.balance ? Web3.utils.fromWei(
            this.balance.mul(PRIVACY_TOKEN_UNIT).toString(10),
        ) : '0';
    }

    hexBalance() {
        return this.balance ? '0x' + this.balance.mul(PRIVACY_TOKEN_UNIT).toString(16) : '0x0';
    }

    // TODO find way to do automation test on browser
    listenNewUTXO(scOpts: SmartContractOpts) {
        const webSocketProvider = new Web3.providers.WebsocketProvider(scOpts.SOCKET_END_POINT);
        const web3Socket = new Web3(webSocketProvider);
        this.privacyContractSocket = new web3Socket.eth.Contract(scOpts.ABI, scOpts.ADDRESS);

        this.privacyContractSocket.events.NewUTXO().on('data', (evt) => {
            const utxoInstance = new UTXO(evt.returnValues);
            const isMine = utxoInstance.checkOwnership(this.addresses.privSpendKey);

            if (isMine && isMine.amount && isMine.amount.toString() !== '0') {
                console.log(isMine);
                const rawutxo = {
                    ...evt.returnValues,
                    decodedAmount: isMine.amount,
                };
                this.utxos.push(rawutxo);

                this.balance = this._calTotal(this.utxos);

                this.updateWalletState(this.utxos, this.balance, parseInt(rawutxo._index));

                this.emit('NEW_UTXO');
            }
        });
    }

    // TODO find way to test on browser
    /**
     * Store raw UTXO to localstorage
     * @param {Array<RawUTXO>} rawutxos
     */
    _addNewUTXOS(rawutxos, forceReplace) {
        // running the code in nodejs only
        const { localStorage } = this;
        if (!localStorage) {
            return false;
        }

        let utxos = localStorage.getItem(`${STORAGE_PREFIX}UTXOS`) ? JSON.parse(localStorage.getItem(`${STORAGE_PREFIX}UTXOS`)) : null;
        if (utxos && utxos.length > 0 && !forceReplace) {
            utxos = utxos.concat(rawutxos);
            localStorage.setItem(`${STORAGE_PREFIX}UTXOS`, JSON.stringify(
                utxos,
            ));
        } else {
            localStorage.setItem(`${STORAGE_PREFIX}UTXOS`, JSON.stringify(
                rawutxos,
            ));
        }
    }

    _removeSpentUTXO(spentUTXOS) {
        const indexes = _.map(spentUTXOS, raw => parseInt(raw['3']));
        const rawUTXOs = this._fromStorage('UTXOS');

        if (!rawUTXOs || !rawUTXOs.length) {
            return;
        }

        _.remove(rawUTXOs, raw => parseInt(raw['3']) in indexes);
        this._updateStorage(
            'UTXOS',
            rawUTXOs,
        );
    }

    _updateStorage(field, data) {
        const { localStorage } = this;
        if (!localStorage) {
            return null;
        }
        console.log(`Updating ${field} `, data);
        // TODO remove cloneDeep
        return localStorage.setItem(`${STORAGE_PREFIX}${field}`, JSON.stringify(
            _.cloneDeep(data),
        ));
    }

    _fromStorage(field) {
        const { localStorage } = this;
        if (!localStorage || !localStorage.getItem(`${STORAGE_PREFIX}${field}`)) {
            return null;
        }

        return JSON.parse(localStorage.getItem(`${STORAGE_PREFIX}${field}`));
    }
}
