/* eslint-disable no-control-regex */
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
import { keccak256 } from 'js-sha3';
import base58 from 'bs58';
import * as CONSTANT from './constants';
import * as Address from './address';
import Stealth, { toPoint } from './stealth';
import UTXO from './utxo';
import MLSAG, { keyImage } from './mlsag';
import BulletProof from './bullet_proof';
import { decodeTx, encodeTx } from './crypto';
import { toHex, padLeft, BigInteger } from './common';

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
    constructor(privateKey: string, scOpts: SmartContractOpts) {
        super();
        assert(privateKey && privateKey.length === CONSTANT.PRIVATE_KEY_LENGTH, 'Malform private key !!');

        this.addresses = Address.generateKeys(privateKey);
        this.stealth = new Stealth({
            ...this.addresses,
        });
        this.scOpts = scOpts;
        this.scOpts.gasPrice = this.scOpts.gasPrice || CONSTANT.DEFAULT_GAS_PRICE;
        this.scOpts.gas = this.scOpts.gas || CONSTANT.DEFAULT_GAS;

        const provider = new HDWalletProvider(privateKey, scOpts.RPC_END_POINT);
        const web3 = new Web3(provider);
        const address = web3.eth.accounts.privateKeyToAccount('0x' + privateKey).address;

        this.scOpts.from = this.scOpts.from || address;

        this.scOpts.methodsMapping = this.scOpts.methodsMapping || {
            deposit: 'deposit',
            send: 'send',
            withdraw: 'withdraw',
            getTX: 'getUTXO',
        };

        this.privacyContract = new web3.eth.Contract(
            scOpts.ABI, this.scOpts.ADDRESS, {
                gasPrice: this.scOpts.gasPrice,
                gas: this.scOpts.gas,
            },
        );

        this.scannedTo = 0;

        if (scOpts.SOCKET_END_POINT) {
            this.listenNewUTXO(scOpts);
        }
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
    _genUTXOProof = (amount: number, pubSpendKey: ?string, pubViewKey: ?string, predefinedMask: ?Buffer): Array<string> => {
        const proof = this.stealth.genTransactionProof(amount, pubSpendKey, pubViewKey, predefinedMask);
        // const randomProof = this.stealth.genTransactionProof(0, pubSpendKey, pubViewKey);

        return [
            `0x${proof.onetimeAddress.substr(2, 64)}`, // the X part of point
            `0x${proof.onetimeAddress.substr(-64)}`, // the Y part of point
            `0x${proof.txPublicKey.substr(2, 64)}`, // the X part of point
            `0x${proof.txPublicKey.substr(-64)}`, // the Y par of point,
            `0x${proof.mask}`,
            `0x${proof.encryptedAmount}`, // encrypt of amount using ECDH,
            `0x${proof.encryptedMask}`,
            // _.fill(Array(137), '0x0'), // data parameters
            _.map(
                this._encryptedTransactionData(
                    [proof], amount, this.addresses.pubAddr, '',
                ).toString('hex').match(/.{1,2}/g), num => '0x' + num,
            ),
        ];
    }

    /**
     * Send money normal address to privacy address
     * @param {number} amount Plain money to send to privacy address
     * @returns {Object} TxObject includes UTXO and original proof
     */
    deposit = (amount: number): Promise<any> => {
        this.emit('START_DEPOSIT');

        return new Promise((resolve, reject) => {
            const proof = this._genUTXOProof(
                toBN(amount)
                    .div(CONSTANT.PRIVACY_TOKEN_UNIT)
                    .sub(CONSTANT.DEPOSIT_FEE_WEI)
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
                        tx: receipt,
                    });
                });
        });
    }

    /**
     * Request single UTXO data from smart-contract
     * @param {number} index
     * @returns {Object} utxo data
     */
    getUTXO = (index: number): Promise<Object> => new Promise((resolve, reject) => {
        this.privacyContract.methods.getUTXO(index)
            .call({
                from: this.scOpts.from,
            })
            // eslint-disable-next-line quote-props
            .then(utxo => resolve({ ...utxo, '3': index })).catch((exception) => {
                reject(exception);
            });
    })

    /**
     * Request UTXOs data from smart-contract
     * @param {number} index
     * @returns {Object} utxo data
     */
    getUTXOs = (utxosIndexs: Array<number>): Promise<Object> => new Promise((resolve, reject) => {
        this.privacyContract.methods.getUTXOs(
            utxosIndexs,
        )
            .call()
            .then((utxos) => {
                utxos = _.map(utxos, (raw, index) => {
                    raw['3'] = utxosIndexs[parseInt(index)];
                    // remove all redundant field - because solidity return both by field name and by index with struct
                    // we use just index for sync with other method
                    delete raw.XBits;
                    delete raw.YBits;
                    delete raw.encodeds;
                    delete raw.index;

                    return { ...raw };
                });
                resolve(utxos);
            }).catch((exception) => {
                reject(exception);
            });
    })

    _verifyUsableUTXO = async (rawUTXO) => {
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

    _verifyUsableUTXOs = async (rawutxos) => {
        try {
            const res = await this.areSpent(
                _.map(rawutxos, utxo => new UTXO(utxo)),
            );

            return _.filter(rawutxos, (utxo, index) => res[parseInt(index)] === false);
        } catch (ex) {
            return [];
        }
    }

    /**
     * Scan all belong UTXOs
     * // TODO remove storing UTXO instance, add checking commitment
     * this is recursive version, the old async/await inside loop throw Exception sometimes
     * maybe the babel compiler is not optimized when using async, await inside loop
     * @param {number} fromIndex start scanning utxos on smart-contract for find your balance
     */
    scan = async (fromIndex: number) => {
        const _self = this;
        return new Promise((resolve, reject) => {
            _self.emit('START_SCANNING');
            const index = fromIndex || _self.scannedTo;
            let scannedTo = 0;
            let balance = BigInteger.ZERO();
            let isFinished = false;
            let rawUTXOs = [];

            async function getUTXO(i) {
                let utxos = [];
                utxos = await _self.getUTXOs(_.range(i, i + 49));

                if (!utxos.length) {
                    return false;
                }

                // filter mine and usable utxo
                let ct = 0;
                while (ct < utxos.length) {
                    const utxo = utxos[ct];

                    if (utxo[0][0] === '0') {
                        utxos.splice(ct, 1);

                        if (!isFinished) {
                            scannedTo = utxo[3];
                        }

                        isFinished = true;
                    } else {
                        const utxoInstance = new UTXO(utxo);
                        const isMine = utxoInstance.checkOwnership(_self.addresses.privSpendKey);

                        if (isMine
                            && toBN(isMine.amount).toString(10) === isMine.amount
                            && toBN(isMine.amount).cmp(BigInteger.ZERO()) > 0) {
                            utxo.decodedAmount = isMine.amount;
                            ct++;
                        } else {
                            utxos.splice(ct, 1);
                        }
                    }
                }

                // check keyImage on smart-contract
                const filteredRawUTXOs = await _self._verifyUsableUTXOs(utxos);

                if (filteredRawUTXOs.length) {
                    balance = balance.add(
                        _self._calTotal(filteredRawUTXOs),
                    );

                    rawUTXOs = rawUTXOs.concat(filteredRawUTXOs);
                }

                if (!isFinished) { await getUTXO(i + 50); }
            }

            getUTXO(index).then(() => {
                if (!_self.balance) {
                    _self.balance = balance;
                } else {
                    _self.balance = _self.balance.add(balance);
                }

                _self.scannedTo = scannedTo;
                _self.utxos = _self.utxos || [];
                _self.utxos = _self.utxos.concat(rawUTXOs);

                /**
                 * Store balance, scannedTo, raw utxos to cache
                 * TODO ad qr generator for those data
                 */
                _self.emit('FINISH_SCANNING');
                _self.emit('ON_BALANCE_CHANGE');

                console.log('Total Balance : ', _self.balance.toString(10));
                console.log('Scanned To : ', _self.scannedTo);
                resolve({
                    utxos: rawUTXOs,
                    balance: this.decimalBalance(),
                });
            }).catch((ex) => {
                reject(ex);
            });
        });
    }

    _restoreWalletState(balance: number | string, scannedTo: number, utxos: Array<Object>) {
        if (balance !== null) {
            this.balance = toBN(
                balance || '00',
            );
        }

        if (scannedTo !== null) { this.scannedTo = parseInt(scannedTo) || -1; }

        if (utxos !== null) { this.utxos = utxos; }
    }

    qrUTXOsData() {
    }

    /**
     * Get UTXOs for making transaction with amount
     * @param {BigInteger} amount
     * @returns {Object} needed utxos, number of transaction to send all the amount
     */
    _getSpendingUTXO = (amount: BigInteger): Array<UTXO> => {
        const spendingUTXOS = [];
        let i = 0;
        let justEnoughBalance = BigInteger.ZERO();
        let txTimes = 1;

        while (amount.cmp(
            justEnoughBalance.sub(
                toBN(txTimes).mul(CONSTANT.PRIVACY_FLAT_FEE),
            ),
        ) > 0 && this.utxos[i]) {
            justEnoughBalance = justEnoughBalance.add(
                toBN(
                    this.utxos[i].decodedAmount,
                ),
            );
            spendingUTXOS.push(this.utxos[i]);

            if (spendingUTXOS.length / CONSTANT.MAXIMUM_ALLOWED_RING_NUMBER > txTimes) {
                txTimes++;
            }

            i++;
        }

        console.log('... Doing TX with ', spendingUTXOS.length, ' UTXOs');
        console.log('... Split into ', txTimes, ' sub-tx');

        // not enough balance to pay fee + amount
        if (amount.cmp(
            justEnoughBalance.sub(
                toBN(txTimes).mul(CONSTANT.PRIVACY_FLAT_FEE),
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
            totalFee: toBN(txTimes).mul(CONSTANT.PRIVACY_FLAT_FEE),
        };
    }

    /**
     * Split a complex transaction (with utxos number > CONSTANT.MAXIMUM_ALLOWED_RING_NUMBER)
     * into multiple sub-transaction with utxos number <= CONSTANT.MAXIMUM_ALLOWED_RING_NUMBER
     * @param {Array<UTXO>} utxos all utxos need for this tx
     * @param {number} txTimes number of transactions need to do
     * @param {BigInteger} txAmount total amount need to transfer
     * @returns {Array<Object>} list transaction each include needed utxos, remain amount, receiver amount
     */
    _splitTransaction = (utxos: Array<UTXO>, txTimes: number, txAmount: BigInteger): Array<Object> => {
        const txs = [];
        let sentAmount = BigInteger.ZERO();

        for (let index = 0; index < txTimes - 1; index++) {
            // TODO pick CONSTANT.MAXIMUM_ALLOWED_RING_NUMBER utxos each round while total > CONSTANT.PRIVACY_FLAT_FEE
            const spendingUTXO = utxos.splice(0, CONSTANT.MAXIMUM_ALLOWED_RING_NUMBER);
            const totalThisRound = this._calTotal(spendingUTXO);
            if (totalThisRound.cmp(CONSTANT.PRIVACY_FLAT_FEE) > 0) {
                const sentAmountThisTx = this._calTotal(spendingUTXO).sub(CONSTANT.PRIVACY_FLAT_FEE);
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
            remainAmount: remain.add(sentAmount).sub(CONSTANT.PRIVACY_FLAT_FEE).sub(txAmount),
        });

        return txs;
    }

    /**
     * Estimate fee
     */
    estimateFee = (amount: number): BigInteger => {
        const biAmount = toBN(amount).div(CONSTANT.PRIVACY_TOKEN_UNIT);

        assert(biAmount.cmp(this.balance) <= 0, 'Balance is not enough');
        assert(biAmount.cmp(BigInteger.ZERO()) > 0, 'Amount should be larger than zero');

        const {
            totalFee,
        } = this._getSpendingUTXO(
            biAmount,
        );

        return totalFee.mul(CONSTANT.PRIVACY_TOKEN_UNIT);
    }

    /**
     * Sum amount of a group utxos
     * @param {Array<UTXO>} utxos
     * @returns {BigInteger}
     */
    _calTotal = (utxos: Array<UTXO>): BigInteger => {
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
     * @param {string} message
     * @returns {object} includes new utxos and original created proof
     * on some very first version, we store the proof locally to help debugging if error happens
     */
    send = async (privacyAddress: string, amount: string | number, message: ?string) => {
        assert(privacyAddress.length === CONSTANT.PRIVACY_ADDRESS_LENGTH, 'Malform privacy address !!');

        if (!this.balance) {
            await this.scan();
        }

        const biAmount = toBN(amount).div(CONSTANT.PRIVACY_TOKEN_UNIT);

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
        const totalSpent = utxos.length;

        let currentTx = 0;
        try {
            while (txs[currentTx]) {
                // eslint-disable-next-line no-await-in-loop
                const proof = await this._makePrivateSendProof(
                    privacyAddress,
                    txs[currentTx].receivAmount,
                    txs[currentTx].utxos,
                    txs[currentTx].remainAmount,
                    message,
                );

                // eslint-disable-next-line no-await-in-loop
                const res = await this._send(proof);
                totalResponse.push(res.NewUTXO);
                currentTx++;
            }
            this.emit('FINISH_SENDING');
        } catch (ex) {
            this.utxos.splice(0, totalSpent - txs.length);
            this.balance = this._calTotal(this.utxos);
            this.emit('ON_BALANCE_CHANGE');
            this.emit('STOP_SENDING', ex);
            throw ex;
        }

        // we don't add the response here because of listening to SC-event already
        this.utxos.splice(0, totalSpent);
        this.balance = this._calTotal(this.utxos);

        this.emit('FINISH_SENDING');
        this.emit('ON_BALANCE_CHANGE');
        return totalResponse;
    }

    /**
     * Use Web3 to sign and make tx to smart-contract
     * because we don't need to pay the tx fee directly (TRC21)
     * so we randomizing privatekey each time sending
     * @param {Array} proof
     * @returns {object} new utxos and proof
     */
    _send = (proof: Array<any>): Promise<any> => {
        let address;
        let privacyContract;

        try {
            // const randomPrivatekey = secp256k1.genKeyPair().getPrivate().toString('hex');
            const randomPrivatekey = Web3.utils.randomHex(32).slice(2);

            const provider = new HDWalletProvider(randomPrivatekey, this.scOpts.RPC_END_POINT);
            const web3 = new Web3(provider);
            const account = web3.eth.accounts.privateKeyToAccount('0x' + randomPrivatekey);

            address = account.address;

            privacyContract = new web3.eth.Contract(
                this.scOpts.ABI, this.scOpts.ADDRESS, {
                    gasPrice: this.scOpts.gasPrice,
                    gas: this.scOpts.gas,
                },
            );
        } catch (ex) {
            console.log('EX -- ', ex);
        }

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
     * @param {string} message
     * @returns {object} includes new utxos and original created proof
     * on some very first version, we store the proof locally to help debugging if error happens
     */
    withdraw = async (address: string, amount: string | number, message: ?string) => {
        assert(address.length === CONSTANT.ETH_ADDRESS_LENGTH, 'Malform address !!');

        if (!this.balance) {
            await this.scan();
        }

        const biAmount = toBN(amount).div(CONSTANT.PRIVACY_TOKEN_UNIT);

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
                    message,
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
            this.emit('ON_BALANCE_CHANGE');

            throw ex;
        }

        this.utxos.splice(0, totalSpent);
        this.balance = this._calTotal(this.utxos);

        this.emit('FINISH_WITHDRAW');
        this.emit('ON_BALANCE_CHANGE');

        return totalResponse;
    }

    /**
    * Use Web3 to sign and make tx to smart-contract
    * @param {Array} proof
    * @returns {object} new utxos and proof
    */
    _withdraw(proof: Array<any>): Promise<any> {
        // const randomPrivatekey = secp256k1.genKeyPair().getPrivate().toString('hex');
        const randomPrivatekey = Web3.utils.randomHex(32).slice(2);
        const provider = new HDWalletProvider(randomPrivatekey, this.scOpts.RPC_END_POINT);
        const web3 = new Web3(provider);
        const { address } = web3.eth.accounts.privateKeyToAccount('0x' + randomPrivatekey);
        const privacyContract = new web3.eth.Contract(
            this.scOpts.ABI, this.scOpts.ADDRESS, {
                gasPrice: this.scOpts.gasPrice,
                gas: this.scOpts.gas,
            },
        );

        return new Promise((resolve, reject) => {
            privacyContract.methods.withdrawFunds(...proof)
                .send({
                    from: address,
                })
                .on('error', (error) => {
                    reject(error);
                })
                .then((receipt) => {
                    resolve({
                        ...receipt.events,
                        tx: receipt,
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
        const decoysIndex = [];

        const MAXIMUM_RANDOMIZATION_TIMES = 50;
        let randomizationTimes = 0;

        // should stop if after 50 randomization times can't get all decoys
        for (let counter = 0; counter < CONSTANT.UTXO_RING_SIZE + 1; counter++) {
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
        const ringSize = CONSTANT.UTXO_RING_SIZE; // 11 decoys + one spending

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
                const lfCommitment = toPoint(proof.commitment);
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
                }${ringSignature.c1.toString(16, 64)
                }${_.map(_.flatten(ringSignature.s), element => element.toString(16, 64)).join('')
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
    * @param {BigInteger} remain
    * @param {BigInteger} amount
    * @returns {Object} Proof
    */
    _genRangeProof(remain: BigInteger, amount: BigInteger, masks: Array<BigInteger>): Buffer {
        let result = BulletProof.prove([
            remain,
            amount,
        ], [
            masks[0],
            masks[1],
        ]);

        result = BulletProof.proofToHex(result);

        return Buffer.from(
            toBN(result.CommsLength).toString(16, 8)
            + result.Comms
            + result.A
            + result.S
            + result.T1
            + result.T2
            + result.Tau
            + result.Th
            + result.Mu
            + [
                result.Ipp.L,
                result.Ipp.R,
                result.Ipp.A,
                result.Ipp.B,
                result.Ipp.Challenges,
            ].join('')
            + result.cy
            + result.cz
            + result.cx,
            'hex',
        );
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
        let receiverStealth;
        let proofOfReceiver;

        if (isWithdraw) {
            // When withdraw, we set mask = 0, so commitment  = value*H
            proofOfReceiver = this.stealth.genTransactionProof(
                amount.toString(10), null, null, '0',
            );
        } else {
            receiverStealth = Stealth.fromString(receiver);
            proofOfReceiver = receiverStealth.genTransactionProof(
                amount.toString(10),
            );
        }

        const proofOfMe = this.stealth.genTransactionProof(
            remain.toString(10),
        );

        const proofOfFee = this.stealth.genTransactionProof(
            CONSTANT.PRIVACY_FLAT_FEE.toString(10), null, null, '0',
        );

        return [proofOfReceiver, proofOfMe, proofOfFee];
    }

    /**
    * Create proof base on amount and privacy_addres
    * @param {string} receiver privacy address
    * @param {BigInteger} amount
    * @param {Array<UTXO>} spendingUTXOs
    * @param {BigInteger} remain
    * @param {string} [message]
    * @returns {Object} proof output
    */
    async _makePrivateSendProof(receiver: string, amount: BigInteger, spendingUTXOs: Array<UTXO>, remain: BigInteger, message: ?string): Array {
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
            this._genRangeProof(remain, amount, [
                BigInteger.fromHex(outputProofs[1].mask),
                BigInteger.fromHex(outputProofs[0].mask),
            ]),
            _.map(
                this._encryptedTransactionData(
                    [outputProofs[1], outputProofs[0]], amount, receiver, message || '',
                ).toString('hex').match(/.{1,2}/g), num => '0x' + num,
            ),
        ];
    }

    /**
    * Create proof base on amount and privacy_addres
    * @param {string} receiver privacy address
    * @param {BigInteger} amount
    * @param {Array<UTXO>} spendingUTXOs
    * @param {BigInteger} remain
    * @param {string} string
    * @returns {Object} proof output
    */
    async _makeWithdrawProof(receiver: string, amount: BigInteger, spendingUTXOs: Array<UTXO>, remain: BigInteger, message: ?string): Array {
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
            '0x' + amount.mul(CONSTANT.PRIVACY_TOKEN_UNIT).toString(16), // withdawal amount need multiple with 10^9, convert gwei to wei
            [
                `0x${outputProofs[1].encryptedAmount}`, // encrypt of amount using ECDH],
                `0x${outputProofs[1].encryptedMask}`, // encrypt of mask using ECDH],
            ],
            receiver,
            signature,
            this._genRangeProof(remain, amount, [
                BigInteger.fromHex(outputProofs[1].mask),
                BigInteger.fromHex(outputProofs[0].mask),
            ]),
            // _.fill(Array(137), '0x0'),
            _.map(
                this._encryptedTransactionData(
                    [outputProofs[1], outputProofs[0]], amount, receiver, message || '',
                ).toString('hex').match(/.{1,2}/g), num => '0x' + num,
            ),
        ];
    }

    /**
     * Check if the utxo spent or not by KeyImage (refer MLSAG)
     * @param {UTXO} utxo
     * @returns {boolean}
     */
    isSpent = (utxo: UTXO): Promise<boolean> => {
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
     * Check if the utxo spent or not by KeyImage (refer MLSAG)
     * @param {UTXO} utxo
     * @returns {boolean}
     */
    areSpent = (utxos: Array<UTXO>): Promise<boolean> => {
        const privKey = this.addresses.privSpendKey;

        return new Promise((resolve, reject) => {
            this.privacyContract.methods.areSpent(
                Buffer.from(_.map(utxos, (utxo) => {
                    const ringctKeys = utxo.getRingCTKeys(privKey);
                    return keyImage(
                        BigInteger.fromHex(ringctKeys.privKey),
                        utxo.lfStealth.encode('hex', false).slice(2),
                    ).encode('hex', true);
                }).join(''), 'hex'),
            )
                .call({
                    from: this.scOpts.from,
                })
                .then(areSpent => resolve(areSpent)).catch((exception) => {
                    reject(exception);
                });
        });
    }

    /**
     * Check if the utxo spent or not by KeyImage (refer MLSAG)
     * @param {UTXO} utxo
     * @returns {boolean}
     */
    getTxs = (txIndexs: Array<number>): Promise<boolean> => new Promise((resolve, reject) => {
        this.privacyContract.methods.getTxs(
            txIndexs,
        )
            .call({
                from: this.scOpts.from,
            })
            .then(txs => resolve(txs)).catch((exception) => {
                reject(exception);
            });
    })

    /**
     * Check utxo's proof belongs
     * consider changing input format
     * @param {Buffer | string} txPubkey transaction public key
     * @param {Buffer | string} stealth one time address or public key of UTXO
     * @param {string} encryptedAmount AES(ECDH, amount) in hex string
     * @returns {Object} stealth_private_key, stealth_public_key, real amount
     */
    isMine = (txPubkey: Buffer | string, stealth: Buffer | string, encryptedAmount: string): DecodedProof => this.stealth.checkTransactionProof(
        txPubkey, stealth, encryptedAmount,
    )

    /**
     * Tx_data is a struct that encoded by
     * Secretkey = hash(hash(privateViewKey) + tx_utxo_stealth_1 ... tx_utxo_stealth_n)
     * So for checking weather TX created by you
     * just need to check yourown first 8 data bytes as check sum
     * @param {Array<number> | Array<UTXO>} utxos output utxos
     * @param {Buffer} data Transaction data
     * @returns {Object | null} return decrypted tx data
     */
    checkTxOwnership = async (utxos: Array<number> | Array<UTXO>, data: Buffer) => {
        assert(utxos && utxos.length, 'Blank utxos input ');

        let UTXOIns;

        if (typeof utxos[0] === 'string' || typeof utxos[0] === 'number') {
            UTXOIns = await this.getUTXOs(utxos);
            UTXOIns = _.map(UTXOIns, raw => new UTXO(raw));
        } else {
            UTXOIns = utxos;
        }

        // generate and compare TX-secretkey with the original
        const secretKey = keccak256(
            this.addresses.privViewKey + _.map(UTXOIns, raw => raw.lfTxPublicKey.encode('hex', false)).join(''),
        );

        let decodedData = decodeTx(
            data.slice(8, 137).toString('hex'),
            secretKey,
            false, // arithmetic calculation not on secp256k1 curve
        );

        decodedData = padLeft(decodedData, 256);

        const computedCheckSum = keccak256(decodedData).slice(0, 16);

        if (computedCheckSum === data.slice(0, 8).toString('hex')) {
            let receiver = decodedData.substr(32, 140);

            if (receiver.replace(/^0*/, '').length !== 42) {
                receiver = base58.encode(Buffer.from(decodedData.substr(32, 140), 'hex')).toString('hex');
            }
            return {
                amount: BigInteger.fromHex(decodedData.substr(0, 16)).toString(10),
                createdAt: BigInteger.fromHex(decodedData.substr(16, 16)).toString(10),
                receiver,
                message: Web3.utils.hexToAscii('0x' + decodedData.substr(172, 84)).replace(/\u0000/igm, ''),
            };
        }

        return null;
    }

    /**
     * Encrypt the transaction data
     * @param {Array<UTXO>} output utxos
     * @param {number} amount plain spending amount - in gwei
     * @param {string} receiver privacy address out receiver
     * @param {string} message meta data of tx
     */
    _encryptedTransactionData(outputUTXOs: Array<Object>, amount: number, receiver: string, message: string) {
        const secretKey = keccak256(
            this.addresses.privViewKey + _.map(outputUTXOs, utxo => utxo.txPublicKey).join(''),
        );

        // conver to buffer array
        const data = Buffer.concat([
            Buffer.from(
                padLeft(toHex(amount), 16), 'hex',
            ),
            Buffer.from(
                padLeft(toHex(parseInt(new Date() / 1000)), 16), 'hex',
            ),
            Buffer.from(receiver.length === 42 ? receiver : base58.decode(receiver)),
            Buffer.from(
                padLeft(
                    Web3.utils.asciiToHex(message).slice(2),
                    84,
                ),
                'hex',
            )]);

        const encodedData = encodeTx(
            data.toString('hex'),
            secretKey,
            false, // arithmetic calculation not on secp256k1 curve
        );

        const checksum = keccak256(data.toString('hex')).slice(0, 16);

        const res = Buffer.from(checksum
            + padLeft(encodedData, 258), 'hex');

        return res;
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
        return this.balance ? this.balance.mul(CONSTANT.PRIVACY_TOKEN_UNIT).toString(10) : BigInteger.ZERO();
    }

    hexBalance() {
        return this.balance ? '0x' + this.balance.mul(CONSTANT.PRIVACY_TOKEN_UNIT).toString(16) : '0x0';
    }

    state(state: Object) {
        // need to update wallet state
        if (state) {
            this._restoreWalletState(
                state.balance,
                state.scannedTo,
                state.utxos,
            );
        }

        return {
            balance: this.balance ? this.balance.toString(10) : '0',
            scannedTo: this.scannedTo !== -1 ? this.scannedTo : -1,
            utxos: this.utxos,
        };
    }

    listenNewUTXO(scOpts: SmartContractOpts) {
        const webSocketProvider = new Web3.providers.WebsocketProvider(scOpts.SOCKET_END_POINT);
        const web3Socket = new Web3(webSocketProvider);
        this.privacyContractSocket = new web3Socket.eth.Contract(scOpts.ABI, scOpts.ADDRESS);

        // listen to new UTXO
        this.privacyContractSocket.events.NewUTXO().on('data', (evt) => {
            const utxoInstance = new UTXO(evt.returnValues);
            const isMine = utxoInstance.checkOwnership(this.addresses.privSpendKey);

            if (isMine && isMine.amount && isMine.amount.toString() !== '0') {
                const rawutxo = {
                    ...evt.returnValues,
                    decodedAmount: isMine.amount,
                };

                // this.utxos.push(rawutxo);

                // this.balance = this._calTotal(this.utxos);

                this.emit('ON_BALANCE_CHANGE');

                this.emit('NEW_UTXO', rawutxo);
            }
        });

        // listen to new TX - this for history
        this.privacyContractSocket.events.NewTransaction().on('data', async (evt) => {
            console.log(evt);
            const data = _.map(evt.returnValues[2], byte => byte.substr(2, 2)).join('');
            const txData = await this.checkTxOwnership(
                _.map(evt.returnValues[1], raw => new UTXO(raw)),
                Buffer.from(data, 'hex'),
            );

            if (txData !== null) { this.emit('NEW_TRANSACTION', txData); }
        });
    }
}
