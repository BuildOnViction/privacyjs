/* eslint-disable max-len */
/* eslint-disable no-loop-func */
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import * as _ from 'lodash';
import Wallet from '../../src/wallet';
import Configs from '../config.json';
import { randomUTXOS } from '../utils';

const EC = require('elliptic').ec;

const secp256k1 = new EC('secp256k1');
const address = require('../../src/address');

const { expect } = chai;
chai.should();
chai.use(chaiAsPromised);

const { WALLETS } = Configs;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo
const RECEIVER_WALLET = WALLETS[1]; // hold around 1 mil tomo

describe('#unittest #wallet', () => {
    describe('#tx_encrypted', () => {
        for (let index = 0; index < 10; index++) {
            it('should able to encrypt/decrypt tx data for two outputs', (done) => {
                try {
                    const wallet = new Wallet(SENDER_WALLET.privateKey, {
                        RPC_END_POINT: Configs.RPC_END_POINT,
                        ABI: Configs.PRIVACY_ABI,
                        ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
                        gasPrice: '250000000',
                        gas: '20000000',
                    }, SENDER_WALLET.address);
                    const receiverAddress = address
                        .generateKeys(RECEIVER_WALLET.privateKey).pubAddr;

                    let outputUTXOs = randomUTXOS(
                        RECEIVER_WALLET.privateKey,
                        [100000000, 2000000],
                    );

                    const encryptedTxData = wallet._encryptedTransactionData(
                        outputUTXOs, 10000000, receiverAddress, `test Tx 0${index}`,
                    );

                    expect(encryptedTxData).to.not.equal(null);
                    expect(encryptedTxData.length).to.be.equal(137);

                    outputUTXOs = _.map(outputUTXOs, utxo => ({
                        lfTxPublicKey: secp256k1.curve.pointFromJSON([
                            utxo.txPublicKey.substr(2, 64),
                            utxo.txPublicKey.substr(66, 64),
                        ]),
                    }));

                    wallet.checkTxOwnership(outputUTXOs, encryptedTxData).then((decryptedTxData) => {
                        expect(decryptedTxData).to.not.equal(null);
                        expect(decryptedTxData.amount).to.equal('10000000');
                        expect(decryptedTxData.message).to.equal(`test Tx 0${index}`);
                        expect(decryptedTxData.receiver.toUpperCase()).to.equal(receiverAddress.toString().toUpperCase());
                        done();
                    }).catch((ex) => {
                        done(ex);
                    });
                } catch (exception) {
                    // expect(exception.toString()).to
                    // .be.equal('AssertionError [ERR_ASSERTION]: Malform private key !!');
                    done(exception);
                }
            });
        }

        for (let index = 0; index < 10; index++) {
            it('should able to encrypt/decrypt tx data for one output (deposit)', (done) => {
                try {
                    const wallet = new Wallet(SENDER_WALLET.privateKey, {
                        RPC_END_POINT: Configs.RPC_END_POINT,
                        ABI: Configs.PRIVACY_ABI,
                        ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
                        gasPrice: '250000000',
                        gas: '20000000',
                    }, SENDER_WALLET.address);
                    const receiverAddress = address
                        .generateKeys(RECEIVER_WALLET.privateKey).pubAddr;

                    let outputUTXOs = randomUTXOS(
                        RECEIVER_WALLET.privateKey,
                        [100000000],
                    );

                    const encryptedTxData = wallet._encryptedTransactionData(
                        outputUTXOs, 2000000, receiverAddress, `test Tx 0${index}`,
                    );

                    expect(encryptedTxData).to.not.equal(null);
                    expect(encryptedTxData.length).to.be.equal(137);

                    outputUTXOs = _.map(outputUTXOs, utxo => ({
                        lfTxPublicKey: secp256k1.curve.pointFromJSON([
                            utxo.txPublicKey.substr(2, 64),
                            utxo.txPublicKey.substr(66, 64),
                        ]),
                    }));

                    wallet.checkTxOwnership(outputUTXOs, encryptedTxData).then((decryptedTxData) => {
                        expect(decryptedTxData).to.not.equal(null);
                        expect(decryptedTxData.amount).to.equal('2000000');
                        expect(decryptedTxData.message).to.equal(`test Tx 0${index}`);
                        expect(decryptedTxData.receiver.toUpperCase()).to.equal(receiverAddress.toString().toUpperCase());
                        done();
                    }).catch((ex) => {
                        done(ex);
                    });
                } catch (exception) {
                    // expect(exception.toString()).to
                    // .be.equal('AssertionError [ERR_ASSERTION]: Malform private key !!');
                    done(exception);
                }
            });
        }

    });
});
