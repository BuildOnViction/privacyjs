/* eslint-disable no-loop-func */
import chai from 'chai';
import * as _ from 'lodash';
import toBN from 'number-to-bn';
import TestConfig from '../config.json';
import Wallet from '../../src/wallet';
import { generateKeys } from '../../src/address';
import UTXO from '../../src/utxo';
import { BigInteger } from '../../src/common';

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;

/* eslint-disable max-len */
// eslint-disable-next-line max-len
/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */

describe('#ete #wallet', () => {
    let wallet: Wallet;
    let sendWallet: Wallet;

    beforeEach((done) => {
        wallet = new Wallet(WALLETS[1].privateKey, {
            RPC_END_POINT: TestConfig.RPC_END_POINT,
            ABI: TestConfig.PRIVACY_ABI,
            ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
        }, WALLETS[1].address);
        done();
    });

    describe('#decoys', () => {
        for (let count = 0; count < 5; count++) {
            it('Should get decoys successfully for 5 rings', (done) => {
                wallet.scannedTo = 15;
                wallet._getDecoys(5, [1, 5]).then((res) => {
                    expect(res.length).to.equal(5);
                    expect(res[0].length).to.equal(11);
                    expect(res[1].length).to.equal(11);
                    // expect(typeof res[0][0]).to.equal('UTXO');

                    // const randomElement = res[
                    //     Math.round(Math.random() * 1)
                    // ][
                    //     Math.round(Math.random() * 10)
                    // ];
                    // expect(randomElement).has.property('lfCommitment');
                    // expect(randomElement).has.property('index');
                    // expect(randomElement).has.property('lfStealth');
                    done();
                }).catch((err) => {
                    done(err);
                });
            });
        }
    });

    describe('#getUTXO', () => {
        it('Should get single utxo successfully', (done) => {
            wallet.scannedTo = 15;
            wallet.getUTXO(10).then((res) => {
                expect(res[0].length).to.equal(3);
                expect(res[1].length).to.equal(3);
                expect(res[2].length).to.equal(2);
                expect(res[3]).to.equal(10);
                done();
            }).catch((err) => {
                done(err);
            });
        });
    });

    describe('#tx_data', () => {
        sendWallet = new Wallet(WALLETS[1].privateKey, {
            RPC_END_POINT: TestConfig.RPC_END_POINT,
            ABI: TestConfig.PRIVACY_ABI,
            ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
        }, WALLETS[1].address);

        sendWallet.scannedTo = 0;
        for (let index = 0; index < 5; index++) {
            it('Should able to send and receive correct encrypted tx data TOMO', (done) => {
                const receiver = generateKeys(WALLETS[2].privateKey);
                try {
                    sendWallet.send(receiver.pubAddr, '50000000000000000', `test multiple sending ${index}`).then((txs) => {
                        expect(txs).to.be.an('array');
                        expect(txs.length).to.be.above(0);
                        _.each(txs, (NewUTXO) => {
                            expect(NewUTXO).to.not.equal(undefined);
                            expect(NewUTXO.length).to.equal(2); // always create two
                            const returnUTXOs = NewUTXO.map(utxo => utxo.returnValues);

                            // make sure at least one utxo belonging to receiver, one for sender
                            // and encrypted amount correct
                            const senderUTXOIns = new UTXO(returnUTXOs[0]);
                            const receiverUTXOIns = new UTXO(returnUTXOs[1]);

                            const decodedSenderUTXO = senderUTXOIns.checkOwnership(WALLETS[1].privateKey);
                            const decodedReceiverUTXO = receiverUTXOIns.checkOwnership(
                                WALLETS[2].privateKey,
                            );

                            expect(senderUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);
                            expect(receiverUTXOIns.checkOwnership(WALLETS[2].privateKey)).to.not.equal(null);

                            expect(decodedSenderUTXO).to.not.be.equal(null);
                            expect(decodedReceiverUTXO).to.not.be.equal(null);

                            sendWallet.getTxs([returnUTXOs[0]._txIndex]).then((txData) => {
                                const data = _.map(txData[0][1], byte => byte.substr(2, 2)).join('');

                                sendWallet.checkTxOwnership(
                                    [senderUTXOIns, receiverUTXOIns],
                                    Buffer.from(data, 'hex'),
                                ).then((decryptedTxData) => {
                                    expect(decryptedTxData).to.not.equal(null);
                                    expect(decryptedTxData.amount).to.equal('50000000');
                                    expect(decryptedTxData.message).to.equal(`test multiple sending ${index}`);
                                    expect(decryptedTxData.receiver.toUpperCase()).to.equal(receiver.pubAddr.toUpperCase());
                                    done();
                                }).catch((ex) => {
                                    done(ex);
                                });
                            });
                        });
                    }).catch((err) => {
                        done(err);
                    });
                } catch (ex) {
                    done(ex);
                }
            });
        }
    });

    describe('#send', () => {
        // beforeEach(() => {
        sendWallet = new Wallet(WALLETS[1].privateKey, {
            RPC_END_POINT: TestConfig.RPC_END_POINT,
            ABI: TestConfig.PRIVACY_ABI,
            ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
        }, WALLETS[1].address);
        // });
        sendWallet.scannedTo = 0;
        it('Should not able to send 0 TOMO', (done) => {
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                sendWallet.send(receiver.pubAddr, '0').then(() => {
                    done(new Error(''));
                }).catch(() => {
                    done();
                });
            } catch (ex) {
                done(ex);
            }
        });

        it('Should able to send value = 1 UTXO\'s amount ', (done) => {
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                sendWallet.send(receiver.pubAddr, '1000000000000000000').then((txs) => {
                    expect(txs).to.be.an('array');
                    expect(txs.length).to.be.above(0);

                    _.each(txs, (NewUTXO) => {
                        expect(NewUTXO).to.not.equal(undefined);
                        expect(NewUTXO.length).to.equal(2); // always create two
                        const returnUTXOs = NewUTXO.map(utxo => utxo.returnValues);

                        // make sure at least one utxo belonging to receiver, one for sender
                        // and encrypted amount correct
                        const senderUTXOIns = new UTXO(returnUTXOs[1]);
                        const receiverUTXOIns = new UTXO(returnUTXOs[0]);

                        const decodedSenderUTXO = senderUTXOIns.checkOwnership(WALLETS[1].privateKey);
                        const decodedReceiverUTXO = receiverUTXOIns.checkOwnership(
                            WALLETS[1].privateKey,
                        );

                        expect(senderUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);
                        expect(receiverUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);

                        expect(decodedSenderUTXO).to.not.be.equal(null);
                        expect(decodedReceiverUTXO).to.not.be.equal(null);

                        // expect(decodedSenderUTXO.amount === (2.5 * TOMO).toString()).to.be.equal(true);
                        // expect(decodedReceiverUTXO.amount === '0').to.be.equal(true);
                    });

                    done();
                }).catch((err) => {
                    done(err);
                });
            } catch (ex) {
                done(ex);
            }
        });

        for (let index = 0; index < 5; index++) {
            it('Should able to send 1.5 TOMO', (done) => {
                const receiver = generateKeys(WALLETS[1].privateKey);
                try {
                    sendWallet.send(receiver.pubAddr, '1500000000000000000', `test multiple sending ${index}`).then((txs) => {
                        expect(txs).to.be.an('array');
                        expect(txs.length).to.be.above(0);
                        _.each(txs, (NewUTXO) => {
                            expect(NewUTXO).to.not.equal(undefined);
                            expect(NewUTXO.length).to.equal(2); // always create two
                            const returnUTXOs = NewUTXO.map(utxo => utxo.returnValues);

                            // make sure at least one utxo belonging to receiver, one for sender
                            // and encrypted amount correct
                            const senderUTXOIns = new UTXO(returnUTXOs[1]);
                            const receiverUTXOIns = new UTXO(returnUTXOs[0]);

                            const decodedSenderUTXO = senderUTXOIns.checkOwnership(WALLETS[1].privateKey);
                            const decodedReceiverUTXO = receiverUTXOIns.checkOwnership(
                                WALLETS[1].privateKey,
                            );

                            expect(senderUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);
                            expect(receiverUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);

                            expect(decodedSenderUTXO).to.not.be.equal(null);
                            expect(decodedReceiverUTXO).to.not.be.equal(null);

                        });

                        // TODO wallet need includes new generated utxos
                        // expect(wallet.utxos).to.be.equal(true);

                        done();
                    }).catch((err) => {
                        done(err);
                    });
                } catch (ex) {
                    done(ex);
                }
            });
        }


        it('Should able to send with needed utxos > ring_number', (done) => {
            /**
             * the scenario here is trying to spend 6 TOMO (maximum ring number is 5)
             * so wallet needs to divide into multiple tx
             */
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                sendWallet.send(receiver.pubAddr, '400000000000000000').then((txs) => {
                    let receiveMoney = BigInteger.ZERO();
                    expect(txs).to.be.an('array');
                    expect(txs.length).to.be.above(0);
                    _.each(txs, (NewUTXO) => {
                        expect(NewUTXO).to.not.equal(undefined);
                        expect(NewUTXO.length).to.equal(2); // always create two
                        const returnUTXOs = NewUTXO.map(utxo => utxo.returnValues);

                        // make sure at least one utxo belonging to receiver, one for sender
                        // and encrypted amount correct
                        const senderUTXOIns = new UTXO(returnUTXOs[1]);
                        const receiverUTXOIns = new UTXO(returnUTXOs[0]);

                        const decodedSenderUTXO = senderUTXOIns.checkOwnership(WALLETS[1].privateKey);
                        const decodedReceiverUTXO = receiverUTXOIns.checkOwnership(
                            WALLETS[1].privateKey,
                        );

                        expect(senderUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);
                        expect(receiverUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);

                        expect(decodedSenderUTXO).to.not.be.equal(null);
                        expect(decodedReceiverUTXO).to.not.be.equal(null);

                        // expect(decodedSenderUTXO.amount === (2.5 * TOMO).toString()).to.be.equal(true);
                        // expect(decodedReceiverUTXO.amount === '100000').to.be.equal(true);
                        receiveMoney = receiveMoney.add(
                            toBN(decodedReceiverUTXO.amount),
                        );
                    });
                    expect(
                        receiveMoney.toString(16).toUpperCase() === 'B469471F80140000', // 13000000000000000000 in hex
                    );
                    done();
                }).catch((err) => {
                    done(err);
                });
            } catch (ex) {
                done(ex);
            }
        });

        it('Should not able to send with amount > balance', (done) => {
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                sendWallet.send(receiver.pubAddr, '1000000000000000000000000000').then(() => {
                    done(new Error(''));
                }).catch(() => {
                    done();
                });
            } catch (ex) {
                done(ex);
            }
        });

        it('Should not able to send with negative amount', (done) => {
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                sendWallet.send(receiver.pubAddr, '-100000000').then(() => {
                    done(new Error(''));
                }).catch(() => {
                    done();
                });
            } catch (ex) {
                done(ex);
            }
        });

        // it('Should able to send max balance', (done) => {
        //     const receiver = generateKeys(WALLETS[1].privateKey);
        //     try {
        //         sendWallet.scan(0).then(() => {
        //             sendWallet.send(receiver.pubAddr).then(() => {
        //                 console.log(sendWallet.balance.toString(10));
        //                 done();
        //             }).catch((err) => {
        //                 done(err);
        //             });
        //         });
        //     } catch (ex) {
        //         done(ex);
        //     }
        // });
    });

    describe('#withdraw', () => {
        const withdrawWallet = new Wallet(WALLETS[1].privateKey, {
            RPC_END_POINT: TestConfig.RPC_END_POINT,
            ABI: TestConfig.PRIVACY_ABI,
            ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
        }, WALLETS[1].address);

        for (let index = 0; index < 5; index++) {
            it('Should able to withdraw', (done) => {
                const receiver = WALLETS[1].address;
                try {
                    withdrawWallet.withdraw(receiver, '1000000000000000000').then((txs) => {
                        _.each(txs, (NewUTXO) => {
                            expect(NewUTXO).to.not.equal(undefined);
                            const returnUTXO = NewUTXO.returnValues;
                            const remainUTXOIns = new UTXO(returnUTXO);

                            expect(remainUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);
                        });

                        done();
                    }).catch((err) => {
                        done(err);
                    });
                } catch (ex) {
                    done(ex);
                }
            });
        }

        it('Should able to withdraw with needed utxos > ring_number', (done) => {
            /**
             * the scenario here is trying to spend 6 TOMO (maximum ring number is 5)
             * so wallet needs to divide into multiple tx
             */
            const receiver = WALLETS[1].address;
            try {
                withdrawWallet.withdraw(receiver, '8000000000000000000').then((txs) => {
                    _.each(txs, (NewUTXO) => {
                        expect(NewUTXO).to.not.equal(undefined);
                        const returnUTXO = NewUTXO.returnValues;
                        const remainUTXOIns = new UTXO(returnUTXO);

                        expect(remainUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);
                    });

                    done();
                }).catch((err) => {
                    done(err);
                });
            } catch (ex) {
                done(ex);
            }
        });

        it('Should not able to send with amount > balance', (done) => {
            const receiver = WALLETS[1].address;
            try {
                withdrawWallet.withdraw(receiver, '10000000000000000000000').then(() => {
                    done(new Error(''));
                }).catch(() => {
                    done();
                });
            } catch (ex) {
                done(ex);
            }
        });

    });
});
