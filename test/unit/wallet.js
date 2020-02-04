import sinon from 'sinon';
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import toBN from 'number-to-bn';
import Wallet from '../../src/wallet';
import Configs from '../config.json';
import * as CONSTANT from '../../src/constants';
// import UTXO from '../../src/utxo';

import { randomUTXOS } from '../utils';
import { toPoint } from '../../src/stealth';

const { expect } = chai;
chai.should();
chai.use(chaiAsPromised);

const { WALLETS } = Configs;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo
const GWEI = 1000000000;

describe('#unittest #wallet', () => {
    describe('#init()', () => {
        it('should not able to init wallet with wrong form private key', (done) => {
            try {
                const wallet = new Wallet(`${SENDER_WALLET.privateKey}AA`);
                done(new Error('Wallet should not be inited ', wallet));
            } catch (exception) {
                expect(exception.toString()).to.be.equal('AssertionError [ERR_ASSERTION]: Malform private key !!');
                done();
            }
        });

        it('should able to init wallet from private key', (done) => {
            const wallet = new Wallet(SENDER_WALLET.privateKey, {
                RPC_END_POINT: Configs.RPC_END_POINT,
                ABI: Configs.PRIVACY_ABI,
                ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
                gasPrice: '250000000',
                gas: '20000000',
            }, SENDER_WALLET.address);

            expect(wallet.addresses).to.not.equal(null);
            expect(wallet.addresses.privSpendKey.length).to.equal(CONSTANT.PRIVATE_KEY_LENGTH);
            expect(wallet.addresses.privViewKey.length).to.equal(CONSTANT.PRIVATE_KEY_LENGTH);
            expect(wallet.addresses.pubSpendKey.length).to.equal(CONSTANT.SHORT_FORM_CURVE_POINT);
            expect(wallet.addresses.pubViewKey.length).to.equal(CONSTANT.SHORT_FORM_CURVE_POINT);
            expect(wallet.addresses.pubAddr.length).to.equal(CONSTANT.PRIVACY_ADDRESS_LENGTH);

            done();
        });
    });

    describe('#deposit()', () => {
        let wallet;
        let wallet1;
        let stealthPoint;
        let txPubkeyPoint;
        let decodedProof;
        let proof;

        beforeEach((done) => {
            wallet = new Wallet(SENDER_WALLET.privateKey, {
                RPC_END_POINT: Configs.RPC_END_POINT,
                ABI: Configs.PRIVACY_ABI,
                ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
                gasPrice: '250000000',
                gas: '20000000',
            }, SENDER_WALLET.address);

            wallet1 = new Wallet(WALLETS[1].privateKey, {
                RPC_END_POINT: Configs.RPC_END_POINT,
                ABI: Configs.PRIVACY_ABI,
                ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
                gasPrice: '250000000',
                gas: '20000000',
            }, SENDER_WALLET.address);

            proof = wallet._genUTXOProof(1000000000);

            stealthPoint = toPoint(proof[0].slice(2) + proof[1].slice(2));
            txPubkeyPoint = toPoint(proof[2].slice(2) + proof[3].slice(2));

            done();
        });

        afterEach((done) => {
            // wallet.privacyContract.methods = originalDeposit;
            // sinon.replace(wallet.privacyContract.methods, 'deposit', originalDeposit);
            done();
        });

        it('should able to create a belonging utxo', (done) => {
            decodedProof = wallet.isMine(
                txPubkeyPoint.encode('hex', false), stealthPoint.encode('hex', false), proof[5].slice(2),
            );
            expect(decodedProof).to.not.equal(null);
            expect(decodedProof.amount).to.be.equal('1000000000');

            done();
        });

        it('should not able to decoded wallet\'s proof ', (done) => {
            // make sure other can't decode
            decodedProof = wallet1.isMine(
                txPubkeyPoint.encode('hex', false), stealthPoint.encode('hex', false), proof[5].slice(2),
            );

            expect(decodedProof).to.equal(null);

            done();
        });

        // in this case sc just just your input is on curve and
        // you have enough money to spend, nothing else
        it('should able to deposit with correct data', (done) => {
            try {
                // TODO stupid fake returns, find other way
                // we strictly test how the wallet parse and return data
                // in near future it would change by tx-base not utxo-base
                const fake = sinon.fake.returns({
                    send: () => ({
                        on: () => ({
                            then: (callback) => {
                                callback({
                                    events: { NewUTXO: { returnValues: {} } },
                                });
                            },
                        }),
                    }),
                });
                sinon.replace(wallet.privacyContract.methods, 'deposit', fake);
                wallet.deposit('1000000000')
                    .then((res) => {
                        expect(res).to.have.property('utxo');
                        expect(res.utxo).not.to.equal(null);
                        done();
                    })
                    .catch((err) => {
                        done(err);
                    });
            } catch (exception) {
                done(exception);
            }
        });

        it('should not able to parse other kind of data-structure', (done) => {
            try {
                // TODO stupid fake returns, find other way
                // we strictly test how the wallet parse and return data
                // in near future it would change by tx-base not utxo-base
                const fake = sinon.fake.returns({
                    send: () => ({
                        on: () => ({
                            then: (callback) => {
                                callback({
                                    events: {
                                        NewTX: {
                                            returnValues: { UTXO: {}, timestamp: new Date() },
                                        },
                                    },
                                });
                            },
                        }),
                    }),
                });
                sinon.replace(wallet.privacyContract.methods, 'deposit', fake);
                wallet.deposit('1000000000')
                    .then(() => {
                        done(new Error());
                    })
                    .catch(() => {
                        done();
                    });
            } catch (exception) {
                done(exception);
            }
        });
    });

    describe('#_getSpendingUTXO', () => {
        const wallet = new Wallet(SENDER_WALLET.privateKey, {
            RPC_END_POINT: Configs.RPC_END_POINT,
            ABI: Configs.PRIVACY_ABI,
            ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
            gasPrice: '250000000',
            gas: '20000000',
        }, SENDER_WALLET.address);

        wallet.utxos = randomUTXOS(SENDER_WALLET.privateKey, [
            GWEI,
            GWEI,
            3 * GWEI,
            5 * GWEI,
            0.1 * GWEI,
            GWEI,
            GWEI,
            3 * GWEI,
            5 * GWEI,
            0.1 * GWEI]); // create 10 utxos total balance = 10 tomo

        wallet.balance = toBN(10.1 * GWEI);
        CONSTANT.MAXIMUM_ALLOWED_RING_NUMBER = 4;

        it('Select utxos with tx amount = first utxo', (done) => {
            const {
                utxos, totalFee, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(GWEI),
            );
            expect(utxos.length === 2).to.be.equal(true);
            expect(txTimes === 1).to.be.equal(true);
            expect(totalFee.eq(toBN(0.01 * GWEI))).to.be.equal(true);
            done();
        });

        it('Select utxos with tx amount = 1.5 * first utxo', (done) => {
            const {
                utxos, totalFee, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(1.5 * GWEI),
            );
            expect(utxos.length === 2).to.be.equal(true);
            expect(txTimes === 1).to.be.equal(true);
            expect(totalFee.eq(toBN(0.01 * GWEI))).to.be.equal(true);
            done();
        });
        it('Select utxos with tx amount = sum first 2 utxos', (done) => {
            const {
                utxos, totalFee, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(2 * GWEI),
            );
            expect(utxos.length === 3).to.be.equal(true);
            expect(txTimes === 1).to.be.equal(true);
            expect(totalFee.eq(toBN(0.01 * GWEI))).to.be.equal(true);
            done();
        });
        it('Select utxos with tx amount = sum first 4 utxos', (done) => {

            const {
                utxos, totalFee, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(10 * GWEI),
            );
            expect(utxos.length === 5).to.be.equal(true);
            expect(txTimes === 2).to.be.equal(true);
            expect(totalFee.eq(toBN(0.02 * GWEI))).to.be.equal(true);
            done();
        });
        it('Select utxos with tx amount = sum 6 utxos', (done) => {
            const {
                utxos, totalFee, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(11.1 * GWEI),
            );
            expect(utxos.length === 7).to.be.equal(true);
            expect(txTimes === 2).to.be.equal(true);
            expect(totalFee.eq(toBN(0.02 * GWEI))).to.be.equal(true);
            done();
        });

        it('Select utxos with tx amount = sum 9 utxos', (done) => {
            const {
                utxos, totalFee, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(20.1 * GWEI),
            );
            expect(utxos.length === 10).to.be.equal(true);
            expect(txTimes === 3).to.be.equal(true);
            expect(totalFee.eq(toBN(0.03 * GWEI))).to.be.equal(true);
            done();
        });

        it('Select utxos with all balance - should return null utxos', (done) => {
            const {
                utxos,
            } = wallet._getSpendingUTXO(
                toBN(20.2 * GWEI),
            );
            expect(utxos).to.be.equal(null);
            done();
        });
    });


    describe('#_splitTransaction', () => {
        const wallet = new Wallet(SENDER_WALLET.privateKey, {
            RPC_END_POINT: Configs.RPC_END_POINT,
            ABI: Configs.PRIVACY_ABI,
            ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
            gasPrice: '250000000',
            gas: '20000000',
        }, SENDER_WALLET.address);

        wallet.utxos = randomUTXOS(SENDER_WALLET.privateKey, [
            GWEI,
            GWEI,
            3 * GWEI,
            5 * GWEI,
            0.1 * GWEI,
            GWEI,
            GWEI,
            3 * GWEI,
            5 * GWEI,
            0.1 * GWEI]); // create 10 utxos total balance = 10 tomo

        wallet.balance = toBN(20.2 * GWEI);

        it('Estimate Fee ', (done) => {
            expect(wallet.estimateFee('1500000000000000000').eq(
                CONSTANT.PRIVACY_FLAT_FEE.mul(CONSTANT.PRIVACY_TOKEN_UNIT),
            )).to.be.equal(true);

            expect(wallet.estimateFee('10000000000000000000').eq(
                CONSTANT.PRIVACY_FLAT_FEE.mul(
                    toBN(2),
                ).mul(CONSTANT.PRIVACY_TOKEN_UNIT),
            )).to.be.equal(true);

            expect(wallet.estimateFee('11000000000000000000').eq(
                CONSTANT.PRIVACY_FLAT_FEE.mul(
                    toBN(2),
                ).mul(CONSTANT.PRIVACY_TOKEN_UNIT),
            )).to.be.equal(true);

            expect(wallet.estimateFee('15100000000000000000').eq(
                CONSTANT.PRIVACY_FLAT_FEE.mul(
                    toBN(3),
                ).mul(CONSTANT.PRIVACY_TOKEN_UNIT),
            )).to.be.equal(true);

            // spend all
            expect(wallet.estimateFee().eq(
                CONSTANT.PRIVACY_FLAT_FEE.mul(
                    toBN(3),
                ).mul(CONSTANT.PRIVACY_TOKEN_UNIT),
            )).to.be.equal(true);

            done();
        });

        it('Select utxos with tx amount = first utxo', (done) => {
            const {
                utxos, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(GWEI),
            );

            const txs = wallet._splitTransaction(utxos, txTimes, toBN(GWEI));
            expect(txs.length).to.be.equal(1);
            expect(txs[0].utxos.length).to.be.equal(2);
            expect(txs[0].receivAmount.eq(toBN(GWEI))).to.be.equal(true);
            expect(txs[0].remainAmount.eq(toBN(0.99 * GWEI))).to.be.equal(true);

            done();
        });

        it('Select utxos with tx amount = 1.5 * first utxo', (done) => {
            const {
                utxos, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(1.5 * GWEI),
            );
            const txs = wallet._splitTransaction(utxos, txTimes, toBN(1.5 * GWEI));
            expect(txs.length).to.be.equal(1);
            expect(txs[0].utxos.length).to.be.equal(2);
            expect(txs[0].receivAmount.eq(toBN(1.5 * GWEI))).to.be.equal(true);
            expect(txs[0].remainAmount.eq(toBN(0.49 * GWEI))).to.be.equal(true);
            done();
        });

        it('Select utxos with tx amount = sum first 2 utxos', (done) => {
            const {
                utxos, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(2 * GWEI),
            );
            const txs = wallet._splitTransaction(utxos, txTimes, toBN(2 * GWEI));
            expect(txs.length).to.be.equal(1);
            expect(txs[0].utxos.length).to.be.equal(3);
            expect(txs[0].receivAmount.eq(toBN(2 * GWEI))).to.be.equal(true);
            expect(txs[0].remainAmount.eq(toBN(2.99 * GWEI))).to.be.equal(true);
            done();
        });

        it('Select utxos with tx amount = sum first 4 utxos', (done) => {
            const {
                utxos, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(10 * GWEI),
            );
            const txs = wallet._splitTransaction(utxos, txTimes, toBN(10 * GWEI));
            expect(txs.length).to.be.equal(2);

            expect(txs[0].utxos.length).to.be.equal(4);
            expect(txs[0].receivAmount.eq(toBN(9.99 * GWEI))).to.be.equal(true);
            expect(txs[0].remainAmount.eq(toBN(0 * GWEI))).to.be.equal(true);
            expect(txs[1].utxos.length).to.be.equal(1);
            expect(txs[1].receivAmount.eq(toBN(0.01 * GWEI))).to.be.equal(true);
            expect(txs[1].remainAmount.eq(toBN(0.08 * GWEI))).to.be.equal(true);
            done();
        });

        it('Select utxos with tx amount = sum 6 utxos', (done) => {
            const {
                utxos, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(11.1 * GWEI),
            );
            const txs = wallet._splitTransaction(utxos, txTimes, toBN(11.1 * GWEI));
            expect(txs.length).to.be.equal(2);

            expect(txs[0].utxos.length).to.be.equal(4);
            expect(txs[0].receivAmount.eq(toBN(9.99 * GWEI))).to.be.equal(true);
            expect(txs[0].remainAmount.eq(toBN(0 * GWEI))).to.be.equal(true);

            expect(txs[1].utxos.length).to.be.equal(3);
            expect(txs[1].receivAmount.eq(toBN(1.11 * GWEI))).to.be.equal(true);
            expect(txs[1].remainAmount.eq(toBN(0.98 * GWEI))).to.be.equal(true);
            done();
        });

        it('Select utxos with tx amount = sum 8 utxos', (done) => {
            const {
                utxos, txTimes,
            } = wallet._getSpendingUTXO(
                toBN(15.1 * GWEI),
            );
            const txs = wallet._splitTransaction(utxos, txTimes, toBN(15.1 * GWEI));
            expect(txs.length).to.be.equal(3);

            expect(txs[0].utxos.length).to.be.equal(4);
            expect(txs[0].receivAmount.eq(toBN(9.99 * GWEI))).to.be.equal(true);
            expect(txs[0].remainAmount.eq(toBN(0 * GWEI))).to.be.equal(true);

            expect(txs[1].utxos.length).to.be.equal(4);
            expect(txs[1].receivAmount.eq(toBN(5.09 * GWEI))).to.be.equal(true);
            expect(txs[1].remainAmount.eq(toBN(0 * GWEI))).to.be.equal(true);

            expect(txs[2].utxos.length).to.be.equal(1);
            expect(txs[2].receivAmount.eq(toBN(0.02 * GWEI))).to.be.equal(true);
            expect(txs[2].remainAmount.eq(toBN(4.97 * GWEI))).to.be.equal(true);
            done();
        });


        it('Select utxos with tx amount = total balance', (done) => {
            const {
                utxos, txTimes, totalAmount,
            } = wallet._getSpendingUTXO(
                toBN(20.2 * GWEI),
                true,
            );

            const txs = wallet._splitTransaction(utxos, txTimes, totalAmount);
            expect(txs.length).to.be.equal(3);

            expect(txs[0].utxos.length).to.be.equal(4);
            expect(txs[0].receivAmount.eq(toBN(9.99 * GWEI))).to.be.equal(true);
            expect(txs[0].remainAmount.eq(toBN(0 * GWEI))).to.be.equal(true);

            expect(txs[1].utxos.length).to.be.equal(4);
            expect(txs[1].receivAmount.eq(toBN(5.09 * GWEI))).to.be.equal(true);
            expect(txs[1].remainAmount.eq(toBN(0 * GWEI))).to.be.equal(true);

            expect(txs[2].utxos.length).to.be.equal(2);
            expect(txs[2].receivAmount.eq(toBN(5.09 * GWEI))).to.be.equal(true);
            expect(txs[2].remainAmount.eq(toBN(0 * GWEI))).to.be.equal(true);
            done();
        });
    });

});
