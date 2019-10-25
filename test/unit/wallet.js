import sinon from 'sinon';
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import ecurve from 'ecurve';
import Wallet from '../../src/wallet';
import Configs from '../config.json';
import * as CONSTANT from '../../src/constants';
// import UTXO from '../../src/utxo';
import { BigInteger } from '../../src/crypto';

const ecparams = ecurve.getCurveByName('secp256k1');
const { Point } = ecurve;
const { expect } = chai;
chai.should();
chai.use(chaiAsPromised);

const { WALLETS } = Configs;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

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
                gas: '2000000',
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
                gas: '2000000',
            }, SENDER_WALLET.address);

            wallet1 = new Wallet(WALLETS[1].privateKey, {
                RPC_END_POINT: Configs.RPC_END_POINT,
                ABI: Configs.PRIVACY_ABI,
                ADDRESS: Configs.PRIVACY_SMART_CONTRACT_ADDRESS,
                gasPrice: '250000000',
                gas: '2000000',
            }, SENDER_WALLET.address);

            proof = wallet._genUTXOProof(1000000000);
            stealthPoint = Point.fromAffine(ecparams,
                new BigInteger(proof[0].slice(2), 16),
                new BigInteger(proof[1].slice(2), 16));
            txPubkeyPoint = Point.fromAffine(ecparams,
                new BigInteger(proof[2].slice(2), 16),
                new BigInteger(proof[3].slice(2), 16));

            done();
        });

        afterEach((done) => {
            // wallet.privacyContract.methods = originalDeposit;
            // sinon.replace(wallet.privacyContract.methods, 'deposit', originalDeposit);
            done();
        });

        it('should able to create a belonging utxo', (done) => {
            decodedProof = wallet.isMine(
                txPubkeyPoint.getEncoded(false), stealthPoint.getEncoded(false), proof[5].slice(2),
            );
            expect(decodedProof).to.not.equal(null);
            expect(decodedProof.amount).to.be.equal('1000000000');

            done();
        });

        it('should not able to decoded wallet\'s proof ', (done) => {
            // make sure other can't decode
            decodedProof = wallet1.isMine(
                txPubkeyPoint.getEncoded(false), stealthPoint.getEncoded(false), proof[5].slice(2),
            );
            expect(decodedProof).to.equal(null);

            done();
        });

        // in this case sc just just your input is on curve and you have enough money to spend, nothing else
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
                                    events: { NewTX: { returnValues: { UTXO: {}, timestamp: new Date() } } },
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

    describe('#withdraw()', () => {
        it('should able to withdraw', (done) => {
            done(new Error('Not implemented yet'));
        });
    });

    describe('#send()', () => {
        it('should able to create correct output utxos', (done) => {
            done(new Error('Not implemented yet'));
        });

        it('should able to create correct ringct', (done) => {
            done(new Error('Not implemented yet'));
        });

        it('should able to create correct bullet proof', (done) => {
            done(new Error('Not implemented yet'));
        });

        it('should call to sc correctly to send and receive exactly same output utxos', (done) => {
            done(new Error('Not implemented yet'));
        });

        it('should not create single ring', (done) => {
            done(new Error('Not implemented yet'));
        });

        it('should not create proof with ringsize > 5', (done) => {
            done(new Error('Not implemented yet'));
        });

        it('should not execute-time > 10s ', (done) => {
            done(new Error('Not implemented yet'));
        });

        it('should emit event correctly in sending progress', (done) => {
            done(new Error('Not implemented yet'));
        });
    });
});
