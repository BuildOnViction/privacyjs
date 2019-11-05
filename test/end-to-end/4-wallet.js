/* eslint-disable no-loop-func */
import chai from 'chai';
import Web3 from 'web3';
import HDWalletProvider from 'truffle-hdwallet-provider';
import * as _ from 'lodash';
import numberToBN from 'number-to-bn';
import TestConfig from '../config.json';
import Wallet from '../../src/wallet';
import { generateKeys } from '../../src/address';
import Stealth from '../../src/stealth';
import { toBN } from '../../src/common';
import MLSAG from '../../src/mlsag';
import UTXO from '../../src/utxo';
import MLSAG_DATA from '../unit/mlsag.json';
import { BigInteger } from '../../src/crypto';

const ecurve = require('ecurve');

const ecparams = ecurve.getCurveByName('secp256k1');
const { expect } = chai;
chai.should();

const { RINGCT_PRECOMPILED_CONTRACT, WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

// load single private key as string
const provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

const mlsagPrecompiledContract = new web3.eth.Contract(
    RINGCT_PRECOMPILED_CONTRACT.ABI, RINGCT_PRECOMPILED_CONTRACT.ADDRESS, {
        from: SENDER_WALLET.address, // default from address
        gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
        gas: '2000000',
    },
);

/* eslint-disable max-len */
// eslint-disable-next-line max-len
/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */

describe('#wallet #ete', () => {
    let wallet: Wallet;

    beforeEach((done) => {
        wallet = new Wallet(WALLETS[0].privateKey, {
            RPC_END_POINT: TestConfig.RPC_END_POINT,
            ABI: TestConfig.PRIVACY_ABI,
            ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
        }, WALLETS[0].address);
        done();
    });

    describe('#decoys', () => {
        for (let count = 0; count < 5; count++) {
            it('Should get decoys successfully for 5 rings', (done) => {
                wallet.scannedTo = 40;
                wallet._getDecoys(5, [1, 5]).then((res) => {
                    expect(res.length).to.equal(5);
                    expect(res[0].length).to.equal(11);
                    expect(res[1].length).to.equal(11);
                    // expect(typeof res[0][0]).to.equal('UTXO');

                    const randomElement = res[
                        Math.round(Math.random() * 1)
                    ][
                        Math.round(Math.random() * 10)
                    ];
                    expect(randomElement).has.property('lfCommitment');
                    expect(randomElement).has.property('index');
                    expect(randomElement).has.property('lfStealth');
                    done();
                }).catch((err) => {
                    done(err);
                });
            });
        }
    });

    describe('#getUTXO', () => {
        it('Should get single utxo successfully', (done) => {
            wallet.scannedTo = 40;
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

    describe('#MLSAG', () => {
        it('Should genCT return correct ring (check on precompiled contract) from mlsag', (done) => {
            const sender = new Stealth({
                ...generateKeys(WALLETS[2].privateKey),
            });
            const index = 3;

            MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);

            let totalSpending = BigInteger.ZERO;
            const ins = new UTXO(MLSAG_DATA.SPENDING_UTXOS[0]);
            ins.checkOwnership(WALLETS[2].privateKey);

            totalSpending = totalSpending.add(
                toBN(ins.decodedAmount),
            );
            const proof = sender.genTransactionProof(
                Web3.utils.hexToNumberString(totalSpending.toHex()),
            );

            const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));

            // ct ring
            const {
                privKey,
                publicKeys,
            } = MLSAG.genCTRing(
                WALLETS[2].privateKey,
                [inputUTXOS],
                [{
                    lfCommitment: ecurve.Point.decodeFrom(ecparams, proof.commitment),
                    decodedMask: proof.mask,
                }],
                index,
            );

            // ring-signature of utxos
            const signature = MLSAG.mulSign(
                [
                    BigInteger.fromHex(ins.privKey), privKey],
                [_.map(inputUTXOS, utxo => utxo.lfStealth), publicKeys],
                index,
            );
            expect(signature.I).not.to.equal(null);
            expect(signature.c1).not.to.equal(null);
            expect(signature.s).not.to.equal(null);


            expect(
                MLSAG.verifyMul(
                    [_.map(inputUTXOS, utxo => utxo.lfStealth), publicKeys],
                    signature.I,
                    signature.c1,
                    signature.s,
                ),
            ).to.be.equal(true);

            mlsagPrecompiledContract.methods.VerifyRingCT(
                Buffer.from(
                    `${numberToBN(1 + 1).toString(16, 16)
                    }${numberToBN(MLSAG_DATA.NOISING_UTXOS[0].length).toString(16, 16)
                    }${signature.message.toString('hex')
                    }${signature.c1.toHex(32)
                    }${_.map(_.flatten(signature.s), element => element.toHex(32)).join('')
                    }${_.map(_.flatten([_.map(inputUTXOS, utxo => utxo.lfStealth), publicKeys]), pubkey => pubkey.getEncoded(true).toString('hex')).join('')
                    }${_.map(_.flatten(signature.I), element => element.getEncoded(true).toString('hex')).join('')}`,
                    'hex',
                ),
            )
                .send({
                    from: SENDER_WALLET.address,
                })
                .then((receipt) => {
                    console.log(receipt);
                    done();
                })
                .catch((error) => {
                    console.log(error);
                    done(error);
                });

        });
    });

    describe('#send', () => {
        const sendWallet = new Wallet(WALLETS[0].privateKey, {
            RPC_END_POINT: TestConfig.RPC_END_POINT,
            ABI: TestConfig.PRIVACY_ABI,
            ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
        }, WALLETS[0].address);
        it('Should able to create ringCT and output UTXO with spendingIndex from 0 to 5', (done) => {
            // just lazy don't wanna store privacy address in config, gen it here from private key
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                sendWallet.send(receiver.pubAddr, '100000').then((txs) => {
                    _.each(txs, (NewUTXO) => {
                        expect(NewUTXO).to.not.equal(undefined);
                        expect(NewUTXO.length).to.equal(2); // always create two
                        const returnUTXOs = NewUTXO.map(utxo => utxo.returnValues);

                        // make sure at least one utxo belonging to receiver, one for sender
                        // and encrypted amount correct
                        const senderUTXOIns = new UTXO(returnUTXOs[0]);
                        const receiverUTXOIns = new UTXO(returnUTXOs[1]);

                        const decodedSenderUTXO = senderUTXOIns.checkOwnership(WALLETS[0].privateKey);
                        const decodedReceiverUTXO = receiverUTXOIns.checkOwnership(
                            WALLETS[1].privateKey,
                        );

                        expect(senderUTXOIns.checkOwnership(WALLETS[0].privateKey)).to.not.equal(null);
                        expect(receiverUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);

                        expect(decodedSenderUTXO).to.not.be.equal(null);
                        expect(decodedReceiverUTXO).to.not.be.equal(null);

                        // expect(decodedSenderUTXO.amount === (2.5 * TOMO).toString()).to.be.equal(true);
                        // expect(decodedReceiverUTXO.amount === '100000').to.be.equal(true);
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

        it('Should able to send with needed utxos > ring_number', (done) => {
            // just lazy don't wanna store privacy address in config, gen it here from private key
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                console.log(sendWallet.balance.toHex());
                sendWallet.send(receiver.pubAddr, '6000000000000000000').then((txs) => {
                    _.each(txs, (NewUTXO) => {
                        expect(NewUTXO).to.not.equal(undefined);
                        expect(NewUTXO.length).to.equal(2); // always create two
                        const returnUTXOs = NewUTXO.map(utxo => utxo.returnValues);

                        // make sure at least one utxo belonging to receiver, one for sender
                        // and encrypted amount correct
                        const senderUTXOIns = new UTXO(returnUTXOs[0]);
                        const receiverUTXOIns = new UTXO(returnUTXOs[1]);

                        const decodedSenderUTXO = senderUTXOIns.checkOwnership(WALLETS[0].privateKey);
                        const decodedReceiverUTXO = receiverUTXOIns.checkOwnership(
                            WALLETS[1].privateKey,
                        );

                        expect(senderUTXOIns.checkOwnership(WALLETS[0].privateKey)).to.not.equal(null);
                        expect(receiverUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);

                        expect(decodedSenderUTXO).to.not.be.equal(null);
                        expect(decodedReceiverUTXO).to.not.be.equal(null);

                        // expect(decodedSenderUTXO.amount === (2.5 * TOMO).toString()).to.be.equal(true);
                        // expect(decodedReceiverUTXO.amount === '100000').to.be.equal(true);
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
            // just lazy don't wanna store privacy address in config, gen it here from private key
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                console.log(sendWallet.balance.toHex());
                sendWallet.send(receiver.pubAddr, '1000000000000000000').then(() => {
                    done(new Error(''));
                }).catch((err) => {
                    console.log('err ', err);
                    done(err);
                });
            } catch (ex) {
                done(ex);
            }
        });

        it('Should not able to send with negative money commitment', (done) => {
            // just lazy don't wanna store privacy address in config, gen it here from private key
            const receiver = generateKeys(WALLETS[1].privateKey);
            try {
                console.log(sendWallet.balance.toHex());
                sendWallet.send(receiver.pubAddr, '100000000000000').then((txs) => {
                    _.each(txs, (NewUTXO) => {
                        expect(NewUTXO).to.not.equal(undefined);
                        expect(NewUTXO.length).to.equal(2); // always create two
                        const returnUTXOs = NewUTXO.map(utxo => utxo.returnValues);

                        // make sure at least one utxo belonging to receiver, one for sender
                        // and encrypted amount correct
                        const senderUTXOIns = new UTXO(returnUTXOs[0]);
                        const receiverUTXOIns = new UTXO(returnUTXOs[1]);

                        const decodedSenderUTXO = senderUTXOIns.checkOwnership(WALLETS[0].privateKey);
                        const decodedReceiverUTXO = receiverUTXOIns.checkOwnership(
                            WALLETS[1].privateKey,
                        );

                        expect(senderUTXOIns.checkOwnership(WALLETS[0].privateKey)).to.not.equal(null);
                        expect(receiverUTXOIns.checkOwnership(WALLETS[1].privateKey)).to.not.equal(null);

                        expect(decodedSenderUTXO).to.not.be.equal(null);
                        expect(decodedReceiverUTXO).to.not.be.equal(null);

                        // expect(decodedSenderUTXO.amount === (2.5 * TOMO).toString()).to.be.equal(true);
                        // expect(decodedReceiverUTXO.amount === '100000').to.be.equal(true);
                    });
                    done();
                }).catch((err) => {
                    done(err);
                });
            } catch (ex) {
                done(ex);
            }
        });
    });

});
