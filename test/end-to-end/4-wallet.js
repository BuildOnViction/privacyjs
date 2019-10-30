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

    for (let count = 0; count < 5; count++) {
        it('Should get decoys successfully for 5 rings', (done) => {
            wallet.scannedTo = 100;
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

    it('Should get single utxo successfully', (done) => {
        wallet.scannedTo = 100;
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

    // it('Should genCT return correct ring (check on precompiled contract) from wallet', (done) => {
    //     wallet.scannedTo = 0;
    //     const receiver = generateKeys(WALLETS[1].privateKey);
    //     wallet.scan()
    //         .then(() => {
    //             const outputProofs = wallet._genOutputProofs(wallet.utxos, receiver.pubAddr, toBN('100000'));

    //             wallet._genRingCT(wallet.utxos, outputProofs).then((res) => {
    //                 mlsagPrecompiledContract.methods.VerifyRingCT(
    //                     res.signature,
    //                 )
    //                     .send({
    //                         from: SENDER_WALLET.address,
    //                     })
    //                     .then((receipt) => {
    //                         console.log(receipt);
    //                         done();
    //                     })
    //                     .catch((error) => {
    //                         console.log(error);
    //                         done(error);
    //                     });
    //             });
    //         })
    //         .catch((error) => {
    //             console.log(error);
    //             done(error);
    //         });
    // });

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

    it('Should able to create ringCT and output UTXO', (done) => {
        // just lazy don't wanna store privacy address in config, gen it here from private key
        const receiver = generateKeys(WALLETS[1].privateKey);
        try {
            wallet.send(receiver.pubAddr, '100000').then((res) => {
                console.log(res);
                done();
            }).catch((err) => {
                done(err);
            });
        } catch (ex) {
            done(ex);
        }
    });
});
