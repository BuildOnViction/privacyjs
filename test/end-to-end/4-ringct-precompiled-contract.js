/* eslint-disable max-len */
// eslint-disable-next-line max-len
/**
 * End To End tests using tomochain testnet deployed smart-contract,
 * change config in ./test/config.json ./test/config.json
 */
import Web3 from 'web3';
import chai from 'chai';
import assert from 'assert';
import HDWalletProvider from 'truffle-hdwallet-provider';
import numberToBN from 'number-to-bn';
import * as _ from 'lodash';
import TestConfig from '../config.json';
import * as TestUtils from '../utils';
import MLSAG from '../../src/mlsag';
import UTXO from '../../src/utxo.js';
import RINGCT_DATA from './ringct.json';

const BN = require('bn.js');

const { expect } = chai;
chai.should();

const { RINGCT_PRECOMPILED_CONTRACT, WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

const TOMO = 1000000000000000000;

// load single private key as string
const provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

const privacyContract = new web3.eth.Contract(
    RINGCT_PRECOMPILED_CONTRACT.ABI, RINGCT_PRECOMPILED_CONTRACT.ADDRESS, {
        from: SENDER_WALLET.address, // default from address
        gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
        gas: '2000000',
    },
);

describe('#ringct #verify', () => {
    it('Successful create single ring-signature', (done) => {
        // TestUtils.depositNTimes(12, TOMO).then((utxos) => {
        //     const index = 3;
        const pubkeys = [[]];
        //     const signature = MLSAG.mulSign(
        //         '',
        //         SENDER_WALLET.privateKey,
        //         [utxos.slice(0, 1)],
        //         index,
        //     );

        //     expect(signature.I).not.to.equal(null);
        //     expect(signature.c1).not.to.equal(null);
        //     expect(signature.s).not.to.equal(null);

        //     console.log(
        //         numberToBN(1).toString(16, 16)
        //             + numberToBN(12).toString(16, 16)
        //             + numberToBN(1000).toString(16, 64)
        //             + signature.c1.toString(16, 64)
        //             + _.map(_.flatten(signature.s), element => element.toString(16, 64)).join('')
        //             + _.map(_.flatten(pubkeys), pubkey => new BN(
        //                 pubkey.getEncoded(true).toString('hex'), 16,
        //             ).toString(16, 64)).join('')
        //             + _.map(_.flatten(signature.I), element => element.toString(16, 64)).join(''),
        //     );
        const index = 3;
        RINGCT_DATA.NOISING_UTXOS.splice(index, 0, RINGCT_DATA.SPENDING_UTXOS[0]);

        const inputUTXOS = _.map(RINGCT_DATA.NOISING_UTXOS, (ut) => {
            const utxo = new UTXO(ut);
            pubkeys[0].push(
                utxo.lfStealth,
            );
            return utxo;
        });

        const signature = MLSAG.mulSign(
            SENDER_WALLET.privateKey,
            [inputUTXOS, inputUTXOS, inputUTXOS],
            index,
        );

        const sendingBytes = `${numberToBN(1).toString(16, 16)
        }${numberToBN(12).toString(16, 16)
        }${numberToBN(0).toString(16, 64)
        }${signature.c1.toHex(32)
        }${_.map(_.flatten(signature.s), element => element.toHex(32)).join('')
        }${_.map(_.flatten(pubkeys), pubkey => pubkey.getEncoded(true).toString('hex')).join('')
        }${_.map(_.flatten(signature.I), element => element.getEncoded(true).toString('hex')).join('')}`;

        assert(sendingBytes.length === (16 + 16 + 64 + 64 + 12 * 64 + 66 * 12 + 66), 'Wrong calculation bytes');

        expect(signature.I).not.to.equal(null);
        expect(signature.c1).not.to.equal(null);
        expect(signature.s).not.to.equal(null);

        // self verify
        expect(
            MLSAG.verifyMul(
                [inputUTXOS, inputUTXOS, inputUTXOS],
                signature.I,
                signature.c1,
                signature.s,
            ),
        ).to.be.equal(true);

        console.log(sendingBytes);

        // verify on Smart-contract
        privacyContract.methods.VerifyRingCT(
            Buffer.from(sendingBytes, 'hex'),
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
        // });
    });

    it('Successful create single commitment-ring', (done) => {
        const pubkeys = [[]];
        const index = 3;
        RINGCT_DATA.NOISING_UTXOS.splice(index, 0, RINGCT_DATA.SPENDING_UTXOS[0]);

        const inputUTXOS = _.map(RINGCT_DATA.NOISING_UTXOS, (ut) => {
            const utxo = new UTXO(ut);
            pubkeys[0].push(
                utxo.lfStealth,
            );
            return utxo;
        });

        const signature = MLSAG.signCommitment(
            SENDER_WALLET.privateKey,
            [inputUTXOS],
            index,
        );

        const sendingBytes = `${numberToBN(1).toString(16, 16)
        }${numberToBN(12).toString(16, 16)
        }${numberToBN(0).toString(16, 64)
        }${signature.c1.toHex(32)
        }${_.map(_.flatten(signature.s), element => element.toHex(32)).join('')
        }${_.map(_.flatten(pubkeys), pubkey => pubkey.getEncoded(true).toString('hex')).join('')
        }${_.map(_.flatten(signature.I), element => element.getEncoded(true).toString('hex')).join('')}`;

        assert(sendingBytes.length === (16 + 16 + 64 + 64 + 12 * 64 + 66 * 12 + 66), 'Wrong calculation bytes');

        expect(signature.I).not.to.equal(null);
        expect(signature.c1).not.to.equal(null);
        expect(signature.s).not.to.equal(null);

        // self verify
        expect(
            MLSAG.verifyMul(
                [inputUTXOS],
                signature.I,
                signature.c1,
                signature.s,
            ),
        ).to.be.equal(true);

        // verify on Smart-contract
        privacyContract.methods.VerifyRingCT(
            Buffer.from(sendingBytes, 'hex'),
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
        // });
    });

    it('Should not accept message != concat(pubkey)', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Successful create 5 rings', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Successful create 10 rings', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Unsuccessful validate a ring', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Successful create 1 ring ct', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Should reject tx with commitment from negative value', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Should reject utxo with used-ring', (done) => {
        done(new Error('Not implemented yet'));
    });

    it('Should reject spent utxo', (done) => {
        done(new Error('Not implemented yet'));
    });

    // this case just effect cost of transaction
    it('Should reject ring size > 12', (done) => {
        done(new Error('Not implemented yet'));
    });
});
