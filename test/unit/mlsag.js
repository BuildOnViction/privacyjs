import * as _ from 'lodash';
import chai from 'chai';
import Web3 from 'web3';
import TestConfig from '../config.json';
import MLSAG_DATA from './mlsag.json';
import MLSAG, { hashToPoint } from '../../src/mlsag';

import UTXO from '../../src/utxo';
import { BigInteger } from '../../src/crypto';
import { toBN } from '../../src/common';
import Stealth from '../../src/stealth';
import { generateKeys } from '../../src/address';

const ecurve = require('ecurve');

const ecparams = ecurve.getCurveByName('secp256k1');
const EC = require('elliptic').ec;

const ec = new EC('secp256k1');

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[2]; // hold around 1 mil tomo

/**
 * Multilayered linkable spontaneous ad-hoc group signatures test
 * Cover unit test for
 * 1. Hash turn point to point in seccp256k1 ECC
 * 2. MLSAG sign message
 * 3. MLSAG verify signature
 */

// TODO write more test case
describe('#unittest #ringct #mlsag', () => {
    describe('#hashToPoint', () => {
        // because of this randomization, we do this 50 times to make sure
        // it always return new point on hash
        for (let times = 0; times < 5; times++) {
            it('Should turn a hex into a point in seccp256 ECC correctly', (done) => {
                const publicKey = ec.genKeyPair().getPublic().encodeCompressed('hex');
                const newPoint = hashToPoint(publicKey);

                expect(ecparams.isOnCurve(newPoint)).to.be.equal(true);
                done();
            });
        }
    });

    describe('#sign', () => {
        it('Should able to verify signer belong belong to a group', (done) => {
            const sender = new Stealth({
                ...generateKeys(SENDER_WALLET.privateKey),
            });
            const index = 3;
            MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);
            let totalSpending = BigInteger.ZERO;
            const ins = new UTXO(MLSAG_DATA.SPENDING_UTXOS[0]);
            ins.checkOwnership(SENDER_WALLET.privateKey);

            totalSpending = totalSpending.add(
                toBN(ins.decodedAmount),
            );

            const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));

            const signature = MLSAG.mulSign(
                SENDER_WALLET.privateKey,
                [inputUTXOS],
                index,
            );
            expect(signature.I).not.to.equal(null);
            expect(signature.c1).not.to.equal(null);
            expect(signature.s).not.to.equal(null);

            const proof = sender.genTransactionProof(
                Web3.utils.hexToNumberString(totalSpending.toHex()),
            );

            const ctsignature = MLSAG.signCommitment(
                SENDER_WALLET.privateKey,
                [inputUTXOS],
                [{
                    lfCommitment: ecurve.Point.decodeFrom(ecparams, proof.commitment),
                    decodedMask: proof.mask,
                }],
                index,
            );
            expect(ctsignature.I).not.to.equal(null);
            expect(ctsignature.c1).not.to.equal(null);
            expect(ctsignature.s).not.to.equal(null);

            const verifyInputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));
            expect(
                MLSAG.verifyMul(
                    [verifyInputUTXOS],
                    signature.I,
                    signature.c1,
                    signature.s,
                ),
            ).to.be.equal(true);

            expect(
                MLSAG.verifyCommitment(
                    ctsignature.publicKeys,
                    ctsignature.I,
                    ctsignature.c1,
                    ctsignature.s,
                ),
            ).to.be.equal(true);

            done();
        });

        it('Should not spend more than total balance', (done) => {
            done(new Error('Not impelemented yet'));
        });

        it('Should able to verify with ringsize = 3', (done) => {
            const index = 3;
            MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);

            const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));

            const signature = MLSAG.mulSign(
                SENDER_WALLET.privateKey,
                [inputUTXOS, inputUTXOS, inputUTXOS],
                index,
            );

            expect(signature.I).not.to.equal(null);
            expect(signature.c1).not.to.equal(null);
            expect(signature.s).not.to.equal(null);

            const verifyInputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));
            expect(
                MLSAG.verifyMul(
                    [verifyInputUTXOS],
                    signature.I,
                    signature.c1,
                    signature.s,
                ),
            ).to.be.equal(true);
            done();
        });

        it('Should not sign for index not in range [0, ring.size]', (done) => {
            done(new Error('Not impelemented yet'));
        });

        it('Should able to sign for index  in [0, ring.size]', (done) => {
            done(new Error('Not impelemented yet'));
        });

        //     it('Should not able to verify signer with different message', (done) => {
        //         const index = 3;
        //         MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);

        //         const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));
        //         const signature = MLSAG.mulSign(
        //             SENDER_WALLET.privateKey,
        //             [inputUTXOS],
        //             index,
        //         );

        //         expect(signature.I).not.to.equal(null);
        //         expect(signature.c1).not.to.equal(null);
        //         expect(signature.s).not.to.equal(null);

        //         const verifyInputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));

    //         expect(
    //             MLSAG.verifyMul(
    //                 [verifyInputUTXOS],
    //                 signature.I,
    //                 signature.c1,
    //                 signature.s,
    //             ),
    //         ).to.be.equal(false);
    //         done();
    //     });
    });

});
