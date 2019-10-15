import * as _ from 'lodash';
import chai from 'chai';
import TestConfig from '../config.json';
import MLSAG_DATA from './mlsag.json';
import MLSAG, { hashToPoint } from '../../src/mlsag';

import UTXO from '../../src/utxo';

const ecurve = require('ecurve');

const ecparams = ecurve.getCurveByName('secp256k1');
const EC = require('elliptic').ec;

const ec = new EC('secp256k1');

const { expect } = chai;
chai.should();

const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

/**
 * Multilayered linkable spontaneous ad-hoc group signatures test
 * Cover unit test for
 * 1. Hash turn point to point in seccp256k1 ECC
 * 2. MLSAG sign message
 * 3. MLSAG verify signature
 */

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
            const index = 3;
            MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);

            const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));
            const signature = MLSAG.mulSign(
                'aAAAAAAA',
                SENDER_WALLET.privateKey,
                [inputUTXOS],
                index,
            );

            expect(signature.I).not.to.equal(null);
            expect(signature.c1).not.to.equal(null);
            expect(signature.s).not.to.equal(null);

            const verifyInputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));
            expect(
                MLSAG.verifyMul(
                    'aAAAAAAA',
                    [verifyInputUTXOS],
                    signature.I,
                    signature.c1,
                    signature.s,
                ),
            ).to.be.equal(true);
            done();
        });

        it('Should not able to verify signer with different message', (done) => {
            const index = 3;
            MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);

            const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));
            const signature = MLSAG.mulSign(
                'aAAAAAAA',
                SENDER_WALLET.privateKey,
                [inputUTXOS],
                index,
            );

            expect(signature.I).not.to.equal(null);
            expect(signature.c1).not.to.equal(null);
            expect(signature.s).not.to.equal(null);

            const verifyInputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => new UTXO(ut));

            expect(
                MLSAG.verifyMul(
                    'aAAAAAAABBBB',
                    [verifyInputUTXOS],
                    signature.I,
                    signature.c1,
                    signature.s,
                ),
            ).to.be.equal(false);
            done();
        });
    });

    describe('#verify', () => {
        it('Should able to verify an utxo belong to a group', (done) => {
            done(new Error('not implemented yet'));
        });

        it('Should not able to verify an utxo belong to a group', (done) => {
            done(new Error('not implemented yet'));
        });
    });
});
