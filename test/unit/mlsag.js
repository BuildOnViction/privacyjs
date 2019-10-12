import * as _ from 'lodash';
import TestConfig from '../config.json';
import MLSAG_DATA from './mlsag.json';
import Stealth from '../../src/stealth';
import * as Address from '../../src/address';
import MLSAG, {hashToPoint} from '../../src/mlsag';

const ecurve = require('ecurve');
const ecparams = ecurve.getCurveByName('secp256k1');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');

import chai from 'chai';
import UTXO from '../../src/utxo.js';

const expect = chai.expect;
chai.should();

const WALLETS = TestConfig.WALLETS;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

const TOMO = 1000000000000000000;
const sender = new Stealth({
    ...Address.generateKeys(SENDER_WALLET.privateKey)
});

/**
 * Multilayered linkable spontaneous ad-hoc group signatures test
 * Cover unit test for
 * 1. Hash turn point to point in seccp256k1 ECC
 * 2. MLSAG sign message
 * 3. MLSAG verify signature 
 */

describe('#unittest #ringct #mlsag', function () {
    describe('#hashToPoint', function () {
        // because of this randomization, we do this 50 times to make sure
        // it always return new point on hash
        for (let times = 0; times < 5; times ++){
            it("Should turn a hex into a point in seccp256 ECC correctly", function (done) {
                const publicKey = ec.genKeyPair().getPublic().encodeCompressed('hex');
                const newPoint = hashToPoint(publicKey);

                expect(ecparams.isOnCurve(newPoint)).to.be.equal(true);
                done();
            })
        }
    });

    describe('#sign', function () {
        it("Should able to verify an utxo belong to a group", function (done) {
            const index = 3;
            MLSAG_DATA.NOISING_UTXOS[0].splice(index, 0, MLSAG_DATA.SPENDING_UTXOS[0]);
            
            const inputUTXOS = _.map(MLSAG_DATA.NOISING_UTXOS[0], ut => {
                return new UTXO(ut);
            });
            const signature = MLSAG.sign(SENDER_WALLET.privateKey, inputUTXOS, index, WALLETS[1].address);

            expect(signature.I).not.to.equal(null);
            expect(signature.ci_zero).not.to.equal(null);
            expect(signature.si).not.to.equal(null);
            done();
        });

        // it("Should not able to verify an utxo belong to a group", function (done) {
        //     done(new Error("not implemented yet"));
        // });
    });

    describe('#verify', function () {
        it("Should able to verify an utxo belong to a group", function (done) {
            done(new Error("not implemented yet"));
        });

        it("Should not able to verify an utxo belong to a group", function (done) {
            done(new Error("not implemented yet"));
        });
    });
})

