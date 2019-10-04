import TestConfig from '../config.json';
import Stealth from '../../src/stealth';
import Address from '../../src/address';
import {hashToPoint} from '../../src/mlsag';

const ecurve = require('ecurve');
const ecparams = ecurve.getCurveByName('secp256k1');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');

import chai from 'chai';

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
 * 1. Hash turn point to point in keccak256k1 ECC
 * 2. MLSAG sign message
 * 3. MLSAG verify signature 
 */

describe('#unittest #ringct #mlsag', function () {
    describe('#hashToPoint', function () {
        // because of this randomization, we do this 50 times to make sure
        // it always return new point on hash
        for (let times = 0; times < 50; times ++){
            it("Should turn a hex into a point in keccak256 ECC correctly", function (done) {
                const publicKey = ec.genKeyPair().getPublic().encodeCompressed('hex');
                const newPoint = hashToPoint(publicKey);

                expect(ecparams.isOnCurve(newPoint)).to.be.equal(true);
                done();
            })
        }
    });

    describe('#sign', function () {
        it("Should able to verify an utxo belong to a group", function (done) {
            done(new Error("not implemented yet"));
        });

        it("Should not able to verify an utxo belong to a group", function (done) {
            done(new Error("not implemented yet"));
        });
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

