import TestConfig from '../config.json';
import Stealth from '../../src/stealth';
import Address from '../../src/address';
import Commitment from '../../src/commitment';
import BN from 'bn.js';
import chai from 'chai';

const expect = chai.expect;
chai.should();

const common = require('../../src/common');
const ecurve = require('ecurve');
const ecparams = ecurve.getCurveByName('secp256k1');
const { Point } = ecurve;

const WALLETS = TestConfig.WALLETS;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo
const RECEIVER_WALLET = WALLETS[1];

const TOMO = 1000000000000000000;
const sender = new Stealth({
    ...Address.generateKeys(SENDER_WALLET.privateKey)
})
const receiver = new Stealth({
    ...Address.generateKeys(RECEIVER_WALLET.privateKey)
});

describe('#unittest #commitment', function () {
    describe('#sumCommitments', function () {

        it("Should generateCommitment correctly", function (done) {
            let proof = sender.genTransactionProof(TOMO, sender.pubSpendKey, sender.pubViewKey);
            let regeneratedCommitment = Commitment.genCommitment(TOMO, proof.mask, false);
            expect(proof.commitment.toString('hex')).to.equal(regeneratedCommitment.toString('hex'));
            done();
        })

        it("Should split comitments correctly in private send", function (done) {
            done(new Error("not implemented yet"));
        })
    
    })
})

