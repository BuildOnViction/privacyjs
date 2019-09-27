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

        /**
         * generate 3 proofs for 3 deposit transaction - 1 tomo each time
         * use private send to create 2 input tx
         * one with 2.5 tomo for receiver, one 0.5 for myself
         * We have to make sure sum input = some output
         */
        for(let times = 0; times < 1; times++) {
            it("Should input commitments = output commitments in private send", function (done) {
                let generatedCommitments = [];
    
                // create 3 proofs for depositting 3 tomos
                // we count sum of spending masks also
                let sumOfSpendingMasks = new BN('0', 16);
                for (let txId = 0; txId < 3; txId++) {
                    let proof = sender.genTransactionProof(TOMO, sender.pubSpendKey, sender.pubViewKey);
                    sumOfSpendingMasks.add(new BN(proof.mask, 16));
                    generatedCommitments.push(proof.commitment);
                    console.log(proof.commitment.toString('hex'));
                }
    
                // private send - create 2 proofs from 3 above transactions
                // 1 - 2.5 tomo for other
                // 2 - remain 0.5 for myself
                const proofOfReceiver = sender.genTransactionProof(2.5*TOMO, receiver.pubSpendKey, receiver.pubViewKey);
    
                const myRemainMask = sumOfSpendingMasks.sub(new BN(proofOfReceiver.mask, 16)).toString(16);
    
                let proofOfMe = sender.genTransactionProof(0.5*TOMO, sender.pubSpendKey, sender.pubViewKey, myRemainMask);
    
                let inputCommitments = Commitment.sumCommitments(generatedCommitments);
                let outputCommitments = Point.decodeFrom(ecparams, proofOfReceiver.commitment).add(
                    Point.decodeFrom(ecparams, proofOfMe.commitment)
                );

                expect(inputCommitments.getEncoded(true).toString('hex')).to.equal(outputCommitments.getEncoded(true).toString('hex'));
                done();
            })
        }
    
        it("Should split comitments correctly in private send", function (done) {
            done();
        })
    
    })
})

