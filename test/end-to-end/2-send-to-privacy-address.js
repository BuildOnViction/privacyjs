/**
 * End To End tests using tomochain testnet deployed smart-contract, change config in ./test/config.json ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import { toBN, isBN, numberToHex } from '../../src/common';
import Address from '../../src/address';
import Commitment from '../../src/commitment';
import Stealth from '../../src/stealth';
import TestUtils from '../utils';
import HDWalletProvider from "truffle-hdwallet-provider";
import * as _ from 'lodash';
import BN from 'bn.js';
import { scanUTXOs } from '../utils';
var BigInteger = require('bigi')
import UTXO from '../../src/utxo';

const ecurve = require('ecurve');
const ecparams = ecurve.getCurveByName('secp256k1');
const { Point } = ecurve;

var EC = require('elliptic').ec;
var ec = new EC('secp256k1');

const expect = chai.expect;
chai.should();

const WALLETS = TestConfig.WALLETS;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo
const RECEIVER_WALLET = WALLETS[1]; // hold around 1 mil tomo

const PEDERSON_COMMITMENT_H = [
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
    '31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904',
];

const basePointH = new Point.fromAffine(ecparams,
    new BigInteger(PEDERSON_COMMITMENT_H[0], 16),
    new BigInteger(PEDERSON_COMMITMENT_H[1], 16));

//load single private key as string
let provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

var privacyContract = new web3.eth.Contract(TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
    from: SENDER_WALLET.address, // default from address
    gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
    gas: '1000000'
});

const TOMO = 1000000000000000000;

var receiverBalance = 0;
var receiverUtxos = [];

const runtest = function(done) {
    let sender = new Stealth({
        ...Address.generateKeys(SENDER_WALLET.privateKey)
    });

    let receiver = new Stealth({
        ...Address.generateKeys(RECEIVER_WALLET.privateKey)
    });

    // create 3 utxos, let this test independents to deposit test
    TestUtils.depositNTimes(3, TOMO).then((utxos) => {
        let sumOfSpendingMasks = BigInteger.fromHex('0');
        let UTXOs = [];
        let generatedCommitments = [];
        const spendingUtxosIndex = _.map(utxos, result => {
            generatedCommitments.push(result.proof.commitment);
            sumOfSpendingMasks = sumOfSpendingMasks.add(BigInteger.fromHex(result.proof.mask)).mod(ecparams.p);
            UTXOs.push(new UTXO(result.utxo));
            return result.utxo._index
        });

        let randomMask = ec.genKeyPair().getPrivate('hex');
        const proofOfReceiver = sender.genTransactionProof(0.5 * TOMO, receiver.pubSpendKey, receiver.pubViewKey, randomMask);

        const myRemainMask = ecparams.p
            .add(ecparams.p)
            .subtract(BigInteger.fromHex(proofOfReceiver.mask).mod(ecparams.p))
            .subtract(sumOfSpendingMasks)
            .toHex();

        let proofOfMe = sender.genTransactionProof(2.5 * TOMO, sender.pubSpendKey, sender.pubViewKey, myRemainMask);

        // sum up commitment to make sure input utxo commitments = output utxos commitment
        let inputCommitments = Commitment.sumCommitmentsFromUTXOs(UTXOs, SENDER_WALLET.privateKey);
        let expectedCommitments = Commitment.sumCommitments(generatedCommitments);
        // let outputCommitments = Point.decodeFrom(ecparams, proofOfMe.commitment)
        //     .add(
        //         Point.decodeFrom(ecparams, proofOfReceiver.commitment)
        //     );

        expect(inputCommitments.getEncoded(true).toString('hex')).to.equal(expectedCommitments.getEncoded(true).toString('hex'));
        // expect(inputCommitments.getEncoded(true).toString('hex')).to.equal(outputCommitments.getEncoded(true).toString('hex'));
        const pfm = inputCommitments.add(
            Point.decodeFrom(ecparams, proofOfReceiver.commitment).negate()
        ).getEncoded(false);
        
        console.log('steal of me ', Point.decodeFrom(ecparams, proofOfMe.onetimeAddress).getEncoded(true).toString('hex'));
        console.log('steal of receiver ', Point.decodeFrom(ecparams, proofOfReceiver.onetimeAddress).getEncoded(true).toString('hex'));

        console.log('txPublicKey of me ', Point.decodeFrom(ecparams, proofOfMe.txPublicKey).getEncoded(true).toString('hex'));
        console.log('txPublicKey of receiver ', Point.decodeFrom(ecparams, proofOfReceiver.txPublicKey).getEncoded(true).toString('hex'));

        privacyContract.methods.privateSend(
            spendingUtxosIndex,
            [
                '0x' + pfm.toString('hex').substr(2, 64), // the X part of curve 
                '0x' + pfm.toString('hex').substr(-64), // the Y part of curve
                '0x' + proofOfReceiver.commitment.toString('hex').substr(2, 64), // the X part of curve 
                '0x' + proofOfReceiver.commitment.toString('hex').substr(-64), // the Y part of curve
                '0x' + proofOfMe.onetimeAddress.toString('hex').substr(2, 64), // the X part of curve 
                '0x' + proofOfMe.onetimeAddress.toString('hex').substr(-64), // the Y part of curve
                '0x' + proofOfReceiver.onetimeAddress.toString('hex').substr(2, 64), // the X part of curve 
                '0x' + proofOfReceiver.onetimeAddress.toString('hex').substr(-64), // the Y part of curve
                '0x' + proofOfMe.txPublicKey.toString('hex').substr(2, 64), // the X part of curve 
                '0x' + proofOfMe.txPublicKey.toString('hex').substr(-64), // the Y part of curve
                '0x' + proofOfReceiver.txPublicKey.toString('hex').substr(2, 64), // the X part of curve 
                '0x' + proofOfReceiver.txPublicKey.toString('hex').substr(-64), // the Y part of curve
            ],
            [
                '0x' + proofOfMe.encryptedAmount, // encrypt of amount using ECDH],
                '0x' + proofOfReceiver.encryptedAmount, // encrypt of amount using ECDH],
                '0x' + proofOfMe.encryptedMask, // encrypt of amount using ECDH],
                '0x' + proofOfReceiver.encryptedMask,// encrypt of amount using ECDH],
            ]
        )
            .send({
                from: SENDER_WALLET.address // in real case, generate an dynamic accont to put here
            })
            .then(function (receipt) {
                const returnUTXOs = receipt.events.NewUTXO.map(utxo => {
                    // console.log("utxo ", utxo);
                    return utxo.returnValues;
                });
                console.log("-----------------------------");
                console.log(returnUTXOs);
                console.log("-----------------------------");

                // make sure at least one utxo belonging to receiver, one for sender
                // and encrypted amount correct
                const senderUTXOIns = new UTXO(returnUTXOs[0]);
                const receiverUTXOIns = new UTXO(returnUTXOs[1]);

                var decodedSenderUTXO = senderUTXOIns.checkOwnership(SENDER_WALLET.privateKey);
                var decodedReceiverUTXO = receiverUTXOIns.checkOwnership(RECEIVER_WALLET.privateKey);
                
                console.log("senderUTXOIns.checkOwnership(RECEIVER_WALLET.privateKey) ", senderUTXOIns.checkOwnership(RECEIVER_WALLET.privateKey));
                console.log("receiverUTXOIns.checkOwnership(SENDER_WALLET.privateKey) ", receiverUTXOIns.checkOwnership(SENDER_WALLET.privateKey));

                console.log("senderUTXOIns.checkOwnership(SENDER_WALLET.privateKey) ", decodedSenderUTXO);
                console.log("receiverUTXOIns.checkOwnership(RECEIVER_WALLET.privateKey) ", decodedReceiverUTXO);

                expect(senderUTXOIns.checkOwnership(RECEIVER_WALLET.privateKey)).to.be.equal(null);
                expect(receiverUTXOIns.checkOwnership(SENDER_WALLET.privateKey)).to.be.equal(null);

                expect(decodedSenderUTXO).to.not.be.equal(null);
                expect(decodedReceiverUTXO).to.not.be.equal(null);

                expect(decodedSenderUTXO.amount === (2.5 * TOMO).toString()).to.be.equal(true);
                expect(decodedReceiverUTXO.amount === (0.5 * TOMO).toString()).to.be.equal(true);

                done() ;
            })
            .catch(function (error) {
                done(error);
            });
    })
        .catch(function (err) {
            done(err);
        });
}

describe('privatesend', () => {
    before(function(done) {
        // scanUTXOs().then((ret) => {
        //     receiverBalance = ret.balance;
        //     receiverUtxos = ret.utxos;
        //     done();
        // }).catch(ex => {
        //     done(ex);
        // })
        done();
    });

    for (var count = 0; count < 10; count++) {
        it('Successful send to privacy account - spend 3, 2 news utxo', (done) => {
            runtest(done);
        });
    }
});
