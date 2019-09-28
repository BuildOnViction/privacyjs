/**
 * End To End tests using tomochain testnet deployed smart-contract, change config in ./test/config.json ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import {toBN, isBN, numberToHex} from '../../src/common';
import Address from '../../src/address';
import Commitment from '../../src/commitment';
import Stealth from '../../src/stealth';
import TestUtils from '../utils';
import HDWalletProvider from "truffle-hdwallet-provider";
import * as _ from 'lodash';
import BN from 'bn.js';
var BigInteger = require('bigi')
import UTXO from '../../src/utxo.js';

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

//load single private key as string
let provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

var privacyContract = new web3.eth.Contract(TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
    from: SENDER_WALLET.address, // default from address
    gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
    gas: '1000000'
});

const TOMO = 1000000000000000000;

describe('privatesend', () => {
    for (var count = 0; count < 5; count++) {
        it('Successful send to privacy account - spend 3, 2 news utxo', (done) => {
            let amount = 3*TOMO;
            let sender = new Stealth({
                ...Address.generateKeys(SENDER_WALLET.privateKey)
            });

            let receiver = new Stealth({
                ...Address.generateKeys(RECEIVER_WALLET.privateKey)
            });

            // console.log("ecparams.p ", ecparams.p);

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
                // const proofOfReceiver = sender.genTransactionProof(0.5*TOMO, receiver.pubSpendKey, receiver.pubViewKey);
                const proofOfReceiver = sender.genTransactionProof(0.5*TOMO, receiver.pubSpendKey, receiver.pubViewKey, randomMask);
                console.log('sumOfSpendingMasks ', sumOfSpendingMasks.mod(ecparams.p).toHex());

                const myRemainMask = sumOfSpendingMasks
                                        .add(ecparams.p)
                                        .subtract(BigInteger.fromHex(proofOfReceiver.mask).mod(ecparams.p))
                                        .mod(ecparams.p)
                                        .toHex();

                console.log('myRemainMask ', myRemainMask);
                console.log('proofOfReceiver ', proofOfReceiver.mask);
                let proofOfMe = sender.genTransactionProof(2.5*TOMO, sender.pubSpendKey, sender.pubViewKey, myRemainMask);

                // sum up commitment to make sure input utxo commitments = output utxos commitment
                let inputCommitments = Commitment.sumCommitmentsFromUTXOs(UTXOs, SENDER_WALLET.privateKey);
                let expectedCommitments = Commitment.sumCommitments(generatedCommitments);
                // let outputCommitments = Point.decodeFrom(ecparams, proofOfReceiver.commitment).add(
                //     Point.decodeFrom(ecparams, proofOfMe.commitment)
                // );
                let outputCommitments = ecparams.G.multiply(BigInteger.fromHex(myRemainMask)).add(
                    ecparams.G.multiply(BigInteger.fromHex(randomMask))
                );
                console.log("---------------------------------------------");
                console.log('Sum in ', ecparams.G.multiply(sumOfSpendingMasks).getEncoded(true));
                console.log(ecparams.G.multiply(
                    BigInteger.fromHex(proofOfReceiver.mask)
                        .add(BigInteger.fromHex(proofOfMe.mask))
                ).getEncoded(true));
                console.log(ecparams.G.multiply(
                    BigInteger.fromHex(proofOfReceiver.mask)
                        .add(BigInteger.fromHex(proofOfMe.mask)).mod(ecparams.p)
                ).getEncoded(true));
                console.log('Sum out ', outputCommitments.getEncoded(true));

                expect(inputCommitments.getEncoded(true).toString('hex')).to.equal(expectedCommitments.getEncoded(true).toString('hex'));
                
                let NpointOfReceiver = ecparams.G.multiply(
                    BigInteger.fromHex(proofOfReceiver.mask)
                );

                let sendToSCCM = inputCommitments.add(
                    NpointOfReceiver.negate()
                );

                
                expect(ecparams.isOnCurve(sendToSCCM)).to.equal(true);
                expect(sendToSCCM.add(NpointOfReceiver).getEncoded(true).toString('hex')).to.equal(inputCommitments.getEncoded(true).toString('hex'));
                
                console.log(sendToSCCM.affineX.toHex());
                console.log(sendToSCCM.affineY.toHex());

                // expect(inputCommitments.getEncoded(true).toString('hex')).to.equal(outputCommitments.getEncoded(true).toString('hex'));
                privacyContract.methods.privateSend(
                    spendingUtxosIndex,
                    [
                        '0x' + sendToSCCM.getEncoded(false).toString('hex').substr(2, 64), // the X part of curve 
                        '0x' + sendToSCCM.getEncoded(false).toString('hex').substr(-64), // the Y part of curve
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
                        console.log("receipt ", receipt.events.InputSum.returnValues);
                        console.log("receipt ", receipt.events.OutputSum.returnValues);

                        // const insumCM = Point.fromAffine(ecparams, BigInteger.fromHex(numberToHex(receipt.events.InputSum.returnValues["0"])), 
                        // BigInteger.fromHex(numberToHex(receipt.events.InputSum.returnValues["1"])));

                        // const outsumCM = Point.fromAffine(ecparams, BigInteger.fromHex(numberToHex(receipt.events.OutputSum.returnValues["0"])), 
                        // BigInteger.fromHex(numberToHex(receipt.events.OutputSum.returnValues["1"])));

                        // console.log("---------------------------------------------");
                        console.log("In sum return ", numberToHex(receipt.events.InputSum.returnValues["0"]));
console.log("In sum return ", numberToHex(receipt.events.InputSum.returnValues["1"]))
                        console.log("Out sum return ", numberToHex(receipt.events.OutputSum.returnValues["0"]));
                        console.log("Out sum return ", numberToHex(receipt.events.OutputSum.returnValues["1"]));
                        console.log("---------------------------------------------");
                        done();
                        
                    })
                    .catch(function (error) {
                        console.log(error);
                        done(error);
                    });
            })
            .catch(function(err){
                done(err);
            });

        });
    }
});
