/**
 * End To End tests using tomochain testnet deployed smart-contract, change config in ./test/config.json ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import {toBN} from '../../src/common';
import Address from '../../src/address';
import Commitment from '../../src/commitment';
import Stealth from '../../src/stealth';
import TestUtils from '../utils';
import HDWalletProvider from "truffle-hdwallet-provider";
import * as _ from 'lodash';
import BN from 'bn.js';
import UTXO from '../../src/utxo.js';

const ecurve = require('ecurve');
const ecparams = ecurve.getCurveByName('secp256k1');
const { Point } = ecurve;

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
/**
 * To private send we need to do
 * 1. Ta
 */
describe('privatesend', () => {
    for (var count = 0; count < 1; count++) {
        it('Successful send to privacy account - spend 3, 2 news utxo', (done) => {
            let amount = 3*TOMO;
            let sender = new Stealth({
                ...Address.generateKeys(SENDER_WALLET.privateKey)
            });

            let receiver = new Stealth({
                ...Address.generateKeys(RECEIVER_WALLET.privateKey)
            });

            // create 3 utxos, let this test independents to deposit test
            TestUtils.depositNTimes(3, TOMO).then((utxos) => {
                let sumOfSpendingMasks = new BN('0', 16);
                let UTXOs = [];
                let generatedCommitments = [];
                const spendingUtxosIndex = _.map(utxos, result => {
                    generatedCommitments.push(result.proof.commitment);
                    sumOfSpendingMasks = sumOfSpendingMasks.add(new BN(result.proof.mask, 16));
                    UTXOs.push(new UTXO(result.utxo));
                    return result.utxo._index
                });

                const proofOfReceiver = sender.genTransactionProof(0.5*TOMO, receiver.pubSpendKey, receiver.pubViewKey);

                const myRemainMask = sumOfSpendingMasks.sub(new BN(proofOfReceiver.mask, 16)).toString(16);

                let proofOfMe = sender.genTransactionProof(2.5*TOMO, sender.pubSpendKey, sender.pubViewKey, myRemainMask);

                // sum up commitment to make sure input utxo commitments = output utxos commitment
                let inputCommitments = Commitment.sumCommitmentsFromUTXOs(UTXOs, SENDER_WALLET.privateKey);
                let expectedCommitments = Commitment.sumCommitments(generatedCommitments);
                let outputCommitments = Point.decodeFrom(ecparams, proofOfReceiver.commitment).add(
                    Point.decodeFrom(ecparams, proofOfMe.commitment)
                );
                
                expect(inputCommitments.getEncoded(true).toString('hex')).to.equal(expectedCommitments.getEncoded(true).toString('hex'));
                expect(inputCommitments.getEncoded(true).toString('hex')).to.equal(outputCommitments.getEncoded(true).toString('hex'));
                privacyContract.methods.privateSend(
                    spendingUtxosIndex,
                    [
                        '0x' + proofOfMe.commitment.toString('hex').substr(2, 64), // the X part of curve 
                        '0x' + proofOfMe.commitment.toString('hex').substr(-64), // the Y part of curve
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
                        console.log("receipt ", receipt);
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
