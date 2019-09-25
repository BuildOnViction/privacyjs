/**
 * End To End tests using tomochain testnet deployed smart-contract, change config in ./test/config.json ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import Address from '../../src/address';
import Stealth from '../../src/stealth';
import TestUtils from '../utils';
import HDWalletProvider from "truffle-hdwallet-provider";
import * as _ from 'lodash';

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
    it('Successful send to privacy account - spend 3, 2 news utxo', (done) => {
        let amount = 3*TOMO;
        let sender = new Stealth({
            ...Address.generateKeys(SENDER_WALLET.privateKey)
        });

        let receiver = new Stealth({
            ...Address.generateKeys(RECEIVER_WALLET.privateKey)
        });

        var proofOfReceiver = sender.genTransactionProof(0.5*TOMO, receiver.pubSpendKey, receiver.pubViewKey)

        /**
         * We must recalculate mask base on 
         * remain_mask = sum(mask of all utxos) - mask_proof_receiver
         */
        
        // create 3 utxos, let this test independents to deposit test
        TestUtils.depositNTimes(3, TOMO).then((utxos) => {
            privacyContract.methods.privateSend(
                _.map(utxos, ut => {
                    return ut.utxo._index
                }),
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
                    '0x' + proofOfReceiver.encryptedAmount// encrypt of amount using ECDH],
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
});
