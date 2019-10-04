/**
 * End To End tests using tomochain testnet deployed smart-contract, change config in ./test/config.json ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import UTXO from '../../src/utxo';
import Stealth from '../../src/stealth';
import Address from '../../src/address';
import Commitment from '../../src/commitment';
import HDWalletProvider from "truffle-hdwallet-provider";
import TestUtils from '../utils';
import { hexToNumberString } from '../../src/common';

const expect = chai.expect;
chai.should();

const WALLETS = TestConfig.WALLETS;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

//load single private key as string
let provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

var privacyContract = new web3.eth.Contract(TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
    from: SENDER_WALLET.address, // default from address
    gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
    gas: '1000000'
});

let sender = new Stealth({
    ...Address.generateKeys(SENDER_WALLET.privateKey)
})


const ecurve = require('ecurve');
const ecparams = ecurve.getCurveByName('secp256k1');
const { Point } = ecurve;

// const basePoint = ecparams.G;

/**
 * To withdraw, you have to register privacy address to smart-contract on the first time you're on privacy mode
 * and make sure you already successfully privatesend to the wallet 2 already
 * // TODO refactor to run the withdraw the range randomly from 1 to 1000k
 */
describe('withdraw from SC', () => {
    // make sure we run deposit first to get some balance
    it('Successful withdraw 0.4 out of 1 balance utxo', (done) => {
        // register privacy address, deposit 10 TOMO first the get the UTXO
        Promise.all([
            TestUtils.registerPrivacyAddress(SENDER_WALLET.privateKey),
            TestUtils.deposit(1000000000000000000)]).then((result) => {
                // console.log("result ", result);
                let originalUTXO = result[1].utxo;
                let originUTXOIns = new UTXO(originalUTXO);

                let utxoIndex = originalUTXO._index
                let signature = originUTXOIns.sign(SENDER_WALLET.privateKey, SENDER_WALLET.address);
                let amount = '400000000000000000';
                let remain = '600000000000000000';

                // encrypted the remain amount by same ECDH secret key
                // and recalculate the commitment base on new amount and same ECDH
                let encryptedRemain = sender.encryptedAmount(originUTXOIns.lfTxPublicKey.getEncoded(false), originUTXOIns.lfStealth.getEncoded(false), remain);
                let expectedCommitment = Commitment.genCommitmentFromTxPub(remain, {
                    X: originUTXOIns.txPubX,
                    YBit: originUTXOIns.txPubYBit
                }, sender.privViewKey, false);

                privacyContract.methods.withdrawFunds(
                    utxoIndex,
                    amount.toString(), '0x' + encryptedRemain,
                    [[...signature.r.toBuffer()], [...signature.s.toBuffer()]],
                    SENDER_WALLET.address,
                    [
                        '0x' + expectedCommitment.toString('hex').substr(2, 64), // the X part of curve 
                        '0x' + expectedCommitment.toString('hex').substr(-64), // the Y part of curve
                    ]
                )
                    .send({
                        from: SENDER_WALLET.address
                    })
                    .then(function (receipt) {
                        let utxoIns = new UTXO(receipt.events.NewUTXO.returnValues);
                        let isMineUTXO = utxoIns.checkOwnership(SENDER_WALLET.privateKey);
                        
                        expect(isMineUTXO).to.not.equal(null);
                        expect(isMineUTXO.amount).to.equal(remain);

                        expect(
                            utxoIns.lfCommitment.getEncoded(false).toString('hex') === expectedCommitment.toString('hex')
                        ).to.equal(true);
                        
                        // sum up commitment and double check
                        // check if we can decode the amount on receipt
                        done();
                    })
                    .catch(function (error) {
                        console.log(error);
                        done(error);
                    });
            })
            .catch((ex) => {
                done(ex);
            })
    });

    it('Successful withdraw 1 out of 1 balance utxo', (done) => {
        // register privacy address, deposit 10 TOMO first the get the UTXO
        Promise.all([
            TestUtils.registerPrivacyAddress(SENDER_WALLET.privateKey),
            TestUtils.deposit(1000000000000000000)]).then((result) => {
                // console.log("result ", result);
                let originalUTXO = result[1].utxo;
                let originUTXOIns = new UTXO(originalUTXO);

                let utxoIndex = originalUTXO._index
                let signature = originUTXOIns.sign(SENDER_WALLET.privateKey, SENDER_WALLET.address);
                let amount = '1000000000000000000';
                let remain = '0';

                // encrypted the remain amount by same ECDH secret key
                // and recalculate the commitment base on new amount and same ECDH
                let encryptedRemain = sender.encryptedAmount(originUTXOIns.lfTxPublicKey.getEncoded(false), originUTXOIns.lfStealth.getEncoded(false), remain);
                let expectedCommitment = Commitment.genCommitmentFromTxPub(remain, {
                    X: originUTXOIns.txPubX,
                    YBit: originUTXOIns.txPubYBit
                }, sender.privViewKey, false);

                privacyContract.methods.withdrawFunds(
                    utxoIndex,
                    amount.toString(), '0x' + encryptedRemain,
                    [[...signature.r.toBuffer()], [...signature.s.toBuffer()]],
                    SENDER_WALLET.address,
                    [
                        '0x' + expectedCommitment.toString('hex').substr(2, 64), // the X part of curve 
                        '0x' + expectedCommitment.toString('hex').substr(-64), // the Y part of curve
                    ]
                )
                    .send({
                        from: SENDER_WALLET.address
                    })
                    .then(function (receipt) {
                        let utxoIns = new UTXO(receipt.events.NewUTXO.returnValues);
                        let isMineUTXO = utxoIns.checkOwnership(SENDER_WALLET.privateKey);
                        
                        expect(isMineUTXO).to.not.equal(null);
                        expect(isMineUTXO.amount).to.equal(remain);

                        expect(
                            utxoIns.lfCommitment.getEncoded(false).toString('hex') === expectedCommitment.toString('hex')
                        ).to.equal(true);
                        
                        // sum up commitment and double check
                        // check if we can decode the amount on receipt
                        done();
                    })
                    .catch(function (error) {
                        console.log(error);
                        done(error);
                    });
            })
            .catch((ex) => {
                done(ex);
            })
    });

    it('Should not successfully withdraw larger than balance', (done) => {
        // register privacy address, deposit 10 TOMO first the get the UTXO
        Promise.all([
            TestUtils.registerPrivacyAddress(SENDER_WALLET.privateKey),
            TestUtils.deposit(1000000000000000000)]).then((result) => {
                // console.log("result ", result);
                let utxo = result[1].utxo;
                let UTXOIns = new UTXO(utxo);
                let utxoIndex = utxo._index
                let signature = UTXOIns.sign(SENDER_WALLET.privateKey, SENDER_WALLET.address);
                let amount = 2000000000000000000;

                // create proof for a transaction, we deposit 1 tomo, withdraw 0.5 so amount here = 0.5 tomo
                let proof = sender.genTransactionProof(
                    amount
                    , sender.pubSpendKey, sender.pubViewKey);

                // console.log("proof.encryptedAmount ", proof.encryptedAmount)
                if (proof.encryptedAmount.length % 2 == 1) {
                    proof.encryptedAmount = '0' + proof.encryptedAmount;
                }

                let commitment = Commitment.genCommitmentFromTxPub(0, {
                    X: UTXOIns.txPubX,
                    YBit: UTXOIns.txPubYBit
                }, sender.privViewKey, false);

                // console.log([...signature.r.toBuffer()], [...signature.s.toBuffer()]);

                privacyContract.methods.withdrawFunds(
                    utxoIndex,
                    amount.toString(), hexToNumberString(proof.encryptedAmount),
                    [[...signature.r.toBuffer()], [...signature.s.toBuffer()]],
                    SENDER_WALLET.address,
                    [
                        Web3.utils.hexToNumberString(commitment.toString('hex').substr(2, 64)), // the X part of curve 
                        Web3.utils.hexToNumberString(commitment.toString('hex').substr(-64)), // the Y part of curve
                    ]
                )
                    .send({
                        from: SENDER_WALLET.address
                    })
                    .then(function (receipt) {
                        done(new Error("Should not expected successfully withdraw "));
                    })
                    .catch(function (error) {
                        done();
                    });
            })
            .catch((ex) => {
                done(ex);
            })
    });
});
