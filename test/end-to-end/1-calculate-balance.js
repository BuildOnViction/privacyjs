/**
 * End To End tests using tomochain testnet deployed smart-contract, change config in ./test/config.json ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import Address from '../../src/address';
import Stealth from '../../src/stealth';
import HDWalletProvider from "truffle-hdwallet-provider";
import ecurve from 'ecurve';
import crypto from '../../src/crypto';
import { scanUTXOs } from '../utils';
const { BigInteger } = crypto;
const ecparams = ecurve.getCurveByName('secp256k1');
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

describe('#balance', () => {
    it('#scanUTXOs and sum balance', (done) => {
        // scan all UTXO
        scanUTXOs(SENDER_WALLET.privateKey, 10).then((ret) => {
            expect(ret.balance > 0).to.be.equal(true);
            done();
        }).catch(ex => {
            done(ex);
        })
    });
});
