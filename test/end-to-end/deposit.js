/**
 * We test real smart contract, you can config the address in ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import chaiAsPromised from 'chai-as-promised';
import Address from '../../src/address';
import Stealth from '../../src/stealth';
import HDWalletProvider from "truffle-hdwallet-provider";

const BigNumber = require('bignumber.js');
const WALLETS = TestConfig.WALLETS;

//load single private key as string
let provider = new HDWalletProvider(WALLETS[0].privateKey, TestConfig.RPC_END_POINT);


chai.use(chaiAsPromised);
const expect = chai.expect;
const web3 = new Web3(provider);

var privacyContract = new web3.eth.Contract(TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
    from: WALLETS[0].address, // default from address
    gasPrice: '20000000000', // default gas price in wei, 20 gwei in this case,
    gas: '1000000'
});

describe('End to End Deposit SC', done => {
    it('Successful deposit to to privacy account', (done) => {
        let amount = 1000000000000000000; // 1 tomo
        // generate a tx 1 tomo from normal addess to privacy address
        let sender = new Stealth({
            ...Address.generateKeys(WALLETS[0].privateKey)
        })
        
        // create proof for a transaction 
        let proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);
        
        let temp1 = [...proof.onetimeAddress.slice(1)].map(function(ele) {
            return BigNumber(ele).toString(10)
        });

        let temp2 = [...proof.txPublicKey.slice(1)].map(function(ele) {
            return BigNumber(ele).toString(10)
        });

        privacyContract.methods.deposit(temp1, temp2)
            .send({
                from: WALLETS[0].address,
                value: amount
            })
            .on('transactionHash', function(hash){
                console.log("tx hash ", hash);
            })
            .on('receipt', function(receipt){
                console.log("tx receipt ", receipt);
                done();
            })
            .on('confirmation', function(confirmationNumber, receipt){
                console.log("confirmationNumber, receipt ", confirmationNumber, receipt)
            })
            .on('error', function(error) {
                console.log(error);
                done(error);
            });

    });
});
