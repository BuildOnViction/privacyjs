/**
 * End To End tests using tomochain testnet deployed smart-contract, change config in ./test/config.json ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import Address from '../../src/address';
import Stealth from '../../src/stealth';
import UTXO from '../../src/utxo';
import HDWalletProvider from "truffle-hdwallet-provider";
import TestUtils from '../utils';

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

/**
 * To withdraw, you have to register privacy address to smart-contract on the first time you're on privacy mode
 */
describe('withdraw 0.5Tomo to SC', () => {
    // make sure we run deposit first to get some balance
    it('Successful withdraw from privacy account', (done) => {
        // register privacy address, deposit 10 TOMO first the get the UTXO
        Promise.all([
            TestUtils.registerPrivacyAddress(SENDER_WALLET.privateKey),
            TestUtils.deposit(1000000000000000000)]).then((result) => {
                let utxo = result[1];
                let UTXOIns = new UTXO(utxo);
                let utxoIndex = utxo.events.NewUTXO.returnValues
                let derSign = UTXOIns.sign(SENDER_WALLET.privateKey);
                let amount = 500000000000000000; // 0.5 tomo

                privacyContract.methods.withdrawFunds(
                    utxoIndex,
                    [spend, leftCommitment],
                    derSign,
                    SENDER_WALLET.address,
                    amount
                )
                    .send({
                        from: SENDER_WALLET.address,
                        value: amount
                    })
                    .on('error', function (error) {
                        console.log(error);
                        done(error);
                    })
                    .then(function (receipt) {
                        try {
                            done();
                        } catch (error) {
                            done(error);
                        }
                    });
            })
            .catch((ex) => {
                done(ex);
            })
    });
});
