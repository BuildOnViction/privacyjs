/**
 * We test real smart contract, you can config the address in ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import Address from '../../src/address';
import Stealth from '../../src/stealth';
import HDWalletProvider from "truffle-hdwallet-provider";
import ecurve from 'ecurve';
import crypto from '../../src/crypto';
import UTXO from '../../src/utxo';

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

// todo - move to util
function getUTXO(index) {
    return new Promise((resolve, reject) => {
        privacyContract.methods.getUTXO(index)
                .call({
                    from: WALLETS[0].address
                })
                .then(function (utxo) {
                    return resolve(utxo);
                }).catch(exception => {
                    reject(exception);
                })
    });
}

const scanAllUTXO = async() => {
    let index = 0;
    var utxo = {};
    var balance = 0;

    do {
        try {
            utxo = await getUTXO(index);
            let utxoInstance = new UTXO(utxo);
            let isMine = utxoInstance.isMineUTXO(SENDER_WALLET.privateKey);
            
            if (isMine && parseFloat(isMine.amount).toString() == isMine.amount ) {
                balance += isMine.amount;
            }
            index++;
        } catch(exception) {
            utxo = null;
            break;
        }
    } while (utxo);

    return balance;
}

describe('Get List All UTXO and count balance', () => {
    it('#scanAllUTXO', (done) => {
        // scan all UTXO
        scanAllUTXO().then((balance) => {
            expect(balance > 0).to.be.equal(true);
            done();
        }).catch(ex => {
            done(ex);
        })
    });
});
