import Web3 from 'web3';
import chai from 'chai';
import TestConfig from './config.json';
import Address from '../src/address';
import Stealth from '../src/stealth';
import HDWalletProvider from "truffle-hdwallet-provider";
import { hextobin } from '../src/common';

chai.should();

const WALLETS = TestConfig.WALLETS;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

//load single private key as string
let provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

var privacyContract = new web3.eth.Contract(TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
    from: SENDER_WALLET.address, // default from address
    gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
    gas: '2000000'
});

module.exports.deposit = (amount) => {
    return new Promise((resolve, reject) => {
        let sender = new Stealth({
            ...Address.generateKeys(SENDER_WALLET.privateKey)
        })

        // create proof for a transaction 
        let proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);
        
        privacyContract.methods.deposit(
            '0x' + proof.onetimeAddress.toString('hex').substr(2, 64), // the X part of curve 
            '0x' + proof.onetimeAddress.toString('hex').substr(-64), // the Y part of curve
            '0x' + proof.txPublicKey.toString('hex').substr(2, 64), // the X part of curve
            '0x' + proof.txPublicKey.toString('hex').substr(-64), // the Y par of curve,
            '0x' + proof.mask,
            '0x' + proof.encryptedAmount// encrypt of amount using ECDH
        )
            .send({
                from: SENDER_WALLET.address,
                value: amount
            })
            .on('error', function (error) {
                console.log
                reject(error);
            })
            .then(function (receipt) {
                receipt.events.NewUTXO.should.be.a('object');
                try {
                    resolve({
                        utxo: receipt.events.NewUTXO.returnValues,
                        proof
                    });
                } catch (error) {
                    reject(error);
                }
            });
    });
}


var privacyAddressContract = new web3.eth.Contract(TestConfig.PRIVACYADD_MAPPING_ABI, TestConfig.PRIVACYADD_MAPPING_SMART_CONTRACT, {
    from: SENDER_WALLET.address, // default from address
    gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
    gas: '2000000'
});

module.exports.registerPrivacyAddress = (privateKey) => {
    return new Promise((resolve, reject) => {
        let privacyAddress = Address.generateKeys(privateKey).pubAddr;
        privacyAddressContract.methods.register(
            hextobin(web3.utils.toHex(privacyAddress))
        )
            .send({
                from: SENDER_WALLET.address,
            })
            .on('error', function (error) {
                reject(error);
            })
            .then(function (receipt) {
                try {
                    resolve(receipt);
                } catch (error) {
                    reject(error);
                }
            });
    });
}