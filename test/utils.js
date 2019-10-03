import Web3 from 'web3';
import chai from 'chai';
import TestConfig from './config.json';
import Address from '../src/address';
import Stealth from '../src/stealth';
import HDWalletProvider from "truffle-hdwallet-provider";
import { hextobin } from '../src/common';
import UTXO from '../src/utxo';

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

// we deposit a lot, actually all cases need deposit first
// to make sure we all have data in case mocha doesnt run deposit first
const deposit = (amount) => {
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
            '0x' + proof.encryptedAmount,// encrypt of amount using ECDH,
            '0x' + proof.encryptedMask
        )
            .send({
                from: SENDER_WALLET.address,
                value: amount
            })
            .on('error', function (error) {
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

module.exports.depositNTimes = async (N, amount) => {
    // const amountEachTransfer = numberToBN(amount).div(N).toString(10);
    // console.log("amountEachTransfer ", amountEachTransfer);
    const utxos = [];
    for (let index = 0; index < N; index++) {
        utxos.push(await deposit(amount));
    }
    return utxos;
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

/**
 * scan all utxo with input privateKey to check ownership
 * you can stop this progress until got some number
 * @param {*} privateKey 
 * @param {*} limit 
 */
const scanUTXOs = async (privateKey, limit) => {
    let index = 0;
    var utxo = {};
    var balance = 0;
    var utxos = [];

    do {
        try {
            utxo = await getUTXO(index);

            if (utxo["3"] === false) {
                let utxoInstance = new UTXO({
                    ...utxo,
                    "3": index
                });
                let isMine = utxoInstance.isMineUTXO(privateKey);
                
                if (isMine) {
                    utxos.push(utxo);
                }

                if (isMine && parseFloat(isMine.amount).toString() == isMine.amount) {
                    balance += parseFloat(isMine.amount);
                }
                index++;
            } else {
                index++;
            }

        } catch (exception) {
            // console.log(exception);
            utxo = null;
            break;
        }

        // we can't scan all utxo, it would take minutes on testnet and days on mainet
        // in testnet the encryption algorithm can be changed :( 
        if (limit) {
            if (utxos.length > limit) break;
        }
    } while (utxo);

    return {
        balance,
        utxos
    }
}

module.exports.scanUTXOs = scanUTXOs;

module.exports.deposit = deposit;