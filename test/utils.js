import Web3 from 'web3';
import TestConfig from './config.json';
import Address from '../src/address';
import Stealth from '../src/stealth';
import HDWalletProvider from "truffle-hdwallet-provider";

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

module.exports.deposit = (amount) => {
    return new Promise((resolve, reject) => {
        let sender = new Stealth({
            ...Address.generateKeys(SENDER_WALLET.privateKey)
        })

        // create proof for a transaction 
        let proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);

        privacyContract.methods.deposit(
            Web3.utils.hexToNumberString(proof.onetimeAddress.toString('hex').substr(2, 64)), // the X part of curve 
            Web3.utils.hexToNumberString(proof.onetimeAddress.toString('hex').substr(-64)), // the Y part of curve
            Web3.utils.hexToNumberString(proof.txPublicKey.toString('hex').substr(2, 64)), // the X part of curve
            Web3.utils.hexToNumberString(proof.txPublicKey.toString('hex').substr(-64)), // the Y par of curve,
            Web3.utils.hexToNumberString(proof.mask),
            Web3.utils.hexToNumberString(proof.encryptedAmount)// encrypt of amount using ECDH
        )
            .send({
                from: WALLETS[0].address,
                value: amount
            })
            .on('error', function (error) {
                reject(error);
            })
            .then(function (receipt) {
                try {
                    resolve(receipt.events.NewUTXO.returnValues);
                } catch (error) {
                    reject(error);
                }
            });
    });
}