/**
 * We test real smart contract, you can config the address in ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import Address from '../../src/address';
import Stealth from '../../src/stealth';
import UTXO from '../../src/utxo';
import HDWalletProvider from "truffle-hdwallet-provider";
import ecurve from 'ecurve';
import crypto from '../../src/crypto';

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

describe('End to End Deposit to 1Tomo to SC', () => {
    it('Successful deposit to to privacy account', (done) => {
        let amount = 1000000000000000000; // 1 tomo
        // generate a tx 1 tomo from normal addess to privacy address
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
            Web3.utils.hexToNumberString(web3.utils.toHex(proof.encryptedAmount)) // encrypt of amount using ECDH
        )
            .send({
                from: WALLETS[0].address,
                value: amount
            })
            .on('error', function(error) {
                console.log(error);
                done(error);
            })
            .then(function(receipt){
                try {
                    receipt.events.NewUTXO.should.be.a('object')
                    expect(receipt.events.NewUTXO.transactionHash).to.have.lengthOf(66);

                    let utxoIns = new UTXO(receipt.events.NewUTXO.returnValues);
                    let isMineUTXO = utxoIns.isMineUTXO(SENDER_WALLET.privateKey);

                    expect(isMineUTXO).to.not.equal(null);
                    expect(isMineUTXO.amount).to.equal('1000000000000000000');
                    done();
                } catch (error) {
                    done(error);
                }
            });

    });
});
