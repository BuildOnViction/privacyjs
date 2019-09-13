/**
 * We test real smart contract, you can config the address in ./test/config.json
 */

import Web3 from 'web3';
import TestConfig from '../config.json';
import chai from 'chai';
import Address from '../../src/address';
import Stealth from '../../src/stealth';
import HDWalletProvider from "truffle-hdwallet-provider";
import { AssertionError } from 'assert';
import assert from 'assert';

const expect = chai.expect;
chai.should();

const WALLETS = TestConfig.WALLETS;

//load single private key as string
let provider = new HDWalletProvider(WALLETS[0].privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

var privacyContract = new web3.eth.Contract(TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
    from: WALLETS[0].address, // default from address
    gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
    gas: '1000000'
});

describe('End to End Deposit to 1Tomo to SC', () => {
    it('Successful deposit to to privacy account', (done) => {
        let amount = 1000000000000000000; // 1 tomo
        // generate a tx 1 tomo from normal addess to privacy address
        let sender = new Stealth({
            ...Address.generateKeys(WALLETS[0].privateKey)
        })

        // create proof for a transaction 
        let proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);

        privacyContract.methods.deposit(
            Web3.utils.hexToNumberString(proof.onetimeAddress.slice(1).slice(0, 32).toString('hex')), 
            Web3.utils.hexToNumberString(proof.onetimeAddress.slice(0, 1).toString('hex')),
            Web3.utils.hexToNumberString(proof.txPublicKey.slice(1).slice(0, 32).toString('hex')), 
            Web3.utils.hexToNumberString(proof.txPublicKey.slice(0, 1).toString('hex'))
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
                    const UTXO = receipt.events.NewUTXO;
                    UTXO.should.be.a('object')
                    expect(UTXO.transactionHash).to.have.lengthOf(66);

                    // double check the ownership
                    
                    let isMineUTXO = sender.checkTransactionProof(
                        Buffer.from(web3.utils.numberToHex(UTXO.returnValues._pubkeyYBit + UTXO.returnValues._pubkeyX).slice(2), "hex"),
                        Buffer.from(web3.utils.numberToHex(UTXO.returnValues._commitmentYBit + UTXO.returnValues._commitmentX).slice(2), "hex"),
                    )
                    expect(isMineUTXO).to.not.equal(null);
                    done();
                } catch (error) {
                    done(error);
                }
            });

    });
});
