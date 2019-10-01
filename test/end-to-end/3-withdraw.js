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

// const basePoint = ecparams.G;

/**
 * To withdraw, you have to register privacy address to smart-contract on the first time you're on privacy mode
 */
describe('withdraw 0.5Tomo from SC', () => {
    // make sure we run deposit first to get some balance
    it('Successful withdraw from privacy account', (done) => {
        // register privacy address, deposit 10 TOMO first the get the UTXO
        Promise.all([
            TestUtils.registerPrivacyAddress(SENDER_WALLET.privateKey),
            TestUtils.deposit(1000000000000000000)]).then((result) => {
                // console.log("result ", result);
                let utxo = result[1].utxo;
                let UTXOIns = new UTXO(utxo);
                let utxoIndex = utxo._index
                let signature = UTXOIns.sign(SENDER_WALLET.privateKey, SENDER_WALLET.address);
                let amount = 500000000000000000; // 0.5 tomo
                
                // create proof for a transaction, we deposit 1 tomo, withdraw 0.5 so amount here = 0.5 tomo
                let proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);
                
                // console.log("proof.encryptedAmount ", proof.encryptedAmount)
                if (proof.encryptedAmount.length % 2 == 1) {
                    proof.encryptedAmount = '0' + proof.encryptedAmount;
                }

                let commitment = Commitment.genCommitmentFromTxPub(amount, {
                    X: UTXOIns.txPubX,
                    YBit: UTXOIns.txPubYBit
                }, sender.privViewKey, false);
                
                // console.log([...signature.r.toBuffer()], [...signature.s.toBuffer()]);
                
                privacyContract.methods.withdrawFunds(
                    utxoIndex,
                    '500000000000000000', hexToNumberString(proof.encryptedAmount),
                    [[...signature.r.toBuffer()], [...signature.s.toBuffer()]],
                    SENDER_WALLET.address,
                    // Commitment.genCommitment(amount,proof.mask), we already know  this mask, in reality we just know txpub
                    [
                        Web3.utils.hexToNumberString(commitment.toString('hex').substr(2, 64)), // the X part of curve 
                        Web3.utils.hexToNumberString(commitment.toString('hex').substr(-64)), // the Y part of curve
                    ]
                )
                    .send({
                        from: SENDER_WALLET.address
                    })
                    .then(function (receipt) {
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
});
