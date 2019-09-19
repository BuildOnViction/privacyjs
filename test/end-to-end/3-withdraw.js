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
                console.log("result ", result);
                let utxo = result[1];
                let UTXOIns = new UTXO(utxo);
                let utxoIndex = utxo._index
                let derSign = UTXOIns.sign(SENDER_WALLET.privateKey);
                let amount = 500000000000000000; // 0.5 tomo
                
                // create proof for a transaction, we deposit 1 tomo, withdraw 0.5 so amount here = 0.5 tomo
                let proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);
                
                console.log("proof.encryptedAmount ", proof.encryptedAmount)
                privacyContract.methods.withdrawFunds(
                    utxoIndex,
                    [500000000000000000, 16237732103012451899913639141037139769701578],
                    derSign,
                    SENDER_WALLET.address,
                    // Commitment.genCommitment(amount,proof.mask), we already know  this mask, in reality we just know txpub
                    [ ...Commitment.genCommitmentFromTxPub(amount, {
                        X: UTXOIns.txPubX,
                        YBit: UTXOIns.txPubYBit
                    }, sender.privViewKey)]
                )
                    .call({
                        from: SENDER_WALLET.address
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
