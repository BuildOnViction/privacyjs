// /**
//  * End To End tests using tomochain testnet deployed smart-contract,
//  * change config in ./test/config.json ./test/config.json
//  */

// import Web3 from 'web3';
// import chai from 'chai';
// import HDWalletProvider from 'truffle-hdwallet-provider';
// import TestConfig from '../config.json';
// import UTXO from '../../src/utxo';
// import Stealth from '../../src/stealth';
// import * as Address from '../../src/address';
// import Commitment from '../../src/commitment';
// import * as TestUtils from '../utils';
// import { hexToNumberString } from '../../src/common';

// const { expect } = chai;
// chai.should();

// const { WALLETS } = TestConfig;
// const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

// // load single private key as string
// const provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

// const web3 = new Web3(provider);

// const privacyContract = new web3.eth.Contract(
//     TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
//         from: SENDER_WALLET.address, // default from address
//         gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
//         gas: '1000000',
//     },
// );

// const sender = new Stealth({
//     ...Address.generateKeys(SENDER_WALLET.privateKey),
// });
// // const basePoint = ecparams.G;

// /**
//  * To withdraw, you have to register privacy address to
//  * smart-contract on the first time you're on privacy mode
//  * and make sure you already successfully privatesend to the wallet 2 already
//  * // TODO refactor to run the withdraw the range randomly from 1 to 1000k
//  */
// describe('withdraw from SC', () => {
//     // make sure we run deposit first to get some balance
//     it('Successful withdraw 0.4 out of 1 balance utxo', (done) => {
//         // register privacy address, deposit 10 TOMO first the get the UTXO
//         Promise.all([
//             TestUtils.registerPrivacyAddress(SENDER_WALLET.privateKey),
//             TestUtils.deposit(1000000000000000000)]).then((result) => {
//             // console.log("result ", result);
//             const originalUTXO = result[1].utxo;
//             const originUTXOIns = new UTXO(originalUTXO);

//             const utxoIndex = originalUTXO._index;
//             const signature = originUTXOIns.sign(SENDER_WALLET.privateKey, SENDER_WALLET.address);
//             const amount = '400000000000000000';
//             const remain = '600000000000000000';

//             // encrypted the remain amount by same ECDH secret key
//             // and recalculate the commitment base on new amount and same ECDH
//             const encryptedRemain = sender.encryptedAmount(
//                 originUTXOIns.lfTxPublicKey.getEncoded(false),
//                 originUTXOIns.lfStealth.getEncoded(false), remain,
//             );
//             const expectedCommitment = Commitment.genCommitmentFromTxPub(remain, {
//                 X: originUTXOIns.txPubX,
//                 YBit: originUTXOIns.txPubYBit,
//             }, sender.privViewKey, false);

//             privacyContract.methods.withdrawFunds(
//                 utxoIndex,
//                 amount.toString(), `0x${encryptedRemain}`,
//                 [[...signature.r.toBuffer()], [...signature.s.toBuffer()]],
//                 SENDER_WALLET.address,
//                 [
//                     `0x${expectedCommitment.toString('hex').substr(2, 64)}`, // the X part of curve
//                     `0x${expectedCommitment.toString('hex').substr(-64)}`, // the Y part of curve
//                 ],
//             )
//                 .send({
//                     from: SENDER_WALLET.address,
//                 })
//                 .then((receipt) => {
//                     const utxoIns = new UTXO(receipt.events.NewUTXO.returnValues);
//                     const isMineUTXO = utxoIns.checkOwnership(SENDER_WALLET.privateKey);

//                     expect(isMineUTXO).to.not.equal(null);
//                     expect(isMineUTXO.amount).to.equal(remain);

//                     expect(
//                         utxoIns.lfCommitment.getEncoded(false).toString('hex') === expectedCommitment.toString('hex'),
//                     ).to.equal(true);

//                     // sum up commitment and double check
//                     // check if we can decode the amount on receipt
//                     done();
//                 })
//                 .catch((error) => {
//                     console.log(error);
//                     done(error);
//                 });
//         })
//             .catch((ex) => {
//                 done(ex);
//             });
//     });

//     it('Successful withdraw 1 out of 1 balance utxo', (done) => {
//         // register privacy address, deposit 10 TOMO first the get the UTXO
//         Promise.all([
//             TestUtils.registerPrivacyAddress(SENDER_WALLET.privateKey),
//             TestUtils.deposit(1000000000000000000)]).then((result) => {
//             // console.log("result ", result);
//             const originalUTXO = result[1].utxo;
//             const originUTXOIns = new UTXO(originalUTXO);

//             const utxoIndex = originalUTXO._index;
//             const signature = originUTXOIns.sign(SENDER_WALLET.privateKey, SENDER_WALLET.address);
//             const amount = '1000000000000000000';
//             const remain = '0';

//             // encrypted the remain amount by same ECDH secret key
//             // and recalculate the commitment base on new amount and same ECDH
//             const encryptedRemain = sender.encryptedAmount(
//                 originUTXOIns.lfTxPublicKey.getEncoded(false),
//                 originUTXOIns.lfStealth.getEncoded(false), remain,
//             );
//             const expectedCommitment = Commitment.genCommitmentFromTxPub(remain, {
//                 X: originUTXOIns.txPubX,
//                 YBit: originUTXOIns.txPubYBit,
//             }, sender.privViewKey, false);

//             privacyContract.methods.withdrawFunds(
//                 utxoIndex,
//                 amount.toString(), `0x${encryptedRemain}`,
//                 [[...signature.r.toBuffer()], [...signature.s.toBuffer()]],
//                 SENDER_WALLET.address,
//                 [
//                     `0x${expectedCommitment.toString('hex').substr(2, 64)}`, // the X part of curve
//                     `0x${expectedCommitment.toString('hex').substr(-64)}`, // the Y part of curve
//                 ],
//             )
//                 .send({
//                     from: SENDER_WALLET.address,
//                 })
//                 .then((receipt) => {
//                     const utxoIns = new UTXO(receipt.events.NewUTXO.returnValues);
//                     const isMineUTXO = utxoIns.checkOwnership(SENDER_WALLET.privateKey);

//                     expect(isMineUTXO).to.not.equal(null);
//                     expect(isMineUTXO.amount).to.equal(remain);

//                     expect(
//                         utxoIns.lfCommitment.getEncoded(false).toString('hex') === expectedCommitment.toString('hex'),
//                     ).to.equal(true);

//                     // sum up commitment and double check
//                     // check if we can decode the amount on receipt
//                     done();
//                 })
//                 .catch((error) => {
//                     console.log(error);
//                     done(error);
//                 });
//         })
//             .catch((ex) => {
//                 done(ex);
//             });
//     });

//     it('Should not successfully withdraw larger than balance', (done) => {
//         // register privacy address, deposit 10 TOMO first the get the UTXO
//         Promise.all([
//             TestUtils.registerPrivacyAddress(SENDER_WALLET.privateKey),
//             TestUtils.deposit(1000000000000000000)]).then((result) => {
//             // console.log("result ", result);
//             const { utxo } = result[1];
//             const UTXOIns = new UTXO(utxo);
//             const utxoIndex = utxo._index;
//             const signature = UTXOIns.sign(SENDER_WALLET.privateKey, SENDER_WALLET.address);
//             const amount = 2000000000000000000;

//             // create proof for a transaction,
//             // we deposit 1 tomo, withdraw 0.5 so amount here = 0.5 tomo
//             const proof = sender.genTransactionProof(
//                 amount,
//                 sender.pubSpendKey, sender.pubViewKey,
//             );

//             // console.log("proof.encryptedAmount ", proof.encryptedAmount)
//             if (proof.encryptedAmount.length % 2 === 1) {
//                 proof.encryptedAmount = `0${proof.encryptedAmount}`;
//             }

//             const commitment = Commitment.genCommitmentFromTxPub(0, {
//                 X: UTXOIns.txPubX,
//                 YBit: UTXOIns.txPubYBit,
//             }, sender.privViewKey, false);

//             // console.log([...signature.r.toBuffer()], [...signature.s.toBuffer()]);

//             privacyContract.methods.withdrawFunds(
//                 utxoIndex,
//                 amount.toString(), hexToNumberString(proof.encryptedAmount),
//                 [[...signature.r.toBuffer()], [...signature.s.toBuffer()]],
//                 SENDER_WALLET.address,
//                 [
//                     Web3.utils.hexToNumberString(commitment.toString('hex').substr(2, 64)), // the X part of curve
//                     Web3.utils.hexToNumberString(commitment.toString('hex').substr(-64)), // the Y part of curve
//                 ],
//             )
//                 .send({
//                     from: SENDER_WALLET.address,
//                 })
//                 .then(() => {
//                     done(new Error('Should not expected successfully withdraw '));
//                 })
//                 .catch(() => {
//                     done();
//                 });
//         })
//             .catch((ex) => {
//                 done(ex);
//             });
//     });
// });
