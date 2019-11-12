// /**
//  * End To End tests using tomochain testnet deployed smart-contract,
//  * change config in ./test/config.json ./test/config.json
//  */

// import Web3 from 'web3';
// import chai from 'chai';
// import HDWalletProvider from '@truffle/hdwallet-provider';
// import * as _ from 'lodash';
// import TestConfig from '../config.json';
// import * as Address from '../../src/address';
// import Commitment from '../../src/commitment';
// import Stealth from '../../src/stealth';
// import * as TestUtils from '../utils';
// import UTXO from '../../src/utxo';
// import { BigInteger } from '../../src/crypto';

// const ecurve = require('ecurve');

// const ecparams = ecurve.getCurveByName('secp256k1');
// const { Point } = ecurve;

// const EC = require('elliptic').ec;

// const ec = new EC('secp256k1');

// const { expect } = chai;
// chai.should();

// const { WALLETS } = TestConfig;
// const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo
// const RECEIVER_WALLET = WALLETS[1]; // hold around 1 mil tomo

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

// const TOMO = 1000000000000000000;

// const runtest = function (done) {
//     const sender = new Stealth({
//         ...Address.generateKeys(SENDER_WALLET.privateKey),
//     });

//     const receiver = new Stealth({
//         ...Address.generateKeys(RECEIVER_WALLET.privateKey),
//     });

//     // create 3 utxos, let this test independents to deposit test
//     TestUtils.depositNTimes(3, TOMO).then((utxos) => {
//         let sumOfSpendingMasks = BigInteger.fromHex('');
//         const UTXOs = [];
//         const generatedCommitments = [];
//         const spendingUtxosIndex = _.map(utxos, (result) => {
//             generatedCommitments.push(result.proof.commitment);
//             sumOfSpendingMasks = sumOfSpendingMasks.add(
//                 BigInteger.fromHex(result.proof.mask),
//             ).mod(ecparams.p);
//             UTXOs.push(new UTXO(result.utxo));
//             return result.utxo._index;
//         });

//         const randomMask = ec.genKeyPair().getPrivate('hex');
//         const proofOfReceiver = sender.genTransactionProof(
//             0.5 * TOMO, receiver.pubSpendKey, receiver.pubViewKey, randomMask,
//         );
//         const myRemainMask = ecparams.p
//             .add(ecparams.p)
//             .subtract(BigInteger.fromHex(proofOfReceiver.mask).mod(ecparams.p))
//             .subtract(sumOfSpendingMasks)
//             .toHex();

//         const proofOfMe = sender.genTransactionProof(2.5 * TOMO,
//             sender.pubSpendKey, sender.pubViewKey, myRemainMask);

//         // sum up commitment to make sure input utxo commitments = output utxos commitment
//         const inputCommitments = Commitment.sumCommitmentsFromUTXOs(
//             UTXOs, SENDER_WALLET.privateKey,
//         );
//         const expectedCommitments = Commitment.sumCommitments(generatedCommitments);
//         // let outputCommitments = Point.decodeFrom(ecparams, proofOfMe.commitment)
//         //     .add(
//         //         Point.decodeFrom(ecparams, proofOfReceiver.commitment)
//         //     );

//         expect(inputCommitments.getEncoded(true).toString('hex'))
//             .to.equal(
//                 expectedCommitments.getEncoded(true).toString('hex'),
//             );
//         // expect(inputCommitments.getEncoded(true).toString('hex'))
//         // .to.equal(outputCommitments.getEncoded(true).toString('hex'));
//         const pfm = inputCommitments.add(
//             Point.decodeFrom(ecparams, proofOfReceiver.commitment).negate(),
//         ).getEncoded(false);

//         privacyContract.methods.privateSend(
//             spendingUtxosIndex,
//             [
//                 `0x${pfm.toString('hex').substr(2, 64)}`, // the X part of curve
//                 `0x${pfm.toString('hex').substr(-64)}`, // the Y part of curve
//                 `0x${proofOfReceiver.commitment.toString('hex').substr(2, 64)}`, // the X part of curve
//                 `0x${proofOfReceiver.commitment.toString('hex').substr(-64)}`, // the Y part of curve
//                 `0x${proofOfMe.onetimeAddress.toString('hex').substr(2, 64)}`, // the X part of curve
//                 `0x${proofOfMe.onetimeAddress.toString('hex').substr(-64)}`, // the Y part of curve
//                 `0x${proofOfReceiver.onetimeAddress.toString('hex').substr(2, 64)}`, // the X part of curve
//                 `0x${proofOfReceiver.onetimeAddress.toString('hex').substr(-64)}`, // the Y part of curve
//                 `0x${proofOfMe.txPublicKey.toString('hex').substr(2, 64)}`, // the X part of curve
//                 `0x${proofOfMe.txPublicKey.toString('hex').substr(-64)}`, // the Y part of curve
//                 `0x${proofOfReceiver.txPublicKey.toString('hex').substr(2, 64)}`, // the X part of curve
//                 `0x${proofOfReceiver.txPublicKey.toString('hex').substr(-64)}`, // the Y part of curve
//             ],
//             [
//                 `0x${proofOfMe.encryptedAmount}`, // encrypt of amount using ECDH],
//                 `0x${proofOfReceiver.encryptedAmount}`, // encrypt of amount using ECDH],
//                 `0x${proofOfMe.encryptedMask}`, // encrypt of amount using ECDH],
//                 `0x${proofOfReceiver.encryptedMask}`, // encrypt of amount using ECDH],
//             ],
//         )
//             .send({
//                 from: SENDER_WALLET.address, // in real case, generate an dynamic accont to put here
//             })
//             .then((receipt) => {
//                 const returnUTXOs = receipt.events.NewUTXO.map(utxo => utxo.returnValues);

//                 // make sure at least one utxo belonging to receiver, one for sender
//                 // and encrypted amount correct
//                 const senderUTXOIns = new UTXO(returnUTXOs[0]);
//                 const receiverUTXOIns = new UTXO(returnUTXOs[1]);

//                 const decodedSenderUTXO = senderUTXOIns.checkOwnership(SENDER_WALLET.privateKey);
//                 const decodedReceiverUTXO = receiverUTXOIns.checkOwnership(
//                     RECEIVER_WALLET.privateKey,
//                 );

//                 expect(senderUTXOIns.checkOwnership(RECEIVER_WALLET.privateKey)).to.be.equal(null);
//                 expect(receiverUTXOIns.checkOwnership(SENDER_WALLET.privateKey)).to.be.equal(null);

//                 expect(decodedSenderUTXO).to.not.be.equal(null);
//                 expect(decodedReceiverUTXO).to.not.be.equal(null);

//                 expect(decodedSenderUTXO.amount === (2.5 * TOMO).toString()).to.be.equal(true);
//                 expect(decodedReceiverUTXO.amount === (0.5 * TOMO).toString()).to.be.equal(true);

//                 done();
//             })
//             .catch((error) => {
//                 done(error);
//             });
//     })
//         .catch((err) => {
//             done(err);
//         });
// };

// describe('#send', () => {
//     before((done) => {
//         // scanUTXOs().then((ret) => {
//         //     receiverBalance = ret.balance;
//         //     receiverUtxos = ret.utxos;
//         //     done();
//         // }).catch(ex => {
//         //     done(ex);
//         // })
//         done();
//     });

//     for (let count = 0; count < 2; count++) {
//         it('Successful send to privacy account - spend 3, 2 news utxo', (done) => {
//             runtest(done);
//         });
//     }
// });
