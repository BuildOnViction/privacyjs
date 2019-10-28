/* eslint-disable no-await-in-loop */
import Web3 from 'web3';
import chai from 'chai';
import HDWalletProvider from 'truffle-hdwallet-provider';
import TestConfig from './config.json';
import * as Address from '../src/address';
import Stealth from '../src/stealth';
import { hextobin } from '../src/common';
import UTXO from '../src/utxo';
import { keyImage } from '../src/mlsag';
import { BigInteger } from '../src/crypto';

chai.should();

const { WALLETS } = TestConfig;
const SENDER_WALLET = WALLETS[0]; // hold around 1 mil tomo

// load single private key as string
const provider = new HDWalletProvider(SENDER_WALLET.privateKey, TestConfig.RPC_END_POINT);

const web3 = new Web3(provider);

const privacyContract = new web3.eth.Contract(
    TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
        from: SENDER_WALLET.address, // default from address
        gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
        gas: '2000000',
    },
);

// we deposit a lot, actually all cases need deposit first
// to make sure we all have data in case mocha doesnt run deposit first
export const deposit = (amount, privateKey, from) => new Promise((resolve, reject) => {
    let web3ls;
    let contract = privacyContract;

    if (privateKey) {
        web3ls = new Web3(new HDWalletProvider(privateKey, TestConfig.RPC_END_POINT));

        contract = new web3ls.eth.Contract(
            TestConfig.PRIVACY_ABI, TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS, {
                from, // default from address
                gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
                gas: '2000000',
            },
        );

    }
    const sender = new Stealth({
        ...Address.generateKeys(privateKey || SENDER_WALLET.privateKey),
    });

    // create proof for a transaction
    const proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);

    contract.methods.deposit(
        `0x${proof.onetimeAddress.toString('hex').substr(2, 64)}`, // the X part of curve
        `0x${proof.onetimeAddress.toString('hex').substr(-64)}`, // the Y part of curve
        `0x${proof.txPublicKey.toString('hex').substr(2, 64)}`, // the X part of curve
        `0x${proof.txPublicKey.toString('hex').substr(-64)}`, // the Y par of curve,
        `0x${proof.mask}`,
        `0x${proof.encryptedAmount}`, // encrypt of amount using ECDH,
        `0x${proof.encryptedMask}`,
    )
        .send({
            from: from || SENDER_WALLET.address,
            value: amount,
        })
        .on('error', (error) => {
            reject(error);
        })
        .then((receipt) => {
            receipt.events.NewUTXO.should.be.a('object');
            try {
                resolve({
                    utxo: receipt.events.NewUTXO.returnValues,
                    proof,
                });
            } catch (error) {
                reject(error);
            }
        });
});

export const depositNTimes = async (N, amount) => {
    // const amountEachTransfer = numberToBN(amount).div(N).toString(10);
    // console.log("amountEachTransfer ", amountEachTransfer);
    const utxos = [];
    for (let index = 0; index < N; index++) {
        utxos.push(await deposit(amount));
    }
    return utxos;
};

const privacyAddressContract = new web3.eth.Contract(
    TestConfig.PRIVACYADD_MAPPING_ABI, TestConfig.PRIVACYADD_MAPPING_SMART_CONTRACT, {
        from: SENDER_WALLET.address, // default from address
        gasPrice: '250000000', // default gas price in wei, 20 gwei in this case,
        gas: '2000000',
    },
);

module.exports.registerPrivacyAddress = privateKey => new Promise((resolve, reject) => {
    const privacyAddress = Address.generateKeys(privateKey).pubAddr;
    privacyAddressContract.methods.register(
        hextobin(web3.utils.toHex(privacyAddress)),
    )
        .send({
            from: SENDER_WALLET.address,
        })
        .on('error', (error) => {
            reject(error);
        })
        .then((receipt) => {
            try {
                resolve(receipt);
            } catch (error) {
                reject(error);
            }
        });
});


function getUTXO(index) {
    return new Promise((resolve, reject) => {
        privacyContract.methods.getUTXO(index)
            .call({
                from: WALLETS[0].address,
            })
            .then(utxo => resolve(utxo)).catch((exception) => {
                reject(exception);
            });
    });
}

function isSpent(ki) {
    return new Promise((resolve, reject) => {
        privacyContract.methods.isSpent(ki)
            .call({
                from: WALLETS[0].address,
            })
            .then(utxo => resolve(utxo)).catch((exception) => {
                reject(exception);
            });
    });
}

/**
 * scan all utxo with input privateKey to check ownership
 * you can stop this progress until got some number
 * @param {*} privateKey
 * @param {*} limit
 */
export const scanUTXOs = async (privateKey, limit) => {
    let index = 0;
    let utxo = {};
    let balance = 0;
    const utxos = [];

    console.log('#Scanning my ', limit, ' utxo');

    do {
        try {
            utxo = await getUTXO(index);

            const utxoInstance = new UTXO({
                ...utxo,
                3: index,
            });

            const isMine = utxoInstance.checkOwnership(privateKey);

            if (isMine && parseFloat(isMine.amount).toString() === isMine.amount) {
                const ringctKeys = utxoInstance.getRingCTKeys(privateKey);
                // check if utxo is spent already
                const res = await isSpent(
                    `0x${keyImage(
                        BigInteger.fromHex(ringctKeys.privKey),
                        utxoInstance.lfStealth.getEncoded(false).toString('hex').slice(2),
                    ).getEncoded(true).toString('hex')}`,
                );

                if (!res) {
                    balance += parseFloat(isMine.amount);
                    utxos.push(utxoInstance);
                }
            }
            index++;
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
        utxos,
    };
};
