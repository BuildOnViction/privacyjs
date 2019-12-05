/* eslint-disable no-await-in-loop */
import Web3 from 'web3';
import chai from 'chai';
import HDWalletProvider from '@truffle/hdwallet-provider';
import TestConfig from './config.json';
import * as Address from '../src/address';
import Stealth from '../src/stealth';
import Wallet from '../src/wallet';
import { toBN, hextobin, hexToNumberString, DEPOSIT_FEE_WEI, FEE_WEI } from '../src/common';

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

const PRIVACY_TOKEN_UNIT = toBN(
    '1000000000',
); // use gwei as base unit for reducing size of rangeproof

// we deposit a lot, actually all cases need deposit first
// to make sure we all have data in case mocha doesnt run deposit first
// amunt is in wei unit
export const deposit = (_amount, privateKey, from) => new Promise((resolve, reject) => {
    let web3ls;
    let contract = privacyContract;
    let amount = _amount - DEPOSIT_FEE_WEI;

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
    const proof = sender.genTransactionProof(
        hexToNumberString(
            toBN(amount).divide(PRIVACY_TOKEN_UNIT).toString(16),
        ), sender.pubSpendKey, sender.pubViewKey,
    );
    // const proof = sender.genTransactionProof(amount, sender.pubSpendKey, sender.pubViewKey);
    console.log('Amount deposit = ', amount, ', deposit fee = ', DEPOSIT_FEE_WEI);
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
            value: _amount,
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
    const wallet = new Wallet(privateKey, {
        RPC_END_POINT: TestConfig.RPC_END_POINT,
        ABI: TestConfig.PRIVACY_ABI,
        ADDRESS: TestConfig.PRIVACY_SMART_CONTRACT_ADDRESS,
    }, WALLETS[0].address);

    const { utxos, balance } = await wallet.scan(limit);

    return {
        balance,
        utxos,
    };
};

/**
 * Generate random utxos
 * @param {string} privateKey
 * @param {BigInteger} totalBalance
 * @returns {Array<UTXO>}
 */
export const randomUTXOS = (privateKey, specifiedAmount) => {
    const utxos = [];
    const sender = new Stealth({
        ...Address.generateKeys(privateKey),
    });
    for (let index = 0; index < specifiedAmount.length; index++) {
        utxos.push(
            {
                ...sender.genTransactionProof(specifiedAmount[index]),
                decodedAmount: specifiedAmount[index],
            },
        );
    }

    return utxos;
};
