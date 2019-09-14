import web3 from 'web3';
import Address from './address';
import Stealth from './stealth';
import ecurve from 'ecurve';
import crypto from './crypto';

const { BigInteger } = crypto;
const ecparams = ecurve.getCurveByName('secp256k1');

/**
 * TXO stands for the unspent output from bitcoin transactions.
 * Each transaction begins with coins used to balance the ledger.
 * UTXOs are processed continuously and are responsible for beginning and ending each transaction.
 * Confirmation of transaction results in the removal of spent coins from the UTXO database.
 * But a record of the spent coins still exists on the ledger. 
 */

/* UTXO structure input
    * 0 - commitmentX:
    * 1 - _commitmentYBit: '0',
    * 2 - _pubkeyX: stealth_address_X, short form of a point in ECC
    * 3 - _pubkeyYBit: '', // bit indicate odd or even of stealth_address_Y
    * 4 - _amount: encrypt_AES(shared_ECDH, amount),
    *_5 - _txPubX: transation_public_key_X, short form of a point in ECC
    * 6 - _txPubYBit
    
    EX: 
    '0': '18155385148682453381171818128120365169772552264272945929233713987750616246610',
    '1': '3',
    '2': '105402281739543703241605506454141998113174872495611241696092003547383306768736',
    '3': '3',
    '4': '30068922563895814107606905823132927972759867595009162926879225955533868852029',
    '5': '27246925684297394305550515166422186690892865966252478222982343298519032345022',
    '6': '2'
*/

class UTXO {
    constructor(utxo){
        this.commitmentX = utxo["0"];
        this.commitmentYBit = utxo["1"];
        this.pubkeyX = utxo["2"];
        this.pubkeyYBit = utxo["3"];
        this.amount = utxo["4"];
        this.txPubX = utxo["5"];
        this.txPubYBit = utxo["6"];
    }

    /**
     * Check if this utxo belong to account base on a secretkey
     * @param {string} privateSpendKey Hex string of private spend key - in other word serectkey
     * @returns {object} amount, keys
     */
    isMineUTXO(privateSpendKey) {
        let receiver = new Stealth({
            ...Address.generateKeys(privateSpendKey)
        });
        let isYStealthOdd = parseInt(this.pubkeyYBit) % 2 == 1;
        let longFormStealth = ecparams.pointFromX(isYStealthOdd,
            BigInteger(this.pubkeyX));

        let isYTxPublicKeyOdd = parseInt(this.txPubYBit) % 2 == 1;
        let longFormTxPublicKey = ecparams.pointFromX(isYTxPublicKeyOdd, 
            BigInteger(this.txPubX));

        return receiver.checkTransactionProof(
            longFormTxPublicKey.getEncoded(false),
            longFormStealth.getEncoded(false),
            web3.utils.hexToUtf8(web3.utils.numberToHex(this.amount))
        )
    }

    /**
     * create signature of an UTXO to send to smart-contract to withdraw
     * TODO: future we need to implement ring-signatureCT (monero-like) to prove 
     * @param {string} privateKey
     * @results {array} DER encoded signature in array
     */
    signUTXO(privateKey) {

    }

    /**
     * Withdraw this UTXO
     * decode the amount of this UTXO, create signature 
     */
    withdraw() {
    }

    sendTo(privacyAddress) {

    }
}

module.exports = UTXO;