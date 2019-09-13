import { Interface } from "readline";

/**
 * TXO stands for the unspent output from bitcoin transactions.
 * Each transaction begins with coins used to balance the ledger.
 * UTXOs are processed continuously and are responsible for beginning and ending each transaction.
 * Confirmation of transaction results in the removal of spent coins from the UTXO database.
 * But a record of the spent coins still exists on the ledger. 
 */


class UTXO {
    constructor(fields) {
    }

    isMineUTXO(privateSpendKey) {

    }
 }