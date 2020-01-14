***TOMO privacy wallet's apis***
=======
Terms
- `keys`: private spend key, private view key, public spend key, public view key.
- `UTXO`: Unspent transaction output - result of a privacy transaction.
- `G`: secp256k1 base point
- `H`: secp256k1 generator point(there is an unknown x: H = x*G)
- `Blinding factor`: random Big Integer used as input for Elliptic-curve Diffie–Hellman
- `Mask`: random Big Integer, used as input for Pederson commitment for hiding value
- `Privacy address`: privacy's address
- `Pederson commitment`: Pederson commitment is cryptographic commitment scheme equivalent to secretly writing a secret message m in a sealed, tamper-evident, individually numbered (or/and countersigned) envelope kept by who wrote the message. The envelope's content can't be changed by any means, and the message does not leak any information. Formula = `G*Mask + value*H` .
- `Bullet proof`: Range proofs is a type of zero-knowledge proof used for proving that a secret is within a value range without revealing the precise value of the secret. Bulletproofs is a new non-interactive zero-knowledge proof protocol with very short proofs and without a trusted setup; the proof size is only logarithmic in the witness size. Bulletproofs are especially well suited for efficient range proofs on committed values: they enable proving that a committed value is in a range using only (2 logn + 9) group and field elements, where n is the bit length of the range. Proof generation and verification times are linear in n.
- `Transaction public key`: equal r * G
- `Stealth Address`: in other word - oneTimeAddress - random address just able to be decoded by owner's privatekey, in tomoprivacy - oneTimeAddress is for one UTXO
- `RingCT`: ring confidental transaction protocol, base on Cryptonote's with modifying for tomochain only

Additional requests/features please contact anhnt@tomochain.com

[![Build Status](https://travis-ci.org/tomochain/privacyjs.svg?branch=master)](https://travis-ci.org/tomochain/privacyjs)
[![codecov](https://codecov.io/gh/tomochain/privacyjs/branch/master/graph/badge.svg)](https://codecov.io/gh/tomochain/privacyjs)
### ROADMAP
- Finish high-level apis that able to interact with smart-contracts and precompiled contracts on test net includes ringct, deposit, balance, privatesend and withdraw
- Integrated to tomowallet web and integrated bullet proof, demo on testnet
- Total hide the transaction signer on private send and withdraw
- Integrate to Maxbet, standardlize the transaction flow for Dapp.

Usage
-----

TEST
---
- [x] Unit test - done
- [x] End to end test on tomochain testnet - cover main flow deposit, withdraw, sendtoprivate

License
-------

MIT
