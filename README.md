tomoprivacyjs
Apis for making transactions in privacy mode
=======
Terms
- `keys`: private spend key, private view key, public spend key, public view key.
- `privacy address`: address from privacy transaction. 
- `Pederson commitment`: Pederson commitment is cryptographic commitment scheme equivalent to secretly writing a secret message m in a sealed, tamper-evident, individually numbered (or/and countersigned) envelope kept by who wrote the message. The envelope's content can't be changed by any means, and the message does not leak any information.
- `Bullet proof`: Range proofs is a type of zero-knowledge proof used for proving that a secret is within a value range without revealing the precise value of the secret. Bulletproofs is a new non-interactive zero-knowledge proof protocol with very short proofs and without a trusted setup; the proof size is only logarithmic in the witness size. Bulletproofs are especially well suited for efficient range proofs on committed values: they enable proving that a committed value is in a range using only (2 logn + 9) group and field elements, where n is the bit length of the range. Proof generation and verification times are linear in n.
- `Transaction public key`: equal blinding factor * G (the standard secp256k1 base point)
- `Stealth Address`: in other word - oneTimeAddress or tomo privacy address
- `RingCT`: ring confidental transaction protocol, base on Cryptonote's with modifying for tomochain only

Additional requests/features please contact anhnt@tomochain.com

[![Build Status](https://travis-ci.org/tomochain/privacyjs.svg?branch=master)](https://travis-ci.org/tomochain/privacyjs)
### ROADMAP
- 15/11/2019 Finish high-level apis that able to interact with smart-contracts and precompiled contracts on test net includes ringct, deposit, balance, privatesend and withdraw
- 30/11/2019 Integrated to tomowallet web and integrated bullet proof, demo on testnet
- 15/12/2019 Total hide the transaction signer on private send and withdraw
- 15/01/2020 Integrate to Maxbet, standardlize the transaction flow for Dapp.

### TODO
- [] Remove bigi use bn.js instead because of poor documentation and no-longer support
- [] Remove ecurve use elliptic instead because of poor documentation and no-longer support
- [] Support high level api for instantly use: deposit, check balance, withdraw, privatesend - right now just low-level apis for interacting with Smart-contract and generating fields following  the protocol
- [] Support auto RingCT and bullet-proof (with auto select, mix spending utxos, noising array utxos)
- [] Use type flows for helping other developer understand the structure, bytes length of fiels in privacy protocol

Usage
-----

***The fun part of privacy is the client must calculate all the things. Any wrong calculation results in money loss :)***

***Comming Soon - High-level apis comming for instant use***

TEST
---
- [x] Unit test - done
- [x] Smock test - partial implemented for wallet's api
- [x] End to end test on tomochain testnet - cover main flow deposit, withdraw, sendtoprivate

License
-------

MIT
