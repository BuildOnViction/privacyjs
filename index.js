// mask before sending to sc  8f1e7b29d3f926a47bf91d51186252ee5fa47699f8760b981758fdeb9f9ecc33
// proof.mask  8f1e7b29d3f926a47bf91d51186252ee5fa47699f8760b981758fdeb9f9ecc33
// amount  1000000000000000000
// this.genCommitment(amount, mask).toString('hex')  036a90d565dc082f6df7eb844d9bff5efc823faf994dc9475327e14d8ce99f1c98
// lfCommitment.getEncoded(true).toString('hex')  030b717d06585502d5234d1f6280d79311e5f444b658c553687ac1df73dff1b579
// 04ba00c453c3bf58141df6dbc70e97da06b8452fb6a56f66e4d89832f85f5b5da0c32aea5f7edeb83390267c11d992d9cde99d68ed9fb2992c3562ae25d31650e1
// var pedersen = require('pedersen-commitments');
var commitment = require('./src/commitment');

console.log(commitment.genCommitment(1000000000000000000, '8451ba3e40029568d82c9d78501535e5968b515c4efea552e7612ac90b854f45', false).toString('hex'));