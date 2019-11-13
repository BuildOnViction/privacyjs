// encoding  0de0b6b3a7640000
// ab38d758e4c36a3ef80a2327adaa5fd106d44ef60659ba903fa802fdd52dfb7e
// encoding  00d9c1af37e36050209a02dafe4ebaffa16f344d7070bcf35b621584017a8b90
// ac1299081ca6ca8f18a42602abf91ad0a843834376ca77838d2961ce2f44870e
// encryptedMask  ac1299081ca6ca8f18a42602abf91ad0a843834376ca77838d2961ce2f44870e
// proof.encryptedMask before sending ...  ac1299081ca6ca8f18a42602abf91ad0a843834376ca77838d2961ce2f44870e
// decoding  ab38d758e4c36a3ef80a2327adaa5fd106d44ef60659ba903fa802fdd52dfb7e
// decoding  ac1299081ca6ca8f18a42602abf91ad0a843834376ca77838d2961ce2f44870e

// -----------------------------------------------------------------
// encoding  0de0b6b3a7640000
// ec8e9fb6c66edcacfd1b8363253092c81c13895174c1e3c83e1ebf2860b2fb5e
// encoding  00ac53e377b6e083970e9f1e2210edb72f46a8f559f505bd706679fd758d7dcc
// ed3af39a3e25bd30942a22814741807f4b5a3246ceb6e985a0a482722edc792a
// encryptedMask  ed3af39a3e25bd30942a22814741807f4b5a3246ceb6e985a0a482722edc792a
// proof.encryptedMask before sending ...  ed3af39a3e25bd30942a22814741807f4b5a3246ceb6e985a0a482722edc792a
// decoding  ec8e9fb6c66edcacfd1b8363253092c81c13895174c1e3c83e1ebf2860b2fb5e
// decoding  ed3af39a3e25bd30942a22814741807f4b5a3246ceb6e985a0a482722edc792a

const crypto = require('./src/crypto');

let t1 = crypto.BigInteger.fromHex('ac1299081ca6ca8f18a42602abf91ad0a843834376ca77838d2961ce2f44870e');
// get password's md5 hash
