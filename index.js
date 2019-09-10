var assert = require('assert')
var Stealth = require('./').stealth
var Address = require('./').address
var crypto = require('./lib/crypto')
var fixtures = require('./test/fixtures')

// receiver info
let keys = Address.generateKeys("f67213b122a5d442d2b93bda8cc45c564a70ec5d2a4e0e95bb585cf199869c98")
console.log(keys)

//sender info
keys = Address.generateKeys("f8c02a45667e1390e9702876dd4dc6c0066e49b5cdaa6ec1c83e7d88be92e2e2")
console.log(keys)