require('isomorphic-fetch');
require('./wasm_exec');
const path = require('path');
const fs = require('fs');

// load WASM
let isWASMRunned = false;
const fileName = path.resolve(path.dirname('./wasm/privacy.wasm'), 'privacy.wasm');

if (!String.prototype.splice) {
    /**
     * {JSDoc}
     *
     * The splice() method changes the content of a string by removing a range of
     * characters and/or adding new characters.
     *
     * @this {String}
     * @param {number} start Index at which to start changing the string.
     * @param {number} delCount An integer indicating the number of old chars to remove.
     * @param {string} newSubStr The String that is spliced in.
     * @return {string} A new string with the spliced substring.
     */
    String.prototype.splice = function(start, delCount, newSubStr) {
        return this.slice(0, start) + newSubStr + this.slice(start + Math.abs(delCount));
    };
}

function loadWASM() {
    return new Promise((resolve, reject) => {
        if (isWASMRunned) {
            console.info('WASM was loaded');
            return resolve();
        }

        // eslint-disable-next-line
        const go = new Go();
        let inst;
        const data = fs.readFileSync(fileName);

        WebAssembly.instantiate(data, go.importObject).then((result) => {
            inst = result.instance;
            isWASMRunned = true;
            go.run(inst)
            
            resolve();
        }).catch((ex) => {
            console.log(ex)
            reject(ex);
        });
    });
}

module.exports = loadWASM;
