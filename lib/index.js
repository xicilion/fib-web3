var crypto = require('crypto');
var base64 = require('base64');

var util = require('util');
var vm = require('vm');
var HttpProvider = require('./http-provider');
var http2_constants = require('./http2_constants');

var sbox = new vm.SandBox();
sbox.addBuiltinModules();
sbox.add('http2', {
    constants: http2_constants
});

var Web3 = sbox.require('web3', __dirname);
var secp256k1_1 = sbox.require("ethereum-cryptography/secp256k1", __dirname);

var old_ecdsaSign = secp256k1_1.ecdsaSign;
secp256k1_1.ecdsaSign = function ecdsaSign(msg32, seckey) {
    var sk = crypto.PKey.from({
        "kty": "EC",
        "crv": "secp256k1",
        "d": base64.encode(seckey)
    });

    var sig = sk.sign(msg32, {
        recoverable: true
    });

    var res = {
        signature: sig.slice(0, 64),
        recid: sig[64]
    };

    // var res = old_ecdsaSign(msg32, seckey);

    return res;
}

var old_ecdsaRecover = secp256k1_1.ecdsaRecover;
secp256k1_1.ecdsaRecover = function ecdsaRecover(sig, recid, msg32) {
    var pk = crypto.PKey.recover(msg32, Buffer.concat([sig, Buffer.from([recid])]));
    var res = Uint8Array.from(base64.decode(pk.json({ compress: true }).x));

    // var res = old_ecdsaRecover(sig, recid, msg32);

    return res;
};

function wrap_async_func(mod) {
    for (var k in mod) {
        var m = mod[k];
        if (m && m.request)
            mod[k + '_sync'] = util.sync(m);
    }
}

function Web3_wrap() {
    var web3 = new Web3(...arguments);

    wrap_async_func(web3.eth);
    wrap_async_func(web3.shh);

    web3.eth.accounts.signTransaction_sync = util.sync(web3.eth.accounts.signTransaction);

    return web3;
}

for (var k in Web3)
    Web3_wrap[k] = Web3[k];

Web3_wrap.providers.HttpProvider = HttpProvider;

module.exports = Web3_wrap;
