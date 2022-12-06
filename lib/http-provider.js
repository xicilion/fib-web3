var errors = require('web3-core-helpers').errors;
var http = require('http');

var HttpProvider = function HttpProvider(host, options) {
    options = options || {};
    this.headers = options.headers;
    this.host = host || 'http://localhost:8545';
    this.httpsAgent = new http.Client();
};

HttpProvider.prototype.send = function (payload, callback) {
    var options = {
        json: payload
    };
    var headers = {};

    if (this.headers)
        this.headers.forEach(header => headers[header.name] = header.value);

    if (!headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }
    options.headers = headers;

    var o = this;
    this.httpsAgent.post(this.host, options, function (err, result) {
        if (err)
            return callback(errors.InvalidConnection(o.host));

        try {
            callback(null, result.json());
        } catch (e) {
            callback(errors.InvalidResponse(result.data.toString()));
        }
    });
};

HttpProvider.prototype.disconnect = function () { };
HttpProvider.prototype.supportsSubscriptions = function () { };

module.exports = HttpProvider;
