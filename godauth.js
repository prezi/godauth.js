"use strict";

var util = require("util"),
    crypto = require('crypto');

function GodAuth(cookie_secret, url) {

    this._sha1sum = function (str) {
        var shasum = crypto.createHash('sha1');
        shasum.update(str);
        return shasum.digest('hex');
    }

    this._cleanUserAgent = function (agentStr) {
        if (/[\w\W]*AppleWebKit[\w\W]*/.test(agentStr)) {
            return "StupidAppleWebkitHacksGRRR";
        }
        return agentStr;
    }

    this.authenticate = function (email, roles, timestamp, signature, userAgent) {
        var rawCookie = util.format("%s-%s-%s-%s", email, roles, timestamp, this._cleanUserAgent(userAgent)),
            signatureBase = this._secret + rawCookie,
            computedSignature = this._sha1sum(signatureBase),
            currentTime = new Date().getTime() / 1000;

        timestamp = parseInt(timestamp, 10);

        if (computedSignature !== signature) {
            return null;
        }


        if (timestamp < currentTime - 8 * 60 * 60) {
            return null;
        }

        if (timestamp > currentTime + 5 * 60) {
            return null;
        }

        return {
            'email': email,
            'roles': roles,
            'timestamp': timestamp,
            'signature': signature
        };
    }

    this.authenticateCookie = function (cookieValue, userAgent) {
        var match = /^([\w\W]+)\-([a-zA-Z0-9]+)\-([0-9]+)\-([a-z0-9]+)$/.exec(cookieValue);

        if (!match || match.length < 5) {
            return null;
        }
        return this.authenticate(match[1], match[2], match[3], match[4], userAgent);
    }

    this.authenticateRequest = function (request, response) {
        var cookies = {},
            auth,
            authToken;

        if (request.headers.cookie) {
            request.headers.cookie.split(';').forEach(
                function (cookie) {
                    var parts = cookie.split('=');
                    cookies[parts[0].trim()] = (parts[1] || '').trim();
                }
            );
        }

        if (!cookies.authtoken) {
            auth = null;
        } else {
            authToken = cookies.authtoken.replace(/^"+|"+$/g, '');
            auth = this.authenticateCookie(authToken, request.headers["user-agent"]);
        }

        if (auth === null) {
            response.writeHead(302, {
                Location: 'https://prezi.com/api/v2/auth/godauth/?ref=' + encodeURIComponent(this._url)
            });
            response.end();
        }

        return auth;
    }

    this._secret = cookie_secret;
    this._url = url;
}

module.exports.create = function (cookie_secret, url) {
    return new GodAuth(cookie_secret, url);
};
