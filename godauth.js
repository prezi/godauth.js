"use strict";
var util = require("util"),
    crypto = require('crypto'),
    shasum = crypto.createHash('sha1');


if (typeof process.env.GODAUTH_COOKIE_SECRET === "undefined") {
    console.error("Can't find environmental variable GODAUTH_COOKIE_SECRET");
    process.exit(101);
}
var godauthCookieSecret = process.env.GODAUTH_COOKIE_SECRET;

function sha1sum(str) {
	shasum.update(str);
	return shasum.digest('hex');
}

function cleanUserAgent(agentStr) {
	if (/[\w\W]*AppleWebKit[\w\W]*/.test(agentStr)) {
		return "StupidAppleWebkitHacksGRRR";
	}
	return agentStr;
}

function authenticate(email, roles, timestamp, signature, userAgent) {
	var rawCookie = util.format("%s-%s-%s-%s", email, roles, timestamp, cleanUserAgent(userAgent)),
	    signatureBase = godauthCookieSecret + rawCookie,
	    computedSignature = sha1sum(signatureBase),
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

function authenticateCookie(cookieValue, userAgent) {
	var match = /^([\w\W]+)\-([a-zA-Z0-9]+)\-([0-9]+)\-([a-z0-9]+)$/.exec(cookieValue);
	if (match.length < 5) {
		return null;
	}
	return authenticate(match[1], match[2], match[3], match[4], userAgent);
}

function authenticateRequest(request, response) {
    var cookies = {},
        auth;

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
		auth = authenticateCookie(cookies.authtoken, request.headers["user-agent"]);
	}

	if (auth === null) {
		response.writeHead(301,
			{ Location: 'https://prezi.com/api/v2/auth/godauth/?ref=' + encodeURIComponent(request.url) }
			);
		response.end();
		return null;
	}
}

exports.authenticate = authenticate;
exports.authenticateCookie = authenticateCookie;
exports.authenticateRequest = authenticateRequest;
