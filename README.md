godauth.js
==========

Internal SSO verification tool for Prezi's GodAuth service

Prerequisites
-------------

You will need a https server to use *godauth.js*:

 1. Include the *openssl* chef cookbook on the server hosting your Node.js app.
 2. Initialize the https server with the following options:
        
    {
        key: fs.readFileSync('/etc/ssl/private/*.prezi.com.key'),
        cert: fs.readFileSync('/etc/ssl/private/*.prezi.com.crt')
    };

Installation
------------

    npm install prezi-godauth

Usage example
-------------

    var godAuth = require("prezi-godauth");
    
    // _settings.godAuthSecret is the godauth cookie secret string
    var authenticator = godAuth.create(_settings.godAuthSecret);
    
    // You can either authenticate a HTTP request
    authSuccess = authenticator.authenticateRequest(request, response);
    
    // Or authenticate by providing the credentials manually
    authSuccess = authenticateCookie(authtokenCookieValue, userAgentString);

In case of successful authentication the functions will return a dictionary with the
following keys:

 * email
 * roles
 * timestamp
 * signature

In case of unsuccessful authentication the return value is `null`. If you are using the `authenticateRequest` 
function, a redirect to the prezi login page is done automatically.
