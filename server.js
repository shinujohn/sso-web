var express = require('express');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var path = require('path');
var adal = require('adal-node');
var crypto = require('crypto');
var proxySecurity = require('./ProxySecurity');

var server = express();

server.use(cookieParser());

server.set('views', __dirname + '/public/views');
server.engine('html', require('ejs').renderFile);
server.set('view engine', 'ejs');

server.use(session({
    name: 'session',
    secret: 'd26fb56d-aa1f-4722-a892-0788557021ba',
    rolling : true, 
    resave: false,
    saveUninitialized: true
}));

/*
 * General configuration
 */
// app name: aadonesc-web
var config = {
    tenant: 'aadonesc.onmicrosoft.com',
    loginUrl: 'https://login.windows.net',
    clientId: 'a4eb9cad-1631-4a4f-a799-ce29ff568157',
    clientSecret: 'ikWO5pcpv/LjWCKwg0IIjuPSlsKb55zoizdIvVg7RWc=',
    port: 8788,
    redirectUrl: 'http://localhost:8787/auth/token' ,
    resource: '00000002-0000-0000-c000-000000000000',
    azureUrl: 'https://login.windows.net/{{tenant}}/oauth2/authorize?response_type=code&client_id={{clientId}}&redirect_uri={{redirectUri}}&resource={{resource}}',
    apiBaseUrl: 'http://localhost:8788'
};

/*
 * Azure AD login
 */
var AuthenticationContext = adal.AuthenticationContext;
var loginUrl = (process.env.loginUrl || config.loginUrl) + '/' + (process.env.tenant || config.tenant);
var redirectUri = (process.env.redirectUrl || config.redirectUrl);
var resource = (process.env.resource || config.resource);

var azureUrl = (process.env.azureUrl || config.azureUrl);
azureUrl = azureUrl.replace('{{tenant}}', (process.env.tenant || config.tenant))
            .replace('{{clientId}}', (process.env.clientId || config.clientId))
            .replace('{{redirectUri}}', redirectUri)
            .replace('{{resource}}', resource);

/*
 * Login request handler - redirects to the Azure AD signin page 
 */
server.get('/auth/login', function (req, res) {
    crypto.randomBytes(48, function (ex, buf) {
        var state = buf.toString('base64').replace(/\//g, '_').replace(/\+/g, '-');
        
        res.cookie('state', state);
        res.redirect(azureUrl + '&state=' + state);
    });
    
});

/*
 * Handler to recieve the token from API once successfully authenticated
 */
server.get('/auth/token', function (req, res) {
    // TODO:
    if (req.cookies.state !== req.query.state) {
        res.send('error: state does not match');
    }
    
    proxySecurity.getAccessToken(req.query.code).then(function (accessToken) {
        res.cookie('auth', accessToken);
        res.redirect((process.env.apiBaseUrl || config.apiBaseUrl) + '/auth/login'); //to authenticate apigateway
    }).catch(function (err) {
        res.send(err);
    });
 
});

/*
 * Middleware to validate user context/authentication status
 */
server.use(function (req, res, next) {
    if (req.cookies.auth && proxySecurity.validateToken(req.cookies.auth)) {
        next();
    }
    else {
        res.redirect('/auth/login');
    }
});

/*
 * Root
 */
server.get('/', function (req, res) {
    res.render('./index.html', { title: 'Express' });
});

/*
 * Returns general configuration data
 */
server.get('/config', function (req, res) {
    res.send({
        apiBaseUrl: (process.env.apiBaseUrl || config.apiBaseUrl)
    });
});


server.listen(process.env.port || 8787, function () {
    console.log('Webapp started');
});

// private utility
function parseUserDataFromToken(token) {
    return (new Buffer(token.split('.')[0], 'base64')).toString('ascii');
}