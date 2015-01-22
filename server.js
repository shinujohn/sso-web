var express = require('express');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var path = require('path');
var adal = require('adal-node');
var crypto = require('crypto');
var proxySecurity = require('./ProxySecurity');
var expressJwt = require('express-jwt');
var jwt = require('jsonwebtoken');

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
    azureSignoutUrl: 'https://login.windows.net/{{tenant}}/oauth2/logout?client_id={{clientId}}&post_logout_redirect_uri={{redirectUri}}', 
    apiBaseUrl: 'http://localhost:8788',
    apiLogoutUrl: 'http://localhost:8788/auth/logout'
};

/*
 * Azure AD login
 */
var AuthenticationContext = adal.AuthenticationContext;
var loginUrl = (process.env.loginUrl || config.loginUrl) + '/' + (process.env.tenant || config.tenant);
var redirectUri = (process.env.redirectUrl || config.redirectUrl);
var resource = (process.env.resource || config.resource);
var secret = "cantguessme";

var azureUrl = (process.env.azureUrl || config.azureUrl);
azureUrl = azureUrl.replace('{{tenant}}', (process.env.tenant || config.tenant))
            .replace('{{clientId}}', (process.env.clientId || config.clientId))
            .replace('{{redirectUri}}', redirectUri)
            .replace('{{resource}}', resource);

var azureSignoutUrl = (process.env.azureSignoutUrl || config.azureSignoutUrl);
azureSignoutUrl = azureSignoutUrl.replace('{{tenant}}', (process.env.tenant || config.tenant))
            .replace('{{clientId}}', (process.env.clientId || config.clientId))
            .replace('{{redirectUri}}', (process.env.apiLogoutUrl || config.apiLogoutUrl));

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
 * logout request handler - redirects to the Azure AD signout page 
 */
server.get('/auth/logout', function (req, res) {
    req.session.destroy(function (err) {
        console.error(err);
    });
    
    res.clearCookie('auth');
    res.clearCookie('state');
    res.redirect(azureSignoutUrl);
});

/*
 * Handler to recieve the token from API once successfully authenticated
 */
server.get('/auth/token', function (req, res) {
    // TODO:
    if (req.cookies.state !== req.query.state) {
        res.send('error: state does not match');
    }
    
    res.clearCookie('state');
    res.cookie('key', req.query.code);
    res.render('./auth.html', { title: 'Authenticating...' });
});

/*
 * Handler to recieve the token from API once successfully authenticated
 */
server.get('/auth/osctoken', function (req, res) {
    
    proxySecurity.getAccessToken(req.cookies.key).then(function (accessToken) {
        console.log(accessToken);
        res.clearCookie('key');
        
        accessToken = jwt.sign(accessToken, secret, { expiresInMinutes: 60 * 5 });
        res.cookie('auth', accessToken);
        res.setHeader("Authorization", "Bearer " + accessToken);
        res.send(accessToken);
    }).catch(function (err) {
        console.error(err);
        res.send(err);
    });
 
});

/*
 * Middleware to validate user context/authentication status
 */
server.use(function (req, res, next) {
    if (req.cookies.auth) {
        var result = jwt.verify(req.cookies.auth, secret, function (err, currentUser) {
            if (!err && currentUser != null && currentUser.userId.length > 0) {
                req.user = currentUser;
                next();
            }
            else {
                res.redirect('/auth/login');
            }
        });
        
    }
    else {
        res.redirect('/auth/login');
    }
});


/*
 * Root
 */
server.get('/', function (req, res) {
    console.log(req.user);
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

