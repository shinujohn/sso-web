var express = require('express');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var path = require('path');
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
 * loginUrl: application will be redirected to this url if the request is not authenticated
 */
var config = {
    loginUrl: "http://localhost:8788/auth/login"

};

/*
 * Handler to recieve the token from API once successfully authenticated
 */
server.get('/auth', function (req, res) {
    var token = req.query.token;
    if (token) {
        res.cookie('auth', token);
        req.user = parseUserDataFromToken(token);
        session.user = parseUserDataFromToken(token);
        res.redirect('/');
    }
    else {
        res.send('error - token not recieved');
    }
});

/*
 * Middleware to validate user context/authentication status
 */
server.use(function (req, res, next) {
    if (req.cookies.auth && proxySecurity.validateToken(req.cookies.auth)) {
        next();
    }
    else {
        res.redirect(process.env.loginUrl || config.loginUrl);
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
        apiBaseUrl: (process.env.apiBaseUrl || 'http://localhost:8788')
    });
});


server.listen(process.env.port || 8787, function () {
    console.log('Webapp started');
});

// private utility
function parseUserDataFromToken(token) {
    return (new Buffer(token.split('.')[0], 'base64')).toString('ascii');
}