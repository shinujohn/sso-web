
var adal = require('adal-node');
var q = require('q');
var crypto = require('crypto');
var fs = require("fs");

var ProxySecurity = function () {
    
    /*
    * General configuration
    */
    var config = {
        tenant: 'aadonesc.onmicrosoft.com',
        loginUrl: 'https://login.windows.net',
        clientId: 'c5d1f887-0348-42e2-9f49-cdc733af53ef',
        clientSecret: 'ihtijQhEkdwvoZGPbjg3QXbNMzrEiS64g2cfvIRZc7Y='
    };
    
    ///* NOT USED IN WEBAPP
    
    
    // * Retrieves the access token for the given key from Azure AD
    // */
    //this.getAccessToken = function (key) {
    //    var deferred = q.defer();
    
    //    var AuthenticationContext = adal.AuthenticationContext;
    //    var loginUrl = (process.env.loginUrl || config.loginUrl) + '/' + (process.env.tenant || config.tenant);
    
    //    var redirectUri = (process.env.redirectUrl || config.redirectUrl);
    //    var resource = (process.env.resource || config.resource);
    
    //    var authenticationContext = new AuthenticationContext(loginUrl);
    //    authenticationContext.acquireTokenWithAuthorizationCode(
    //        key, 
    //        redirectUri, 
    //        resource, 
    //        (process.env.clientId || config.clientId), 
    //        (process.env.clientSecret || config.clientSecret), 
    //        function (err, response) {
    //            if (!err) {
    //                var claimsToken = getClaimsToken(response.userId);
    //                var signedToken = signJSON(claimsToken);
    //                deferred.resolve(signedToken);
    //            }
    //            else {
    //                deferred.reject(err);
    //            }
    //        });
    
    //    return deferred.promise;
    //}
    
    /**
     * Validates the signature of the token
     */
    this.validateToken = function (token) {
        var data = token.split('.')[0];
        var signature = token.split('.')[1];
        var publickey = fs.readFileSync('osc.pub').toString();
        
        var isValid = crypto.createVerify('RSA-SHA256').update(data).verify(publickey, signature, 'base64');
        return isValid;
    }
    
    ///* NOT USED IN WEBAPP
    // * Sign
    // */
    //function signJSON(jsonString) {
    //    var privatekey = fs.readFileSync('osc.pem').toString();
    //    var data = new Buffer(JSON.stringify(jsonString)).toString('base64');
    //    var signature = crypto.createSign('RSA-SHA256').update(data).sign(privatekey, 'base64');
    //    return data + '.' + signature;
    //}
    
    //// Test data
    //// This will be returned by the organisation service
    //function getClaimsToken(userId) {
    //    return {
    //        'userId': userId,
    //        'roles': ['admin', 'socialworker']
    //    };
    //}
}

module.exports = new ProxySecurity();