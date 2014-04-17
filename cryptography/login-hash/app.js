var express = require('express');
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var serveStatic = require('serve-static');

var cryptauth = require('./cryptauth');

var app = express();
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(serveStatic(path.join(__dirname, 'public')));

app.get('/users', function(req, res) {

    res.status(200);
    res.send(cryptauth.users());

});

app.post('/auth', function(req, res) {

    var register = req.body.register;
    var username = req.body.username;
    var password = req.body.password;

    if (register)
    {
        cryptauth.register(username, password);

        res.status(200);
        res.send({
            error: false,
            message: 'Registered ' + username + ' with password ' + password
        });
    }
    else
    {
        if (cryptauth.authenticate(username, password))
        {
            res.status(200);
            res.send({
                error: false,
                message: 'Authenticated as ' + username
            });
        }
        else
        {
            res.send({
                error: true,
                message: 'Invalid username or password!'
            });
        }
    }

});

var port = 8080;
app.listen(port, function() {
    console.log('Server started on port ' + port);
});


module.exports = app;
