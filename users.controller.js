
var express = require('express');
var router = express.Router();
var userService = require('./user.service');

// routes
router.post('/authenticate', authenticateUser);
router.post('/register', registerUser);
router.get('/current', getCurrentUser);
router.get('/', getCurrentUser);
router.put('/:_id', updateUser);
router.delete('/:_id', deleteUser);

router.post('/logout', logoutUser);

module.exports = router;

function authenticateUser(req, res) {

    var params = {
        session : req.body.session,
        ua : JSON.parse(req.body.ua)
    };

    userService.authenticate(req.body.email, req.body.password, params)
        .then(function(token) {
            if (token) {
                // authentication successful
                res.send({ token: token });
            } else {
                // authentication failed
                res.status(401).send('Username or password is incorrect');
            }
        })
        .catch(function(err) {
            res.status(400).send(err);
        });
}

function registerUser(req, res) {
    userService.create(req.body)
        .then(function() {
            res.sendStatus(200);
        })
        .catch(function(err) {
            res.status(400).send(err);
        });
}

function getCurrentUser(req, res) {
    userService.getById(req.user.sub)
        .then(function(user) {
            if (user) {
                res.send(user);
            } else {
                res.sendStatus(404);
            }
        })
        .catch(function(err) {
            res.status(400).send(err);
        });
}

function getLastSession(req, res) {
    userService.getLastSessionByUserId(req.user.sub)
        .then(function(sess) {
            if (sess) {
                res.send(sess);
            } else {
                res.sendStatus(404);
            }
        })
        .catch(function(err) {
            res.status(400).send(err);
        });
}


function updateUser(req, res) {
    var userId = req.user.sub;
    if (req.params._id !== userId) {
        // can only update own account
        return res.status(401).send('You can only update your own account');
    }

    userService.update(userId, req.body)
        .then(function() {
            res.sendStatus(200);
        })
        .catch(function(err) {
            res.status(400).send(err);
        });
}

function deleteUser(req, res) {
    var userId = req.user.sub;
    if (req.params._id !== userId) {
        // can only delete own account
        return res.status(401).send('You can only delete your own account');
    }

    userService.delete(userId)
        .then(function() {
            res.sendStatus(200);
        })
        .catch(function(err) {
            res.status(400).send(err);
        });
}

function logoutUser(req, res) {

    if(req.body.session !== undefined){

        userService.logout(req.body.session )
            .then(function() {
                
                res.status(401).send('User logged out sucessfully.');
            })
            .catch(function(err) {
                res.status(400).send(err);
        });

    }else{

        console.log('logout session not found');

        res.status(400);
    }
}