
var _ = require('lodash');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var Q = require('q');

var mongo = require('mongoskin');
var db = mongo.db('mongodb://demo:demo@demo:27017/demo', {native_parser:true});

db.bind('users');
db.bind('sessionlog');

var service = {};

var live = [];

service.authenticate = authenticate;
service.getById = getById;
service.create = create;
service.update = update;
service.delete = _delete;

service.loggedIn = _loggedIn;
service.logout = _loggedOut;

service.sessionById = sessionById;
service.getSessionByUserId = getSessionByUserId;
service.getLastSessionByUserId = getLastSessionByUserId;

module.exports = service;

function authenticate( email, password , params) {

    var deferred = Q.defer();

    db.users.findOne({ email: email }, function (err, user) {

        if (err) deferred.reject(err.name + ': ' + err.message);

        if (user && bcrypt.compareSync(password, user.hash)) {
            
            // authentication successful
            var token = deferred.resolve(jwt.sign({ sub: user._id },"node"));

            params.user_id=user._id;
            // Login Entry 
            _loggedIn(params);

        } else {

            // authentication failed
            deferred.resolve();
        }
    });

    return deferred.promise;
}


function getById(_id) {

    var deferred = Q.defer();

    db.users.findById(_id,
        function (err,user) {

            if (err){
                deferred.reject(err.name + ': ' + err.message);
            }else
            {

                db.sessionlog.find({ user_id : mongo.helper.toObjectID(_id)}).sort({ login_at : -1 }).limit(2).toArray(function(err,sess){
                    
                    if(sess[1] != undefined){
                        user.lastSession = sess[1];
                    }else{
                        user.lastSession = sess[0];
                    }

                    user.live = live;

                    db.sessionlog.find({user_id : mongo.helper.toObjectID(_id),session:{'$in':live }}).sort({ login_at : -1 }).toArray(function(err,sessions){
                    
                        user.liveSession = sessions;

                        deferred.resolve(_.omit(user));

                    });

                });

            }
    });

    return deferred.promise;
}

function getSessionByUserId(_id) {

    var deferred = Q.defer();

    db.sessionlog.find({ user_id : mongo.helper.toObjectID( user._id)}).sort({ login_at : -1 }).toArray(function(err,sess){
        deferred.resolve(_.omit(sess));
    });

    return deferred.promise;
}

function getLastSessionByUserId(_id) {

    var deferred = Q.defer();

    db.sessionlog.find({ user_id : mongo.helper.toObjectID( user._id)}).sort({ login_at : -1 }).limit(1).toArray(function(err,sess){
        deferred.resolve(_.omit(sess[0]));
    });

    return deferred.promise;
}


function create(userParam) {
    var deferred = Q.defer();

    // validation
    db.users.findOne(
        { email: userParam.email },
        function (err, user) {
            if (err) deferred.reject(err.name + ': ' + err.message);

            if (user) {
                // email already exists
                deferred.reject('email "' + userParam.email + '" is already taken');
            } else {
                createUser();
            }
        });

    function createUser() {
        // set user object to userParam without the cleartext password
        var user = _.omit(userParam, 'password');

        // add hashed password to user object
        user.hash = bcrypt.hashSync(userParam.password, 10);

        user.created_at = Date.now();

        db.users.insert(
            user,
            function (err, doc) {
                if (err) deferred.reject(err.name + ': ' + err.message);

                deferred.resolve();
        });
    }

    return deferred.promise;
}

function update(_id, userParam) {
    var deferred = Q.defer();

    // validation
    db.users.findById(_id, function (err, user) {
        if (err) deferred.reject(err.name + ': ' + err.message);

        if (user.email !== userParam.email) {
            // email has changed so check if the new email is already taken
            db.users.findOne(
                { email: userParam.email },
                function (err, user) {
                    if (err) deferred.reject(err.name + ': ' + err.message);

                    if (user) {
                        // email already exists
                        deferred.reject('Username "' + req.body.email + '" is already taken')
                    } else {
                        updateUser();
                    }
                });
        } else {
            updateUser();
        }
    });

    function updateUser() {
        // fields to update
        var set = {
            username: userParam.username,
            email: userParam.email,
            contact: userParam.contact,

        };

        // update password if it was entered
        if (userParam.password) {
            set.hash = bcrypt.hashSync(userParam.password, 10);
        }

        db.users.update(
            { _id: mongo.helper.toObjectID(_id) },
            { $set: set },
            function (err, doc) {
                if (err) deferred.reject(err.name + ': ' + err.message);

                deferred.resolve();
            });
    }

    return deferred.promise;
}

function _delete(_id) {
    var deferred = Q.defer();

    db.users.remove(
        { _id: mongo.helper.toObjectID(_id) },
        function (err) {
            if (err) deferred.reject(err.name + ': ' + err.message);
            deferred.resolve();
        });

    return deferred.promise;
}

function _loggedIn(param) {

    var deferred = Q.defer();

    param.login_at = Date.now();
    param.logout_at  = null;

    db.sessionlog.insert(
        param,
        function (err) {
            if (err) deferred.reject(err.name + ': ' + err.message);
            deferred.resolve();
        });

    live.push(param.session);

    console.log('session ( ' + param.session + ' ) now started');

    console.log('user login time updated');

    return deferred.promise;
}



function _loggedOut(session) {

    var deferred = Q.defer();

        db.sessionlog.update(
            { session : session },
            { $set: { logout_at: Date.now() }},
            { multi : true },
            function (err, doc) {
                if (err) deferred.reject(err.name + ': ' + err.message);
                deferred.resolve();

                remove(session);

                function remove(session) {
                    var i = live.indexOf(session);
                    return live.indexOf(session)>-1 ? live.splice(i, 1) : [];
                };

                console.log('session ( ' + session + ' ) expired');

                console.log('user logout time updated');

            });

    return deferred.promise;

}

function sessionById(_id) {

    var deferred = Q.defer();

    db.sessionlog.findById(_id, function (err, sess) {
        if (err) deferred.reject(err.name + ': ' + err.message);

        if (sess) {
            // return user (without hashed password)
            deferred.resolve(_.omit(sess));
        } else {
            // user not found
            deferred.resolve();
        }
    });

    return deferred.promise;
}
