var mongoose = require('mongoose');
var uniqueValidator = require('mongoose-unique-validator');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var secret = require('../config').secret;

var UserSchema = new mongoose.Schema({
    username: { type: String, lowercase: true, required: [true, "Can't be bank"], match: [/^[a-zA-Z0-9]+$/, 'is invalid'], index: true },
    email: { type: String, lowercase: true, required: [true, "Can't be blank"], match: [/\S+@\S+\.\S+/, 'is invalid'], index: true },
    bio: String,
    image: String,
    favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Article' }],
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    hash: String,
    salt: String
}, { timestamps: true });

UserSchema.plugin(uniqueValidator, { message: "is already taken!" })

UserSchema.methods.setPassword = function (password) {
    this.salt = crypto.randomBytes(16).toString('hex');
    this.hash = crypto.pbkdf2Sync(password, this.salt, 1000, 512, 'sha512').toString('hex');
};

UserSchema.methods.validPassword = function (password) {
    var hash = crypto.pbkdf2Sync(password, this.salt, 1000, 512, 'sha512').toString('hex');
    return this.hash === hash;
};

UserSchema.methods.generateJWT = function () {
    var today = new Date();
    var exp = new Date(today);
    exp.setDate(today.getDate + 60);

    return jwt.sign({
        id: this.id,
        username: this.username,
        exp: parseInt(exp.getTime() / 1000)
    }, secret);
};

UserSchema.methods.toAuthJSON = function () {
    return {
        username: this.username,
        email: this.email,
        token: this.generateJWT,
        bio: this.bio,
        image: this.image
    }
};

UserSchema.methods.toFrofileJSONFor = function (user) {
    return {
        username: this.username,
        bio: this.bio,
        image: this.image || 'https://d2htdayykptdg9.cloudfront.net/sites/550f21d98e6927763a0003dd/content_entry582c570a882534008b009285/5915b878f16b6a008b2da574/files/noname-avatar.jpg',
        following: user ? user.isFollowing(this._id) : false
    }
};

UserSchema.methods.favorite = function (id) {
    if (this.favorites.indexOf(id) === -1) {
        this.favorites.push(id);
    }

    return this.save();
};

UserSchema.methods.unfavorite = function (id) {
    this.favorites.remove(id);
    return this.save();
};

UserSchema.methods.isFavorite = function (id) {
    return this.favorites.some(function (favoriteId) {
        return favoriteId.toString() === id.toString();
    });
};

UserSchema.methods.follow = function (id) {
    if (this.following.indexOf(id) === -1) {
        this.following.push(id);
    }
};

UserSchema.methods.unfollow = function (id) {
    this.following.remove(id);
    return this.save();
};

UserSchema.methods.isFollowing = function (id) {
    return this.following.some(function (followId) {
        return followId.toString() === id.toString();
    });
};

mongoose.model('User', UserSchema);