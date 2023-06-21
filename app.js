// Import required packages
const dotenv = require('dotenv').config({ path: __dirname + '/.env' });
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const port = 3000;
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const app = express();
const findOrCreate = require("mongoose-findorcreate");

// Set up static files and view engine
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// Set up session middleware
app.use(session({
    secret: "our little secret.",
    resave: false,
    saveUninitialized: false
}));

// Initialize Passport and use session middleware
app.use(passport.initialize());
app.use(passport.session());

// Connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/userDB");

// Define user schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// Use passport-local-mongoose plugin for user schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Create User model
const User = new mongoose.model("User", userSchema);

// Set up passport strategies for serialization and deserialization

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
    
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
}
));

// Home route
app.get("/", function(req, res) {
    res.render("home");
});

app.get("/auth/google", 
passport.authenticate("google", {scope: ["profile"]})
)

app.get("/auth/google/secrets", 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
});

// Login route
app.route("/login")
.get(function(req, res) {
    res.render("login");
})
.post((req, res) => {
    const newUser = new User({
        username: req.body.username,
        password: req.body.password
    });
    try {
        req.login(newUser, (err) => {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, function() {
                    res.redirect("/secrets");
                });
            }
        });
    } catch (err) {
        console.log(err);
    }
});

// Secrets route
app.get('/secrets', async (req, res) => {
    try {
        const foundUsers = await User.find({"secret": {$ne: null}});
        if (foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    } catch (err) {
        console.log(err);
    }
});

// Submit route
app.route('/submit')
.get((req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect('/login');
    }
})
.post(async function(req, res) {
    const submittedSecret = req.body.secret;

    console.log(req.user.id);

    try {
        const foundUser = await User.findById(req.user.id);
        if (foundUser) {
            foundUser.secret = submittedSecret;
            await foundUser.save();
            res.redirect("/secrets");
        }
    } catch (err) {
        console.log(err);
    }
});


// Logout route
app.get('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});


// Register route
app.route("/register")
.get(function(req, res) {
    res.render("register");
})
.post(async function(req, res) {
    const username = req.body.username;
    const password = req.body.password;
    User.register({ username: username }, password).then(() => {
        const authenticate = passport.authenticate("local");
        authenticate(req, res, () => {
            res.redirect('/secrets');
        });
    }).catch(err => {
        console.log(err);
        res.redirect("/register");
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
