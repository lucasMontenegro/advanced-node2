'use strict';

const express       = require('express');
const bodyParser    = require('body-parser');
const fccTesting    = require('./freeCodeCamp/fcctesting.js');
const mongo         = require('mongodb').MongoClient;
const passport      = require('passport');
const session       = require('express-session');
const ObjectID      = require('mongodb').ObjectID;
const LocalStrategy = require('passport-local');
const bcrypt        = require('bcrypt');

function ensureAuthenticated (req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/');
}

const app = express();
app.set('view engine', 'pug');

fccTesting(app); //For FCC testing purposes
app.use('/public', express.static(process.cwd() + '/public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

if (process.env.ENABLE_DEBUGGING == 'true') {
  let count = 0;
  app.use((req, res, next) => {
    count++;
    let str = count + ' ' + req.method + ' ' + req.url;
    console.log('\nNew request:\n' + str);
    console.log(req.body);
    res.on('finish', () => console.log('\nRequest ended:\n' + str));
    next();
  });
}

// Enable to pass the challenge called "Advanced Node and Express - 
// Registration of New Users"
if (process.env.ENABLE_DELAYS) app.use((req, res, next) => {
  switch (req.method) {
    case 'GET':
      switch (req.url) {
        case '/logout': return setTimeout(() => next(), 500);
        case '/profile': return setTimeout(() => next(), 700);
        default: next();
      }
    break;
    case 'POST':
      switch (req.url) {
        case '/login': return setTimeout(() => next(), 900);
        default: next();
      }
    break;
    default: next();
  }
});

mongo.connect(process.env.DATABASE, (err, connection) => {
  if (err) console.log('Database error: ' + err);
  else {
    console.log('Successful database connection');
    const db = connection.db();

  app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
  }));
  app.use(passport.initialize());
  app.use(passport.session());
  passport.serializeUser((user, done) => done(null, user._id));

  passport.deserializeUser((id, done) => {
    db.collection('users').findOne(
      {_id: new ObjectID(id)},
      (err, doc) => done(null, doc)
    );
  });

  passport.use(new LocalStrategy((username, password, done) => {
    db.collection('users').findOne(
      { username: username },
      (err, user) => {
        if (err) return done(err);
        if (!user) return done(null, false);
        if (!bcrypt.compare(password, user.password)) {
          return done(null, false);
        }
        return done(null, user);
      }
    );
  }));

    app.route('/').get((req, res) => res.render(
      process.cwd() + '/views/pug/index.pug',
      {
        title: 'Hello',
        message: 'Please login',
        showLogin: true,
        showRegistration: true
      }
    ));

    app.route('/login').post(
      passport.authenticate('local', { failureRedirect: '/' }),
      (req, res) => res.redirect('/profile')
    );

    app.route('/profile').get(
      ensureAuthenticated,
      (req, res) => res.render(
        process.cwd() + '/views/pug/profile',
        {username: req.user.username}
      )
    );

    app.route('/logout').get((req, res) => {
      req.logout();
      res.redirect('/');
    });

    app.route('/register').post(
      (req, res, next) => db.collection('users').findOne(
        { username: req.body.username },
        (err, user) => {
          if (err) next(err);
          else if (user) res.redirect('/');
          else db.collection('users').insertOne(
            {
              username: req.body.username,
              password: bcrypt.hash(req.body.password, 12)
            },
            (err, user) => {
              if (err) res.redirect('/');
              else next();
            }
          );
        }
      ),
      passport.authenticate('local', {
        successRedirect: '/profile',
        failureRedirect: '/'
      })
    );

    app.use((req, res, next) => {
      res.status(404).type('text').send('Not Found');
    });

    app.listen(process.env.PORT || 3000, () => {
      console.log("Listening on port " + process.env.PORT);
    });
  }
});
