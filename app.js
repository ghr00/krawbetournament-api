const express = require('express')
const app = express()

const crypto = require('crypto');
const expressjwt = require('express-jwt');
const jwt = require('jsonwebtoken');
require('dotenv').config()

console.log('secret:' + process.env.SECRET)
const hash = crypto.createHmac('sha256', process.env.SECRET)

const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const mongoose = require('mongoose');

try {
    mongoose.connect(process.env.DB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      }, () => console.log("Connected to DB"));
  } catch (error) {
    console.log("could not connect to DB");
  } 

const { Schema } = mongoose;

const userSchema = new Schema({
    name:  String,
    registerDate: Number,
    admin:   Boolean,
});

const matchSchema = new Schema({
    participants: [],
    winner: String,
    matchCreationDate: Number,
    matchPlayedDate: Number
});

const User = mongoose.model('User', userSchema);
const Match = mongoose.model('Match', matchSchema);

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))
 
// parse application/json
app.use(bodyParser.json())

app.use(cookieParser())

const auth = {
    required: expressjwt(
        {
            secret: process.env.SECRET, 
            credentialsRequired: true,
            algorithms: ['HS256'],
            getToken: (req) => {
                return req.cookies.token;
            }
        }),
    optional: expressjwt(
        {
            secret: process.env.SECRET, 
            credentialsRequired: false,
            algorithms: ['HS256'],
            getToken: (req) => {
                return req.cookies.token;
            }
        })
}

app.get('/matchs', auth.required, (req, res) => {
    Match.find({}, (err, docs) => {
        res.status(200).json(docs);
    });
});

app.put('/match', auth.required, guard.check('ADMIN'), (req, res) => {
    const matchData = {
        _id: req.body_id,
        winner: req.body.winner,
        matchPlayedDate: Date.now(),
    };

    if(matchData.participants && matchData.participants.length == 2) {
        Match.findOneAndUpdate(
            { _id:matchData._id}, 
            { $set: { winner : matchData.winner, matchPlayedDate : matchData.matchPlayedDate }}, 
            (err, doc) => {
                if(err) {
                    res.status(401).json(err);
                    console.log(err);
                } 
                else res.status(200).json(doc);
        })
    }
});

app.post('/match', auth.required, guard.check('ADMIN'), (req, res) => {
    const matchData = {
        participants: req.body.participants,
        matchCreationDate: Date.now(),
    }

    if(matchData.participants && matchData.participants.length == 2) {
        const match = new Match( matchData );

        match.save((err, data) => {
            if(err) {
                res.status(401).json( {err} );
                console.log(err);
            }
            else res.status(200).json( { _id:require('mongodb').ObjectID(data._id) });
        });

    } else {
        res.status(401).json( { error:'La liste des participants est invalide : vide ou sa taille != 2 participants.'});
    }
});

app.post('/register', auth.optional, (req, res) => {
  const userData = {
      name: req.body.name,
      password: req.body.password,
      registerDate: Date.now(),
      admin: false
  }

  if(userData.name && userData.password) {
    const user = new User( userData );

    userData.password = hash.update(userData.password).digest('hex');

    (async (user) => {
        await user.save();

        res.status(200).send();
    })(user);
  }
  
});

app.get('/logout', auth.required, (req, res) => {
    res.clearCookie('token').status(200).send();
});

app.get('/login', auth.optional, (req, res) => {
    const userData = {
        name: req.body.name,
        password: req.body.password
    }

    if(userData.name && userData.password) {
        userData.password = hash.update(userData.password).digest('hex');

        UserModel.findOne({name : userData.name, password : userData.password}, function (err, doc) {
            if (doc){
                jwt.sign({ username: userData.name }, process.env.SECRET, { algorithm: 'RS256' }, function(err, token) {
                    console.log('[' + userData.name + ' : ' + token + ']');

                    res.status(200).cookie("token", token, { maxAge: 900000, httpOnly: true }).send();
                });
            }else{
                res.status(401).send();

                console.log('[ compte introuvable ]');
            }
        });

    }
});




const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
