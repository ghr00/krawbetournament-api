const express = require('express')
const app = express()

const crypto = require('crypto');
const expressjwt = require('express-jwt');
const jwt = require('jsonwebtoken');
require('dotenv').config()

const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const cors = require('cors')

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

var guard = require('express-jwt-permissions')()

const userSchema = new Schema({
    name:  String,
    password: String,
    registerDate: Number,
    admin:   Boolean,
});

const matchSchema = new Schema({
    participants: [],
    winner: Object,
    matchCreationDate: Number,
    matchPlayedDate: Number
});

const participantSchema = new Schema({
    userId: require('mongodb').ObjectID,
    name: String,
    champions: []
});

const User = mongoose.model('User', userSchema);
const Match = mongoose.model('Match', matchSchema);

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))
 
// parse application/json
app.use(bodyParser.json())

app.use(cookieParser())

app.use(cors({credentials: true, origin: 'http://localhost:3000'}))

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

app.get('/', auth.required, guard.check('ADMIN'), (req, res) => {
    res.status(200).send();
});

app.get('/users', auth.required, (req, res) => {
    User.find({}, (err, docs) => {
        if(err) res.status(401).json({err})
        else {
            const users = [];
            for(let i = 0;  i < docs.length; i++)
                users.push({ _id:docs[i]._id, name:docs[i].name})
            res.status(200).json({users});
        }
    });
});

app.get('/user', auth.required, (req, res) => {
    console.log(' COOKIES:' + JSON.stringify(req.cookies))
    res.status(200).send();
});

app.get('/admin', auth.required, guard.check('ADMIN'), (req, res) => {
    console.log('ADMIN COOKIES:' + JSON.stringify(req.cookies))
    res.status(200).send();
});

app.post('/brackets', auth.required, (req, res) => {
    const players = req.body.players;

    console.log(req.body)
    if(players instanceof Array && players.length > 0) {
        var result = [];

        var player1, player2;

            do {
                player1 = players[Math.floor(Math.random() * players.length)]; 
                player2 = players[Math.floor(Math.random() * players.length)]; 
            }
            while(player1 === player2);

        result = { player1, player2 }
        

        res.status(200).json({ result });
    } else {
        res.status(401).send();
    }
})

app.post('/random', auth.required, (req, res) => {
    const champions = req.body.champions;

    console.log(req.body)
    if(champions instanceof Array && champions.length > 0) {
        const champion = champions[Math.floor(Math.random() * champions.length)]; 

        res.status(200).json({ champion })
    } else {
        res.status(401).send();
    }
})

app.get('/matchs', auth.required, (req, res) => {
    Match.find({}, (err, docs) => {
        if(err) res.status(401).json({err})
        else res.status(200).json({docs});
    });
});

app.put('/match', auth.required, guard.check('ADMIN'), (req, res) => {
    const matchData = {
        _id: req.body._id,
        winner: req.body.winner,
        matchPlayedDate: Date.now(),
    };

    if(matchData._id && matchData.winner) {
        Match.findOne(
            { _id:matchData._id}, 
            (err, doc) => {
                if(err) {
                    res.status(401).json(err);
                    console.log(err);
                } 
                else {
                    doc.winner = matchData.winner;
                    doc.matchPlayedDate = matchData.matchPlayedDate;

                    doc.save( (err, doc) => {
                        if(err) res.status(400).json( {'error' : err} ); 
                        else {
                            res.status(200).json(doc);
                            console.log(doc);
                        }
                    });
                }
        })
    } else {
        res.status(401).json({err:"ID ou vainqeur du match invalide"});
    }
});

app.post('/match', auth.required, guard.check('ADMIN'), (req, res) => {
    console.log('body ' + JSON.stringify(req.body));

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

    console.log('body ' + JSON.stringify(req.body));
  const userData = {
      name: req.body.username,
      password: req.body.password,
      registerDate: Date.now(),
      admin: false
  }

  if(userData.name && userData.password) {
    const user = new User( userData );

    user.password = hash.update(userData.password).digest('hex');

    (async (user) => {
        await user.save();

        res.status(200).send();
    })(user);
  }  else {
    res.status(401).json({ error:'Nom ou mot de passe eronné' });
  }
  
});

app.get('/logout', auth.required, (req, res) => {
    res.clearCookie('token').status(200).send();
});

app.get('/login', auth.optional, (req, res) => {
    console.log('LOGIN QUERY' + JSON.stringify(req.query));
    const userData = {
        name: req.query.username,
        password: req.query.password
    }

    if(userData.name && userData.password) {
        userData.password = crypto.createHmac('sha256', process.env.SECRET)
                                  .update(userData.password).digest('hex');

        User.findOne({name : userData.name, password : userData.password}, function (err, doc) {
            if (doc){
                var playload = { username: doc.name };
                if(doc.admin) playload.permissions = ["ADMIN"];
                else playload.permissions = [];

                jwt.sign(playload, process.env.SECRET, { algorithm: 'HS256' }, function(err, token) {
                    if(err) {
                        console.log('Erreur dans la génération du token');
                        res.status(500).json({'error':err});
                    }
                    else {
                        res.status(200).cookie("token", token, { maxAge: 900000, httpOnly: true }).send();
                        console.log('[' + userData.name + ' : ' + token + ']');
                    }
                });
            }else{
                res.status(401).send('[ compte introuvable ]');

                console.log('[ compte introuvable ]');
            }
        });

    } else {
        res.status(401).json({ error:'Nom ou mot de passe eronné' });
    }
});




const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
