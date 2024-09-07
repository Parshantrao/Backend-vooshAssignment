const express = require("express")
const mongoose = require("mongoose")
const cors = require('cors')
const cookieParser = require('cookie-parser');
const passport = require('passport');
const session = require('express-session');

var routes = require('./src/routes/route');

const dotenv = require('dotenv');
dotenv.config();

require('./src/passportAuth');

let app = express()

// Middleware for handling sessions
// CORS configuration

app.use(cors({
  origin: process.env.CORS_ORIGIN_URL_PRODUCTION, // Replace with your actual frontend URL
  credentials: true
}));

app.use(express.json())

// Other middlewares and Passport setup

app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'your-secret', resave: false, saveUninitialized: false }));

app.use(passport.initialize());
app.use(passport.session());


app.use(cookieParser());

app.use("/", routes)


// should store this url in env file 
let url = "mongodb+srv://developerparshant:gImWT1TbXAICSqVP@cluster0.nt8qwy2.mongodb.net/"

app.listen(process.env.PORT || 3001, () => {
  console.log("Server is running on:", process.env.PORT || 3001)
})

mongoose.connect(url)
  .then(() => console.log("mongoDB is connected")
  ).catch(err => console.error(err))