const passport = require('passport');
const UserModel = require('./models/usersModel');
const GoogleStrategy = require('passport-google-oauth20').Strategy;


passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL_PRODUCTION
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      const existingUser = await UserModel.findOne({ email: profile.emails[0].value })
      if (existingUser) {
        return done(null, existingUser)
      }
      else {
        const newUser = await UserModel.create({
          first_name: profile.displayName,
          email: profile.emails[0].value
        })

        return done(null, newUser)
      }
    }
    catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

