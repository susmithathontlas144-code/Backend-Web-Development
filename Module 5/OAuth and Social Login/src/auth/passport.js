
'use strict';
// auth/passport.js — Google OAuth strategy

const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { users, nextId } = require('../data');

// Implement Google OAuth verification
async function verifyCallback(accessToken, refreshToken, profile, done) {
  try {
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const name = profile.displayName;

    // STEP 1: Check for an existing Google account
    const existingGoogleUser = users.find(
      (user) => user.googleId === googleId
    );

    if (existingGoogleUser) {
      return done(null, existingGoogleUser);
    }

    // STEP 2: Check for an existing local account using email
    const existingEmailUser = users.find(
      (user) => user.email === email
    );

    if (existingEmailUser) {
      // Only link the account if Google has verified the email
      if (profile._json.email_verified === true) {
        existingEmailUser.googleId = googleId;
        return done(null, existingEmailUser);
      }

      // Reject unverified email to prevent account takeover
      return done(null, false);
    }

    // STEP 3: Create a new user if no match is found
    const newUser = {
      id: nextId(),
      googleId: googleId,
      email: email,
      name: name,
      role: 'member'
    };

    users.push(newUser);

    return done(null, newUser);

  } catch (err) {
    return done(err);
  }
}

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || 'test-client-id',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'test-client-secret',
      callbackURL: '/auth/google/callback',
    },
    verifyCallback,
  ),
);

// Export passport and verifyCallback
module.exports = { passport, verifyCallback };
