import express from 'express';
import passport from 'passport';
import {Strategy as GoogleStrategy} from 'passport-google-oauth20';

import {EmailVerification, Login, LogOut, Oauth2RedirectGoogle, ResendEmailVerification, ResetPassword, SignUp, TestLoginGoogle, ValidateToken} from '../../controller/v1/auth';
import {validate} from '../../middlewares/auth';
import {getEnvvarValue} from '../../utils/envvar';

const router = express.Router();

router.post('/login', Login);
router.post('/sign-up', SignUp);
router.get('/validate-token', validate(false), ValidateToken);
router.post('/email-verification', validate(false, true), EmailVerification);
router.post('/resend-email-verification', validate(false), ResendEmailVerification);
router.post('/reset-password', validate(true), ResetPassword);
router.post('/logout', validate(false), LogOut);

const {
  value: environment,
} = getEnvvarValue('ENVIRONMENT', true, (error) => {
  if (error) {
    throw new Error(error);
  }
});

const {
  value: googleClientId,
} = getEnvvarValue('GOOGLE_CLIENT_ID', true);

const {
  value: googleClientSecret,
} = getEnvvarValue('GOOGLE_CLIENT_SECRET', true);

const {
  value: googleCallbackUrl,
} = getEnvvarValue('GOOGLE_CALLBACK_URL', true);

if (environment !== 'production') {
  router.post('/test-login-google', TestLoginGoogle);
}

/* c8 ignore start */
if (googleClientId && googleClientSecret && googleCallbackUrl) {
  passport.use(new GoogleStrategy({
    clientID: googleClientId,
    clientSecret: googleClientSecret,
    callbackURL: googleCallbackUrl,
    scope: ['profile', 'email'],
  }, (accessToken, refreshToken, profile, done) => {
    done(null, undefined);
  }));


  router.get('/login/google', passport.authenticate('google', {
    scope: ['profile', 'email'],
    accessType: 'offline',
    prompt: 'consent',
    session: false,
  }));

  router.get('/redirect/google', Oauth2RedirectGoogle);
}
/* c8 ignore start */

export default router;
