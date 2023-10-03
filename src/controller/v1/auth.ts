import {faker} from '@faker-js/faker';
import {prisma} from '@reynandaptr/aha-types/dist';
import {EmailVerificationRequestSchema, LoginRequestSchema, Oauth2RedirectRequest, ResetPasswordRequestSchema, SignUpRequestSchema, UpdateUserProfileRequestSchema, ValidateUserResponse} from '@reynandaptr/aha-types/dist/types';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import {Request, Response} from 'express';
import httpStatus from 'http-status';
import jwt from 'jsonwebtoken';
import moment from 'moment';

import {createOrGetUser, sendEmailVerification, setCookie} from '../../utils/auth';
import {getEnvvarValue} from '../../utils/envvar';
import {validateJWT} from '../../utils/jwt';
import {handleResponseError, handleResponseSuccess} from '../../utils/response';
import {validateRequest} from '../../utils/zod';

export const Login = async (req: Request, res: Response) => {
  try {
    const {body} = await validateRequest(LoginRequestSchema, req);
    return createOrGetUser('login', req, res, 'USER_DEFINED_PASSWORD', body.email, '', body.email, body.password);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const SignUp = async (req: Request, res: Response) => {
  try {
    const {body} = await validateRequest(SignUpRequestSchema, req);
    bcrypt.hash(body.password, 10, async (error, hash) => {
      if (error) return handleResponseError(res, error, null, false);
      return createOrGetUser('sign-up', req, res, 'USER_DEFINED_PASSWORD', body.email, '', body.email, hash);
    });
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const ValidateToken = async (req: Request, res: Response) => {
  try {
    if (!req.user) return handleResponseError(res, null, null, true);
    const session = await prisma.session.create({
      data: {
        type: 'ONLINE',
        user_id: req.user.id,
      },
      include: {
        user: true,
      },
    });
    const responseBody: ValidateUserResponse ={
      id: session.user.id,
      name: session.user.name,
      email: session.user.email,
      is_verified: session.user.is_verified,
      provider: session.user.provider,
    };
    return handleResponseSuccess(res, httpStatus.OK, responseBody);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const EmailVerification = async (req: Request, res: Response) => {
  try {
    const {body} = await validateRequest(EmailVerificationRequestSchema, req);
    const session = await prisma.session.findFirstOrThrow({
      where: {
        id: parseInt(body.session_id),
        token: body.session_token,
        type: 'EMAIL_VERIFICATION',

        start_time: {
          lte: moment().unix(),
        },
        end_time: {
          gte: moment().unix(),
        },
      },
    });
    const payload = await validateJWT(body.session_token);
    if (typeof payload === 'string' || payload.purpose !== 'email-verification') {
      return handleResponseError(res, null, 'Invalid token', true);
    }
    const user = await prisma.user.update({
      where: {
        id: session.user_id,
      },
      data: {
        is_verified: true,
      },
    });
    if (!req.user) {
      await setCookie(res, user, user.provider);
    }
    return handleResponseSuccess(res, httpStatus.OK);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const ResendEmailVerification = async (req: Request, res: Response) => {
  try {
    if (!req.user) return handleResponseError(res, null, null, true);
    const user = await prisma.user.findUniqueOrThrow({
      where: {
        id: req.user.id,
      },
    });
    await sendEmailVerification(user);
    return handleResponseSuccess(res, httpStatus.OK);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const ResetPassword = async (req: Request, res: Response) => {
  try {
    if (!req.user) return handleResponseError(res, null, null, true);
    const {body} = await validateRequest(ResetPasswordRequestSchema, req);
    const user = await prisma.user.findUniqueOrThrow({
      where: {
        id: req.user.id,
      },
    });
    bcrypt.compare(body.old_password, user.password || '', async (error, match) => {
      if (error) return handleResponseError(res, error, null, true);
      if (!match) return handleResponseError(res, error, 'Password is wrong', true);
      bcrypt.hash(body.new_password, 10, async (error, hash) => {
        if (error) return handleResponseError(res, error, null, false);
        await prisma.user.update({
          where: {
            id: user.id,
          },
          data: {
            password: hash,
          },
        });
        return handleResponseSuccess(res, httpStatus.OK);
      });
    });
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const LogOut = async (req: Request, res: Response) => {
  try {
    if (!req.user) return handleResponseError(res, null, null, true);
    await prisma.session.create({
      data: {
        type: 'LOGOUT',
        user_id: req.user.id,
      },
    });
    const {
      value: cookieDomain,
    } = getEnvvarValue('COOKIE_DOMAIN', true, (error) => {
      if (error) {
        return handleResponseError(res, error, null, false);
      }
    });
    res.cookie('aha_jwt', '', {
      httpOnly: true,
      secure: true,
      domain: cookieDomain,
    });

    if (req.headers.accept === 'application/json') {
      return handleResponseSuccess(res, httpStatus.OK);
    }
    const {
      value: appURL,
    } = getEnvvarValue('APP_URL', true, (error) => {
      if (error) {
        throw new Error(error);
      }
    });
    return res.redirect(`${appURL}`);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const TestLoginGoogle = async (req: Request, res: Response) => {
  try {
    const email = req.body.email as string;
    return createOrGetUser('sign-up', req, res, 'GOOGLE', faker.datatype.uuid(), '', email);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

/* c8 ignore start */
export const Oauth2RedirectGoogle = async (req: Request, res: Response) => {
  try {
    const {query: {code}} = await validateRequest(Oauth2RedirectRequest, req);
    const {
      value: googleClientId,
    } = getEnvvarValue('GOOGLE_CLIENT_ID', true, (error) => {
      if (error) {
        throw new Error(error);
      }
    });

    const {
      value: googleClientSecret,
    } = getEnvvarValue('GOOGLE_CLIENT_SECRET', true, (error) => {
      if (error) {
        throw new Error(error);
      }
    });

    const {
      value: googleCallbackUrl,
    } = getEnvvarValue('GOOGLE_CALLBACK_URL', true, (error) => {
      if (error) {
        throw new Error(error);
      }
    });

    const response = await axios.post(
        'https://oauth2.googleapis.com/token',
        {
          code,
          client_id: googleClientId,
          client_secret: googleClientSecret,
          redirect_uri: googleCallbackUrl,
          grant_type: 'authorization_code',
        },
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
    );
    const jwtPayload = jwt.decode(response.data.id_token);
    if (!jwtPayload || typeof jwtPayload === 'string' || !jwtPayload.sub) {
      return handleResponseError(res, null, null, true);
    }
    return createOrGetUser('sign-up', req, res, 'GOOGLE', jwtPayload.sub, jwtPayload.name, jwtPayload.email, '', response.data.access_token, response.data.refresh_token, jwtPayload.exp);
  } catch (error) {
    return handleResponseError(res, error, null, true);
  }
};
/* c8 ignore stop */

export const UpdateUserProfile = async (req: Request, res: Response) => {
  try {
    if (!req.user) return handleResponseError(res, null, null, true);
    const {body} = await validateRequest(UpdateUserProfileRequestSchema, req);
    const user = await prisma.user.update({
      where: {
        id: req.user.id,
      },
      data: {
        name: body.name,
      },
    });
    return handleResponseSuccess(res, httpStatus.OK, user);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};
