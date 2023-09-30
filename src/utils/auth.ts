import {LoginProvider, Prisma, Session, User} from '@prisma/client';
import {prisma} from '@reynandaptr/aha-types/dist';
import sendbirdMail from '@sendgrid/mail';
import bcrypt from 'bcryptjs';
import {Response} from 'express';
import moment from 'moment';

import {getEnvvarValue} from './envvar';
import {generateJWT} from './jwt';
import {handleResponseError} from './response';
import {prismaNotFoundErrorCode} from '../constants';

export const createOrGetUser = async (usage: 'login' | 'sign-up', res: Response, loginProvider: LoginProvider, providerID: string, name: string, email: string, password?: string, accessToken?: string, refreshToken?: string, expiredAt?: number) => {
  try {
    let user = await prisma.user.findFirstOrThrow({
      where: {
        OR: [
          {
            email,
          },
          {
            provider_id: providerID,
            provider: loginProvider,
          },
        ],
      },
    });
    if (user.provider !== loginProvider) {
      return handleResponseError(res, null, `Email already connected with ${user.provider}`, true);
    }
    if (user.provider == 'USER_DEFINED_PASSWORD' && usage === 'sign-up') {
      return handleResponseError(res, null, 'Email already registered', true);
    }
    if (usage === 'login') {
      bcrypt.compare(password || '', user.password || '', async (error, match) => {
        if (error) return handleResponseError(res, error, null, true);
        if (!match) return handleResponseError(res, error, 'Password is wrong', true);
        await setCookie(res, user);
        const {
          value: appURL,
        } = getEnvvarValue('APP_URL', true, (error) => {
          if (error) {
            throw new Error(error);
          }
        });
        return res.redirect(`${appURL}`);
      });
    } else {
      user = await prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          access_token: accessToken,
          refresh_token: refreshToken,
          expired_at: expiredAt,
        },
      });
      await setCookie(res, user);
      const {
        value: appURL,
      } = getEnvvarValue('APP_URL', true, (error) => {
        if (error) {
          throw new Error(error);
        }
      });
      return res.redirect(`${appURL}`);
    }
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === prismaNotFoundErrorCode && usage === 'sign-up') {
        try {
          if (email) {
            const existingUser = await prisma.user.findFirst({
              where: {
                email,
              },
            });
            if (existingUser && existingUser.provider !== loginProvider) {
              return handleResponseError(res, null, `Email already connected with ${existingUser.provider}`, true);
            }
          }
          const user = await prisma.user.create({
            data: {
              name,
              email,
              is_verified: loginProvider !== 'USER_DEFINED_PASSWORD',
              provider: loginProvider,
              provider_id: providerID,
              access_token: accessToken,
              refresh_token: refreshToken,
              expired_at: expiredAt,
              password,
            },
          });
          await prisma.session.create({
            data: {
              type: 'SIGN_UP',
              user_id: user.id,
            },
          });
          await setCookie(res, user);
          await sendEmailVerification(user);
          const {
            value: appURL,
          } = getEnvvarValue('APP_URL', true, (error) => {
            if (error) {
              throw new Error(error);
            }
          });
          return res.redirect(`${appURL}`);
        } catch (error) {
          return handleResponseError(res, error, null, true);
        }
      } else {
        return handleResponseError(res, error, null, false);
      }
    } else {
      return handleResponseError(res, error, null, false);
    }
  }
};

export const setCookie = async (res: Response, user: User) => {
  await prisma.session.create({
    data: {
      type: 'LOGIN',
      user_id: user.id,
    },
  });
  const {
    value: cookieDomain,
  } = getEnvvarValue('COOKIE_DOMAIN', true, (error) => {
    if (error) {
      return handleResponseError(res, error, null, false);
    }
  });
  const jwt = await generateJWT({
    id: user.id,
    provider: user.provider,
    provider_id: user.provider_id,
    access_token: user.access_token,
    refresh_token: user.refresh_token,
    expired_at: user.expired_at,
  }, '30 days', 'authentication');
  res.cookie('aha_jwt', jwt, {
    httpOnly: true,
    secure: true,
    domain: cookieDomain,
  });
};

export const sendEmailVerification = async (user: User): Promise<Session | undefined> => {
  const {
    value: environment,
  } = getEnvvarValue('ENVIRONMENT', true, (error) => {
    if (error) {
      throw new Error(error);
    }
  });
  if (user.is_verified) {
    return undefined;
  }
  const jwt = await generateJWT({
    id: user.id,
  }, '30 days', 'email-verification');
  const session = await prisma.session.create({
    data: {
      type: 'EMAIL_VERIFICATION',
      user_id: user.id,
      token: jwt,

      start_time: moment().unix(),
      end_time: moment().add(15, 'minutes').unix(),
    },
  });
  if (environment === 'production') {
    const {
      value: sendgridAPIKey,
    } = getEnvvarValue('SENDGRID_API_KEY', true, (error) => {
      if (error) {
        throw new Error(error);
      }
    });

    const {
      value: sendgridEmailVerificationTemplateID,
    } = getEnvvarValue('SENDGRID_EMAIL_VERIFICATION_TEMPLATE_ID', true, (error) => {
      if (error) {
        throw new Error(error);
      }
    });

    const {
      value: appURL,
    } = getEnvvarValue('APP_URL', true, (error) => {
      if (error) {
        throw new Error(error);
      }
    });

    sendbirdMail.setApiKey(sendgridAPIKey);
    await sendbirdMail.send({
      to: user.email,
      from: 'hello@reynandaptr.dev',
      templateId: sendgridEmailVerificationTemplateID,
      dynamicTemplateData: {
        email: user.email,
        link: `${appURL}/email-verification?session_id=${session.id}&session_token=${session.token}`,
      },
    });
  }
  return session;
};
