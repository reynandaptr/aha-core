import 'dotenv/config';
import {faker} from '@faker-js/faker';
import {beforeAll, describe, expect, test} from '@jest/globals';
import {BaseResponse, prisma} from '@reynandaptr/aha-types/dist';
import httpStatus from 'http-status';
import request from 'supertest';

import app from '../app';
import {createUserSession as generateUserSession, createUserWithGoogleAccount} from '../seeds';
import {sendEmailVerification} from '../utils/auth';
import {getEnvvarValue} from '../utils/envvar';

const user1Password = `${faker.internet.password(8, false, /[a-z]|[A-Z]/)}${faker.internet.password(8, false, /[0-9]/)}${faker.internet.password(8, false, /[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]/)}`;
const user1 = {
  email: 'reynandapp1997@gmail.com',
  password: user1Password,
  repassword: user1Password,
};
let jwt: string;

const {
  value: appURL,
} = getEnvvarValue('APP_URL', true, (error) => {
  if (error) {
    throw new Error(error);
  }
});

describe('GET /', () => {
  beforeAll(async () => {
    await prisma.session.deleteMany();
    await prisma.user.deleteMany();
    await createUserWithGoogleAccount();
  });

  test('test root path', () => {
    return request(app)
        .get('/')
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
        });
  });

  test('test health path', () => {
    return request(app)
        .get('/health')
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
        });
  });

  test('test 404 path', () => {
    return request(app)
        .get('/abc')
        .then((response) => {
          expect(response.status).toBe(httpStatus.NOT_FOUND);
        });
  });

  test('test login with one character password', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: faker.internet.email(),
          password: faker.internet.password(1, false),
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.BAD_REQUEST);
          expect(responseBody.message).toBe('Password must have at least 8 characters');
        });
  });

  test('test login without one lowercase character', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: faker.internet.email(),
          password: faker.internet.password(8, false, /[A-Z]/),
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.BAD_REQUEST);
          expect(responseBody.message).toBe('Password must contain at least one lowercase character');
        });
  });

  test('test login without one uppercase character', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: faker.internet.email(),
          password: faker.internet.password(8, false, /[a-z]/),
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.BAD_REQUEST);
          expect(responseBody.message).toBe('Password must contain at least one uppercase character');
        });
  });

  test('test login without one digit character', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: faker.internet.email(),
          password: faker.internet.password(8, false, /[a-z]|[A-Z]/),
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.BAD_REQUEST);
          expect(responseBody.message).toBe('Password must contain at least one digit character');
        });
  });

  test('test login without one special character', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: faker.internet.email(),
          password: `${faker.internet.password(8, false, /[a-z]|[A-Z]/)}${faker.internet.password(8, false, /[0-9]/)}`,
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.BAD_REQUEST);
          expect(responseBody.message).toBe('Password must contain at least one special character');
        });
  });

  test('test login with non existing email', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: faker.internet.email(),
          password: `${faker.internet.password(8, false, /[a-z]|[A-Z]/)}${faker.internet.password(8, false, /[0-9]/)}${faker.internet.password(8, false, /[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]/)}`,
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.NOT_FOUND);
          expect(responseBody.message).toBe('Not Found');
        });
  });

  test('test sign-up different repassword', () => {
    return request(app)
        .post('/v1/auth/sign-up')
        .send({
          ...user1,
          repassword: `${faker.internet.password(8, false, /[a-z]|[A-Z]/)}${faker.internet.password(8, false, /[0-9]/)}${faker.internet.password(8, false, /[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]/)}`,
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.BAD_REQUEST);
          expect(responseBody.message).toBe('Passwords do not match');
        });
  });

  test('test sign-up OK', () => {
    return request(app)
        .post('/v1/auth/sign-up')
        .send(user1)
        .set('Accept', 'application/json')
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
          expect(response.get('Set-Cookie').length).toBe(1);
        });
  });

  test('test sign-up with existing email', () => {
    return request(app)
        .post('/v1/auth/sign-up')
        .send(user1)
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
          expect(responseBody.message).toBe('Email already registered');
        });
  });

  test('test login with wrong password', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: user1.email,
          password: `${user1.password}a`,
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
          expect(responseBody.message).toBe('Password is wrong');
        });
  });

  test('test login OK', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: user1.email,
          password: user1.password,
        })
        .set('Accept', 'application/json')
        .then((response) => {
          jwt = response.get('Set-Cookie')[0].split('=')[1];
          expect(response.status).toBe(httpStatus.OK);
          expect(response.get('Set-Cookie').length).toBe(1);
        });
  });

  test('test validate without cookie', () => {
    return request(app)
        .get('/v1/auth/validate-token')
        .then((response) => {
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
        });
  });

  test('test validate OK', () => {
    return request(app)
        .get('/v1/auth/validate-token')
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
        });
  });

  test('test login with email registered with google', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: 'reynandapp1997@yahoo.com',
          password: user1Password,
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
          expect(responseBody.message).toBe('Email already connected with GOOGLE');
        });
  });

  test('test sign-up with email registered with google', () => {
    return request(app)
        .post('/v1/auth/sign-up')
        .send({
          email: 'reynandapp1997@yahoo.com',
          password: user1Password,
          repassword: user1Password,
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
          expect(responseBody.message).toBe('Email already connected with GOOGLE');
        });
  });

  test('test validate OK', () => {
    return request(app)
        .get('/v1/auth/validate-token')
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
        });
  });

  test('test resend email verification OK', () => {
    return request(app)
        .post('/v1/auth/resend-email-verification')
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
        });
  });

  test('test reset password with different renew password', () => {
    return request(app)
        .post('/v1/auth/reset-password')
        .send({
          old_password: user1Password,
          new_password: `${user1Password}a`,
          renew_password: `${user1Password}b`,
        })
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.BAD_REQUEST);
          expect(responseBody.message).toBe('Passwords do not match');
        });
  });

  test('test reset password with wrong old password', () => {
    return request(app)
        .post('/v1/auth/reset-password')
        .send({
          old_password: `${user1Password}b`,
          new_password: `${user1Password}a`,
          renew_password: `${user1Password}a`,
        })
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
          expect(responseBody.message).toBe('Password is wrong');
        });
  });

  test('test reset password OK', () => {
    return request(app)
        .post('/v1/auth/reset-password')
        .send({
          old_password: user1Password,
          new_password: `${user1Password}a`,
          renew_password: `${user1Password}a`,
        })
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
        });
  });

  test('test login with wrong password', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: user1.email,
          password: user1.password,
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
          expect(responseBody.message).toBe('Password is wrong');
        });
  });

  test('test login OK', () => {
    return request(app)
        .post('/v1/auth/login')
        .send({
          email: user1.email,
          password: `${user1Password}a`,
        })
        .set('Accept', 'application/json')
        .then((response) => {
          jwt = response.get('Set-Cookie')[0].split('=')[1];
          expect(response.status).toBe(httpStatus.OK);
          expect(response.get('Set-Cookie').length).toBe(1);
        });
  });

  test('test logout OK', () => {
    return request(app)
        .post('/v1/auth/logout')
        .set('Accept', 'application/json')
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
          expect(response.get('Set-Cookie').length).toBe(1);
        });
  });

  test('test logout without cookie', () => {
    return request(app)
        .post('/v1/auth/logout')
        .then((response) => {
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
        });
  });

  test('test login google', () => {
    return request(app)
        .post('/v1/auth/test-login-google')
        .send({
          email: 'reynandapp1997@yahoo.com',
        })
        .then((response) => {
          expect(response.status).toBe(httpStatus.FOUND);
          expect(response.get('Set-Cookie').length).toBe(1);
          expect(response.get('location')).toBe(`${appURL}/app`);
        });
  });

  test('test login google', () => {
    return request(app)
        .post('/v1/auth/test-login-google')
        .send({
          email: 'hello@reynandaptr.dev',
        })
        .then((response) => {
          expect(response.status).toBe(httpStatus.FOUND);
          expect(response.get('Set-Cookie').length).toBe(1);
          expect(response.get('location')).toBe(`${appURL}/app`);
        });
  });

  test('test sign-up with email registered with user defined password', () => {
    return request(app)
        .post('/v1/auth/test-login-google')
        .send({
          email: user1.email,
        })
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.UNAUTHORIZED);
          expect(responseBody.message).toBe('Email already connected with USER_DEFINED_PASSWORD');
        });
  });

  test('test resend email verification with invalid token', async () => {
    const user = await prisma.user.findFirstOrThrow({
      where: {
        email: user1.email,
      },
    });
    const session = await sendEmailVerification(user);
    return request(app)
        .post('/v1/auth/email-verification')
        .send({
          session_id: `${session?.id}`,
          session_token: `${jwt}`,
        })
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          const responseBody: BaseResponse = response.body;
          expect(response.status).toBe(httpStatus.NOT_FOUND);
          expect(responseBody.message).toBe('Not Found');
        });
  });

  test('test resend email verification OK and not return cookie', async () => {
    const user = await prisma.user.findFirstOrThrow({
      where: {
        email: user1.email,
      },
    });
    const session = await sendEmailVerification(user);
    return request(app)
        .post('/v1/auth/email-verification')
        .send({
          session_id: `${session?.id}`,
          session_token: `${session?.token}`,
        })
        .set('Cookie', [`aha_jwt=${jwt}`])
        .then((response) => {
          expect(response.status).toBe(httpStatus.FOUND);
          expect(response.get('Set-Cookie')).toBeUndefined();
          expect(response.get('location')).toBe(`${appURL}/login`);
        });
  });

  test('test resend email verification OK and return cookie', async () => {
    let user = await prisma.user.findFirstOrThrow({
      where: {
        email: user1.email,
      },
    });
    user = await prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        is_verified: false,
      },
    });
    const session = await sendEmailVerification(user);
    return request(app)
        .post('/v1/auth/email-verification')
        .send({
          session_id: `${session?.id}`,
          session_token: `${session?.token}`,
        })
        .then((response) => {
          expect(response.status).toBe(httpStatus.FOUND);
          expect(response.get('Set-Cookie').length).toBe(1);
          expect(response.get('location')).toBe(`${appURL}/login`);
        });
  });

  test('generate user\'s session', async () => {
    await generateUserSession();
  });

  test('test analytics user list', () => {
    return request(app)
        .get('/v1/analytics/users')
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
        });
  });

  test('test analytics user online', () => {
    return request(app)
        .get('/v1/analytics/users/online')
        .then((response) => {
          expect(response.status).toBe(httpStatus.OK);
        });
  });
});
