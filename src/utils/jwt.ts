import jwt from 'jsonwebtoken';

import {getEnvvarValue} from './envvar';

export const generateJWT = async (payload: object, expiresIn: string, purpose: 'authentication' | 'email-verification'): Promise<string> => {
  const {
    value: privateKey,
  } = getEnvvarValue('JWT_PRIVATE_KEY', true, (error) => {
    if (error) {
      throw new Error(error);
    }
  });

  return jwt.sign({
    ...payload,
    purpose,
  }, privateKey, {
    expiresIn,
    algorithm: 'RS256',
  });
};

export const validateJWT = async (token: string): Promise<string | jwt.JwtPayload> => {
  const {
    value: publicKey,
  } = getEnvvarValue('JWT_PUBLIC_KEY', true, (error) => {
    if (error) {
      throw new Error(error);
    }
  });

  return jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
  });
};
