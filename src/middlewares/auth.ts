import {prisma} from '@reynandaptr/aha-types/dist';
import {NextFunction, Request, Response} from 'express';

import {getEnvvarValue} from '../utils/envvar';
import {validateJWT} from '../utils/jwt';
import {handleResponseError} from '../utils/response';


export const validate = (verifiedUserOnly: boolean, optional?: boolean) => async (req: Request, res: Response, next: NextFunction) => {
  const jwt = req.cookies.aha_jwt || req.headers.authorization;
  if (!jwt) {
    if (optional) {
      return next();
    }
    return handleResponseError(res, null, null, true);
  }

  try {
    const payload = await validateJWT(jwt);
    if (typeof payload === 'string' || payload.purpose !== 'authentication') {
      return handleResponseError(res, null, null, true);
    }
    const user = await prisma.user.findUniqueOrThrow({
      where: {
        id: payload.id,
      },
    });
    const {
      value: environment,
    } = getEnvvarValue('ENVIRONMENT', true, (error) => {
      if (error) {
        throw new Error(error);
      }
    });
    if ((verifiedUserOnly && environment === 'production') && !user.is_verified) {
      return handleResponseError(res, null, null, true);
    }
    req.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      provider: user.provider,
      provider_id: user.provider_id,
    };
    next();
  } catch (error) {
    if (optional) {
      return next();
    }
    return handleResponseError(res, error, null, true);
  }
};
