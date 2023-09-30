import {prisma} from '@reynandaptr/aha-types/dist';
import {Request, Response} from 'express';

import {handleResponseError, handleResponseSuccess} from '../../utils/response';

export const UserList = async (req: Request, res: Response) => {
  try {
    const result = await prisma.$queryRaw`
SELECT
  users.id AS user_id,
  COUNT(sessions) FILTER (
    WHERE
      sessions.type = 'LOGIN'
  ) AS login_count,
  COUNT(sessions) FILTER (
    WHERE
      sessions.type = 'ONLINE'
  ) AS online_count,
  MAX(sessions.created_at) FILTER (
    WHERE
      sessions.type = 'ONLINE'
  ) AS last_session
FROM
  users
  INNER JOIN sessions ON sessions.user_id = users.id
GROUP BY
  1
    `;
    return handleResponseSuccess(res, 200, result);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const UserOnline = async (req: Request, res: Response) => {
  try {
    const result = await prisma.$queryRaw`
WITH users_session AS (
  SELECT
    user_id,
    DATE(created_at) AS session_date
  FROM
    sessions
  WHERE
    created_at >= CURRENT_DATE - INTERVAL '7 days'
    AND TYPE = 'ONLINE'
  GROUP BY
    user_id,
    session_date
),
active_users_last7days_rolling AS (
  SELECT
    user_id
  FROM
    users_session
  GROUP BY
    user_id
  HAVING
    COUNT(DISTINCT session_date) >= 7
)
SELECT
  COUNT(active_users_last7days_rolling) / CAST(
    (
      SELECT
        count(*) AS cnt
      FROM
        users
    ) AS FLOAT
  ) AS average_active_users
FROM
  active_users_last7days_rolling
    `;
    return handleResponseSuccess(res, 200, result);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};
