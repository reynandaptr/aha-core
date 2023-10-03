import {prisma, UserAnalyticsResponse, UserOnlineAnalyticsResponse} from '@reynandaptr/aha-types/dist';
import {Request, Response} from 'express';

import {handleResponseError, handleResponseSuccess} from '../../utils/response';

export const UserList = async (req: Request, res: Response) => {
  try {
    const result: UserAnalyticsResponse[] = await prisma.$queryRaw`
SELECT
    users.id,
    users.email,
    users.name,
    users.provider,
    users.is_verified,
    COUNT(sessions) FILTER (
        WHERE
            sessions.type = 'LOGIN'
    ) AS login_count,
    MIN(sessions.created_at) FILTER (
        WHERE
            sessions.type = 'SIGN_UP'
    ) AS signup_timestamp,
    MAX(sessions.created_at) FILTER (
        WHERE
            sessions.type = 'ONLINE'
    ) AS last_session_timestamp
FROM
    users
    INNER JOIN sessions ON sessions.user_id = users.id
GROUP BY
    1, 2, 3, 4, 5
    `;
    return handleResponseSuccess(res, 200, result);
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};

export const UserOnline = async (req: Request, res: Response) => {
  try {
    const userCount = await prisma.user.count();
    const _userActiveSessionCount: any[] = await prisma.$queryRaw`
SELECT
  COUNT(DISTINCT user_id) AS user_active_session_count
FROM
  sessions
WHERE
  TYPE = 'ONLINE'
    `;
    const _averageActiveUser: any[] = await prisma.$queryRaw`
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
    const userActiveSessionCount: number = _userActiveSessionCount.length > 0 ? _userActiveSessionCount[0].user_active_session_count : 0;
    const averageActiveUser: UserOnlineAnalyticsResponse = _averageActiveUser.length > 0 ? _averageActiveUser[0].average_active_users : 0;
    return handleResponseSuccess(res, 200, {
      user_count: userCount,
      user_active_session_count: userActiveSessionCount,
      average_active_user: averageActiveUser,
    });
  } catch (error) {
    return handleResponseError(res, error, null, false);
  }
};
