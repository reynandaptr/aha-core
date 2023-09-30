import express from 'express';

import {UserList, UserOnline} from '../../controller/v1/analytics';

const router = express.Router();

router.get('/users', UserList);
router.get('/users/online', UserOnline);

export default router;
