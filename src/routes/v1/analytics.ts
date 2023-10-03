import express from 'express';

import {UserList, UserOnline} from '../../controller/v1/analytics';
import {validate} from '../../middlewares/auth';

const router = express.Router();

router.get('/users', validate(true), UserList);
router.get('/users/online', validate(true), UserOnline);

export default router;
