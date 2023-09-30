import express from 'express';

import analytics from './analytics';
import auth from './auth';

const router = express.Router();

router.use('/auth', auth);
router.use('/analytics', analytics);

export default router;
