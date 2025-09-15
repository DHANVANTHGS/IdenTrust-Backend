const express = require('express');
const { body, param } = require('express-validator');
const { authenticateToken } = require('../middleware/auth');
const revocationController = require('../controllers/revocationController');

const router = express.Router();

router.post(
  '/revoke',
  authenticateToken,
  [
    body('credentialHash').notEmpty().withMessage('Credential hash is required'),
    body('reason').notEmpty().withMessage('Revocation reason is required')
  ],
  revocationController.revokeCredential
);

router.get(
  '/status/:hash',
  [
    param('hash').notEmpty().withMessage('Credential hash parameter is required')
  ],
  revocationController.getRevocationStatus
);

router.get(
  '/info/:hash',
  [
    param('hash').notEmpty().withMessage('Credential hash parameter is required')
  ],
  revocationController.getRevocationInfo
);

module.exports = router;
