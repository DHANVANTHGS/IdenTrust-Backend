// router/Credentials_Router.js (or .cjs)
const express = require('express');
const { body } = require('express-validator');
const { authenticateToken } = require('../middleware/auth');
const credentialController = require('../controllers/credentialController'); // Fixed name

const router = express.Router();

// Issue credential (protected)
router.post(
  '/issue',
  authenticateToken,
  [
    body('ipfsHash').notEmpty().withMessage('IPFS hash is required'),
    body('holderDID').notEmpty().withMessage('Holder DID is required'),
    body('schemaId').notEmpty().withMessage('Schema ID is required'),
    body('expiresAt').isInt({ min: 1 }).withMessage('Valid expiry timestamp required')
  ],
  credentialController.issueCredential
);

// Get credential (public)
router.get('/:hash', credentialController.getCredential);

// Verify credential (public)
router.get('/verify/:hash', credentialController.verifyCredential);

// Get issuer's credentials (protected)
router.get('/issuer/:address', authenticateToken, credentialController.getIssuerCredentials);

// Get holder's credentials (protected)
router.get('/holder/:did', authenticateToken, credentialController.getHolderCredentials);

// Batch verify credentials (protected)
router.post(
  '/batch-verify',
  authenticateToken,
  [
    body('credentialHashes').isArray().withMessage('Credential hashes must be an array'),
    body('credentialHashes.*').notEmpty().withMessage('Each credential hash is required')
  ],
  credentialController.batchVerifyCredentials
);

module.exports = router;
