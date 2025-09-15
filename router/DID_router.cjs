// router/DID_Router.js
const express = require('express');
const { body } = require('express-validator');
const { authenticateToken } = require('../middleware/auth');
const didController = require('../controllers/didController'); // Fixed - removed .cjs

const router = express.Router();

// Create DID (protected)
router.post(
  '/create',
  authenticateToken,
  [
    body('did').notEmpty().withMessage('DID is required'),
    body('document').notEmpty().withMessage('DID document is required')
  ],
  didController.createDID
);

// Update DID (protected)
router.put(
  '/update',
  authenticateToken,
  [
    body('did').notEmpty().withMessage('DID is required'),
    body('document').notEmpty().withMessage('Updated document is required')
  ],
  didController.updateDID
);

// Transfer DID ownership (protected)
router.post(
  '/transfer',
  authenticateToken,
  [
    body('did').notEmpty().withMessage('DID is required'),
    body('newOwner').isEthereumAddress().withMessage('Valid Ethereum address required')
  ],
  didController.transferDID
);

// Get DID document (public)
router.get('/:did', didController.getDIDDocument);

// Get owner's DIDs (public)
router.get('/owner/:address', didController.getOwnerDIDs);

// Resolve DID (public) - returns full DID document in W3C format
router.get('/resolve/:did', didController.resolveDID);

// Verify DID ownership (protected)
router.post(
  '/verify-ownership',
  authenticateToken,
  [
    body('did').notEmpty().withMessage('DID is required'),
    body('signature').notEmpty().withMessage('Signature is required'),
    body('challenge').notEmpty().withMessage('Challenge is required')
  ],
  didController.verifyDIDOwnership
);

// Get DID history (public)
router.get('/history/:did', didController.getDIDHistory);

// Batch create DIDs (protected)
router.post(
  '/batch-create',
  authenticateToken,
  [
    body('dids').isArray().withMessage('DIDs must be an array'),
    body('dids.*.did').notEmpty().withMessage('Each DID is required'),
    body('dids.*.document').notEmpty().withMessage('Each DID document is required')
  ],
  didController.batchCreateDIDs
);

module.exports = router;
