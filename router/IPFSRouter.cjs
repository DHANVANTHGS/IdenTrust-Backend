// router/ipfs.js
const express = require('express');
const { body } = require('express-validator');
const { authenticateToken } = require('../middleware/auth.cjs');
const ipfsController = require('../controllers/ipfsController.cjs'); // Fixed - removed .cjs

const router = express.Router();

// Upload sensitive user data (protected endpoint)
router.post(
  '/upload-sensitive',
  authenticateToken,
  [
    body('data').notEmpty().withMessage('Sensitive data is required'),
    body('dataType').notEmpty().withMessage('Data type is required'),
    body('description').optional().isString().withMessage('Description must be a string')
  ],
  ipfsController.uploadSensitiveData
);

// Batch upload sensitive data (protected endpoint)
router.post(
  '/batch-upload-sensitive',
  authenticateToken,
  [
    body('dataItems').isArray().withMessage('Data items must be an array'),
    body('dataItems.*.data').notEmpty().withMessage('Each data item is required'),
    body('dataItems.*.dataType').notEmpty().withMessage('Each data type is required')
  ],
  ipfsController.batchUploadSensitiveData
);

// Retrieve specific sensitive data (protected endpoint)
router.get(
  '/sensitive/:dataId',
  authenticateToken,
  ipfsController.retrieveSensitiveData
);

// Get all user's sensitive data records (protected endpoint)
router.get(
  '/sensitive',
  authenticateToken,
  ipfsController.getUserSensitiveDataList
);

// Delete sensitive data (protected endpoint)
router.delete(
  '/sensitive/:dataId',
  authenticateToken,
  ipfsController.deleteSensitiveData
);

// General IPFS operations (protected endpoints)
router.post(
  '/upload',
  authenticateToken,
  [body('data').notEmpty().withMessage('Data is required for IPFS upload')],
  ipfsController.uploadToIPFS
);

router.get('/retrieve/:hash', authenticateToken, ipfsController.retrieveFromIPFS);
router.post('/pin/:hash', authenticateToken, ipfsController.pinToIPFS);

module.exports = router;
