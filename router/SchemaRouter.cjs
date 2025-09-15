const express = require('express');
const { body } = require('express-validator');
const { authenticateToken } = require('../middleware/auth');
const schemaController = require('../controllers/schemaController.cjs');

const router = express.Router();

router.post(
  '/create',
  authenticateToken,
  [
    body('schemaId').notEmpty().withMessage('Schema ID is required'),
    body('name').notEmpty().withMessage('Schema name is required'),
    body('description').notEmpty().withMessage('Schema description is required'),
    body('schemaJSON').notEmpty().withMessage('Schema JSON is required'),
    body('version').isInt({ min: 1 }).withMessage('Valid version number required')
  ],
  schemaController.createSchema
);

router.get('/:schemaId', schemaController.getSchema);
router.get('/', schemaController.getAllSchemas);
router.get('/creator/:address', authenticateToken, schemaController.getCreatorSchemas);

module.exports = router;
