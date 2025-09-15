// router/authRouter.js
const express = require('express');
const { body } = require('express-validator');
const { authenticateToken } = require('../middleware/auth');
const authController = require('../controllers/authController.js');

const router = express.Router();

// Validation middleware
const validateSignup = [
    body('gmail').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/),
    body('name').isLength({ min: 2 }).trim().escape(),
    body('number').isMobilePhone()
];

const validateLogin = [
    body('gmail').isEmail().normalizeEmail(),
    body('password').isLength({ min: 1 })
];

const validateUpdate = [
    body('name').optional().isLength({ min: 2 }).trim().escape(),
    body('number').optional().isMobilePhone()
];

// Auth routes
router.post('/signup', validateSignup, authController.signup);
router.post('/login', validateLogin, authController.login);

// Protected routes
router.get('/profile', authenticateToken, authController.getProfile);
router.put('/profile', authenticateToken, validateUpdate, authController.updateProfile);
router.get('/recover-key', authenticateToken, authController.recoverKey);
router.get('/key-availability', authenticateToken, authController.checkKeyAvailability);
router.post('/sync-keys', authenticateToken, authController.syncKeys);
router.delete('/delete-keys', authenticateToken, authController.deleteKeys);

// Admin route (optional)
router.get('/all-users', authenticateToken, authController.getAllUsers);

module.exports = router;
