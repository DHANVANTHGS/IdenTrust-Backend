const express = require('express');
const { body } = require('express-validator');
const main = require('../controllers/main_logic.cjs');
const router = express.Router();

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

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    const jwt = require('jsonwebtoken');
    const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_change_this';
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

router.post('/login', validateLogin, main.login);
router.post('/addUser', validateSignup, main.signup);
router.get('/profile', authenticateToken, main.getProfile);
router.get('/recover-key', authenticateToken, main.recoverKey);
router.get('/key-availability', authenticateToken, main.checkKeyAvailability);
router.delete('/delete-keys', authenticateToken, main.deleteKeys);

module.exports = router;
