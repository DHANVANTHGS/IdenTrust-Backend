const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const AWS = require('aws-sdk');
const fs = require('fs').promises;
const path = require('path');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const router = express.Router();

// Environment variables (create a .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_change_this';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your_encryption_key_32_chars_long';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const S3_BUCKET = process.env.S3_BUCKET || 'your-ssi-bucket';

// Simulated user storage (replace with proper database in production)
let users = [];

// AWS S3 setup
const s3 = new AWS.S3({
    region: AWS_REGION,
    accessKeyId: AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY
});

// Helper: Find user by gmail or number
function findUser({ gmail, number }) {
    return users.find(u => u.gmail === gmail || u.number === number);
}

// Helper: Hash password
async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

// Helper: Compare password
async function comparePassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// Helper: Encrypt private key
function encryptPrivateKey(privateKey, encryptionKey) {
    const cipher = crypto.createCipher('aes-256-cbc', encryptionKey);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Helper: Decrypt private key
function decryptPrivateKey(encryptedKey, encryptionKey) {
    const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
    let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Helper: Save encrypted private key locally
async function savePrivateKeyLocally(gmail, privateKey) {
    try {
        const dir = path.join(__dirname, '../user_keys');
        
        // Create directory if it doesn't exist
        try {
            await fs.access(dir);
        } catch {
            await fs.mkdir(dir, { recursive: true });
        }
        
        // Encrypt before saving
        const encryptedKey = encryptPrivateKey(privateKey, ENCRYPTION_KEY);
        await fs.writeFile(path.join(dir, `${gmail}_private.key`), encryptedKey, 'utf8');
        
        console.log(`Private key saved locally for ${gmail}`);
    } catch (error) {
        console.error('Error saving private key locally:', error);
        throw error;
    }
}

// Helper: Upload encrypted private key to S3
async function uploadPrivateKeyToS3(gmail, privateKey) {
    try {
        // Encrypt before uploading
        const encryptedKey = encryptPrivateKey(privateKey, ENCRYPTION_KEY);
        
        const params = {
            Bucket: S3_BUCKET,
            Key: `private_keys/${gmail}_private.key`,
            Body: encryptedKey,
            ServerSideEncryption: 'AES256', // Additional S3 encryption
            ContentType: 'text/plain'
        };
        
        await s3.putObject(params).promise();
        console.log(`Private key uploaded to S3 for ${gmail}`);
    } catch (error) {
        console.error('Error uploading to S3:', error);
        throw error;
    }
}

// Helper: Retrieve private key from S3
async function getPrivateKeyFromS3(gmail) {
    try {
        const params = {
            Bucket: S3_BUCKET,
            Key: `private_keys/${gmail}_private.key`
        };
        
        const data = await s3.getObject(params).promise();
        const encryptedKey = data.Body.toString();
        
        // Decrypt the key
        const privateKey = decryptPrivateKey(encryptedKey, ENCRYPTION_KEY);
        return privateKey;
    } catch (error) {
        console.error('Error retrieving from S3:', error);
        throw error;
    }
}

// Helper: Generate DID (simplified)
function generateDID(publicKey) {
    return `did:key:${publicKey.substring(0, 44)}`;
}

// Helper: Generate key pair for DID
function generateKeyPair() {
    const keyPair = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
    };
}

// Input validation middleware
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

// Signup endpoint
router.post('/signup', validateSignup, async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors.array() 
            });
        }

        const { gmail, password, name, number } = req.body;

        // Check if user already exists
        if (findUser({ gmail, number })) {
            return res.status(409).json({ 
                error: 'Account with this email or phone number already exists' 
            });
        }

        // Hash password
        const hashedPassword = await hashPassword(password);

        // Generate cryptographic key pair for DID
        const { publicKey, privateKey } = generateKeyPair();
        
        // Generate DID
        const did = generateDID(publicKey);

        // Generate session private key (for encryption/decryption)
        const sessionPrivateKey = crypto.randomBytes(32).toString('hex');

        try {
            // Save private key locally (encrypted)
            await savePrivateKeyLocally(gmail, sessionPrivateKey);
            
            // Upload private key to S3 (encrypted)
            await uploadPrivateKeyToS3(gmail, sessionPrivateKey);
        } catch (storageError) {
            return res.status(500).json({ 
                error: 'Failed to secure private key storage',
                details: storageError.message 
            });
        }

        // Save user (in production, use a proper database)
        const user = {
            gmail,
            password: hashedPassword,
            name,
            number,
            did,
            publicKey,
            cryptoPrivateKey: privateKey, // For DID operations
            createdAt: new Date().toISOString()
        };
        
        users.push(user);

        // Create JWT token
        const token = jwt.sign(
            { 
                gmail, 
                did,
                name 
            }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'Account created successfully',
            token,
            user: {
                gmail: user.gmail,
                name: user.name,
                did: user.did,
                publicKey: user.publicKey
            }
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ 
            error: 'Internal server error during signup',
            details: error.message 
        });
    }
});

// Login endpoint
router.post('/login', validateLogin, async (req, res) => {
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors.array() 
            });
        }

        const { gmail, password } = req.body;
        
        // Find user
        const user = users.find(u => u.gmail === gmail);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await comparePassword(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create JWT token
        const token = jwt.sign(
            { 
                gmail: user.gmail, 
                did: user.did,
                name: user.name 
            }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                gmail: user.gmail,
                name: user.name,
                did: user.did,
                publicKey: user.publicKey
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            error: 'Internal server error during login',
            details: error.message 
        });
    }
});

// Get user profile endpoint (protected)
router.get('/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.gmail === req.user.gmail);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    res.json({
        gmail: user.gmail,
        name: user.name,
        number: user.number,
        did: user.did,
        publicKey: user.publicKey,
        createdAt: user.createdAt
    });
});

// Recover private key endpoint (protected)
router.get('/recover-key', authenticateToken, async (req, res) => {
    try {
        const gmail = req.user.gmail;
        
        // Try to get private key from S3
        const privateKey = await getPrivateKeyFromS3(gmail);
        
        res.json({
            message: 'Private key recovered successfully',
            privateKey: privateKey // In production, handle this more securely
        });
        
    } catch (error) {
        console.error('Key recovery error:', error);
        res.status(500).json({ 
            error: 'Failed to recover private key',
            details: error.message 
        });
    }
});

// JWT authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

module.exports = router;
