const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const fs = require('fs').promises;
const path = require('path');
const { validationResult } = require('express-validator');
require('dotenv').config();

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_change_this';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your_encryption_key_32_chars_long';

// Firebase configuration
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
const FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL;
const FIREBASE_STORAGE_BUCKET = process.env.FIREBASE_STORAGE_BUCKET;

// Simulated user storage (replace with proper database in production)
let users = [];

// Firebase Admin initialization
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: FIREBASE_PROJECT_ID,
            privateKey: FIREBASE_PRIVATE_KEY,
            clientEmail: FIREBASE_CLIENT_EMAIL,
        }),
        storageBucket: FIREBASE_STORAGE_BUCKET
    });
}

// Get Firebase Storage bucket
const bucket = admin.storage().bucket();

// Helper functions
function findUser({ gmail, number }) {
    return users.find(u => u.gmail === gmail || u.number === number);
}

async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

async function comparePassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

function encryptPrivateKey(privateKey, encryptionKey) {
    const cipher = crypto.createCipher('aes-256-cbc', encryptionKey);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decryptPrivateKey(encryptedKey, encryptionKey) {
    const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
    let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

async function savePrivateKeyLocally(gmail, privateKey) {
    try {
        const dir = path.join(__dirname, '../user_keys');
        
        try {
            await fs.access(dir);
        } catch {
            await fs.mkdir(dir, { recursive: true });
        }
        
        const encryptedKey = encryptPrivateKey(privateKey, ENCRYPTION_KEY);
        await fs.writeFile(path.join(dir, `${gmail}_private.key`), encryptedKey, 'utf8');
        
        console.log(`Private key saved locally for ${gmail}`);
    } catch (error) {
        console.error('Error saving private key locally:', error);
        throw error;
    }
}

// Firebase Cloud Storage: Upload encrypted private key
async function uploadPrivateKeyToFirebase(gmail, privateKey) {
    try {
        // Encrypt before uploading
        const encryptedKey = encryptPrivateKey(privateKey, ENCRYPTION_KEY);
        
        const fileName = `private_keys/${gmail}_private.key`;
        const file = bucket.file(fileName);
        
        // Upload the encrypted key
        await file.save(encryptedKey, {
            metadata: {
                contentType: 'text/plain',
                metadata: {
                    encrypted: 'true',
                    user: gmail,
                    uploadTime: new Date().toISOString()
                }
            }
        });
        
        console.log(`Private key uploaded to Firebase Storage for ${gmail}`);
    } catch (error) {
        console.error('Error uploading to Firebase Storage:', error);
        throw error;
    }
}

// Firebase Cloud Storage: Retrieve private key
async function getPrivateKeyFromFirebase(gmail) {
    try {
        const fileName = `private_keys/${gmail}_private.key`;
        const file = bucket.file(fileName);
        
        // Check if file exists
        const [exists] = await file.exists();
        if (!exists) {
            throw new Error(`Private key not found for ${gmail}`);
        }
        
        // Download the file
        const [data] = await file.download();
        const encryptedKey = data.toString();
        
        // Decrypt the key
        const privateKey = decryptPrivateKey(encryptedKey, ENCRYPTION_KEY);
        return privateKey;
    } catch (error) {
        console.error('Error retrieving from Firebase Storage:', error);
        throw error;
    }
}

// Firebase Cloud Storage: Delete private key
async function deletePrivateKeyFromFirebase(gmail) {
    try {
        const fileName = `private_keys/${gmail}_private.key`;
        const file = bucket.file(fileName);
        
        await file.delete();
        console.log(`Private key deleted from Firebase Storage for ${gmail}`);
    } catch (error) {
        console.error('Error deleting from Firebase Storage:', error);
        throw error;
    }
}

// Firebase Cloud Storage: Check if private key exists
async function checkPrivateKeyExistsInFirebase(gmail) {
    try {
        const fileName = `private_keys/${gmail}_private.key`;
        const file = bucket.file(fileName);
        
        const [exists] = await file.exists();
        return exists;
    } catch (error) {
        console.error('Error checking Firebase Storage:', error);
        return false;
    }
}

// Get private key locally with Firebase fallback
async function getPrivateKeyWithFallback(gmail) {
    try {
        // Try local storage first
        const dir = path.join(__dirname, '../user_keys');
        const keyPath = path.join(dir, `${gmail}_private.key`);
        
        const encryptedKey = await fs.readFile(keyPath, 'utf8');
        return decryptPrivateKey(encryptedKey, ENCRYPTION_KEY);
    } catch (localError) {
        console.log(`Local key not found for ${gmail}, trying Firebase...`);
        
        // Fallback to Firebase
        try {
            const privateKey = await getPrivateKeyFromFirebase(gmail);
            
            // Save back to local for future use
            try {
                await savePrivateKeyLocally(gmail, privateKey);
                console.log(`Key synced back to local storage for ${gmail}`);
            } catch (syncError) {
                console.warn(`Failed to sync key to local: ${syncError.message}`);
            }
            
            return privateKey;
        } catch (firebaseError) {
            throw new Error(`Private key not found in local or Firebase storage: ${firebaseError.message}`);
        }
    }
}

function generateDID(publicKey) {
    return `did:key:${publicKey.substring(0, 44)}`;
}

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

// Controller Class
class MainController {
    // Signup function
    async signup(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    error: 'Validation failed', 
                    details: errors.array() 
                });
            }

            const { gmail, password, name, number } = req.body;

            if (findUser({ gmail, number })) {
                return res.status(409).json({ 
                    error: 'Account with this email or phone number already exists' 
                });
            }

            const hashedPassword = await hashPassword(password);
            const { publicKey, privateKey } = generateKeyPair();
            const did = generateDID(publicKey);
            const sessionPrivateKey = crypto.randomBytes(32).toString('hex');

            try {
                // Save to both local and Firebase
                await savePrivateKeyLocally(gmail, sessionPrivateKey);
                await uploadPrivateKeyToFirebase(gmail, sessionPrivateKey);
            } catch (storageError) {
                return res.status(500).json({ 
                    error: 'Failed to secure private key storage',
                    details: storageError.message 
                });
            }

            const user = {
                gmail,
                password: hashedPassword,
                name,
                number,
                did,
                publicKey,
                cryptoPrivateKey: privateKey,
                createdAt: new Date().toISOString()
            };
            
            users.push(user);

            const token = jwt.sign(
                { gmail, did, name }, 
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
    }

    // Login function
    async login(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    error: 'Validation failed', 
                    details: errors.array() 
                });
            }

            const { gmail, password } = req.body;
            
            const user = users.find(u => u.gmail === gmail);
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const validPassword = await comparePassword(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

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
    }

    // Get profile function
    async getProfile(req, res) {
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
    }

    // Recover key function with fallback
    async recoverKey(req, res) {
        try {
            const gmail = req.user.gmail;
            const privateKey = await getPrivateKeyWithFallback(gmail);
            
            res.json({
                message: 'Private key recovered successfully',
                privateKey: privateKey,
                source: 'recovered'
            });
            
        } catch (error) {
            console.error('Key recovery error:', error);
            res.status(500).json({ 
                error: 'Failed to recover private key',
                details: error.message 
            });
        }
    }

    // Check key availability
    async checkKeyAvailability(req, res) {
        try {
            const gmail = req.user.gmail;
            
            // Check local storage
            let localExists = false;
            try {
                const dir = path.join(__dirname, '../user_keys');
                const keyPath = path.join(dir, `${gmail}_private.key`);
                await fs.access(keyPath);
                localExists = true;
            } catch {
                localExists = false;
            }

            // Check Firebase storage
            const firebaseExists = await checkPrivateKeyExistsInFirebase(gmail);

            res.json({
                gmail,
                keyAvailability: {
                    local: localExists,
                    firebase: firebaseExists
                },
                recommendation: localExists && firebaseExists 
                    ? 'Keys available in both locations. Fully backed up.'
                    : localExists && !firebaseExists
                    ? 'Local key found but not in Firebase. Consider backup.'
                    : !localExists && firebaseExists
                    ? 'Firebase backup found but not local. Consider sync.'
                    : 'No keys found. This is a serious issue.'
            });

        } catch (error) {
            console.error('Check availability error:', error);
            res.status(500).json({ 
                error: 'Failed to check key availability', 
                details: error.message 
            });
        }
    }

    // Delete keys
    async deleteKeys(req, res) {
        try {
            const gmail = req.user.gmail;
            const { location } = req.body; // 'local', 'firebase', or 'both'

            let result = { gmail, location };

            if (location === 'local' || location === 'both') {
                try {
                    const dir = path.join(__dirname, '../user_keys');
                    const keyPath = path.join(dir, `${gmail}_private.key`);
                    await fs.unlink(keyPath);
                    result.localDeleted = true;
                } catch (error) {
                    result.localError = error.message;
                }
            }

            if (location === 'firebase' || location === 'both') {
                try {
                    await deletePrivateKeyFromFirebase(gmail);
                    result.firebaseDeleted = true;
                } catch (error) {
                    result.firebaseError = error.message;
                }
            }

            res.json({
                message: 'Key deletion completed',
                result
            });

        } catch (error) {
            console.error('Delete keys error:', error);
            res.status(500).json({ 
                error: 'Failed to delete keys', 
                details: error.message 
            });
        }
    }
}

module.exports = new MainController();

