// controllers/authController.js
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const admin = require('firebase-admin');
const fs = require('fs').promises;
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your_encryption_key_32_chars_long';

// Simulated user storage (replace with proper database)
let users = [];

// Firebase setup
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        }),
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET
    });
}

const bucket = admin.storage().bucket();

class AuthController {
    async signup(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { gmail, password, name, number } = req.body;

            // Check if user exists
            const existingUser = users.find(u => u.gmail === gmail || u.number === number);
            if (existingUser) {
                return res.status(409).json({ error: 'Account with this email or phone already exists' });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 12);

            // Generate cryptographic key pair for DID
            const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            });

            // Generate DID
            const did = `did:key:${publicKey.substring(0, 44)}`;

            // Generate session private key
            const sessionPrivateKey = crypto.randomBytes(32).toString('hex');

            try {
                // Save keys securely to both local and Firebase
                await this.savePrivateKeyLocally(gmail, sessionPrivateKey);
                console.log(`Local key saved for ${gmail}`);
                
                await this.uploadPrivateKeyToFirebase(gmail, sessionPrivateKey);
                console.log(`Firebase key saved for ${gmail}`);
            } catch (storageError) {
                console.error('Storage error:', storageError);
                return res.status(500).json({ 
                    error: 'Failed to secure private key storage',
                    details: storageError.message 
                });
            }

            // Save user
            const user = {
                gmail,
                password: hashedPassword,
                name,
                number,
                did,
                publicKey,
                cryptoPrivateKey: privateKey,
                sessionPrivateKey, // Keep reference for internal use
                createdAt: new Date().toISOString()
            };
            users.push(user);

            // Create JWT
            const token = jwt.sign({ gmail, did, name }, JWT_SECRET, { expiresIn: '24h' });

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
            res.status(500).json({ error: 'Internal server error during signup', details: error.message });
        }
    }

    async login(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { gmail, password } = req.body;

            const user = users.find(u => u.gmail === gmail);
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign({ gmail: user.gmail, did: user.did, name: user.name }, JWT_SECRET, { expiresIn: '24h' });

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
            res.status(500).json({ error: 'Internal server error during login', details: error.message });
        }
    }

    async getProfile(req, res) {
        try {
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
        } catch (error) {
            console.error('Get profile error:', error);
            res.status(500).json({ error: 'Failed to get profile', details: error.message });
        }
    }

    async recoverKey(req, res) {
        try {
            const gmail = req.user.gmail;
            let privateKey;
            let source;

            try {
                // Try local storage first (faster access)
                privateKey = await this.getPrivateKeyLocally(gmail);
                source = 'local';
                console.log(`Key recovered from local storage for ${gmail}`);
            } catch (localError) {
                console.log(`Local key not found for ${gmail}, trying Firebase storage...`);
                
                try {
                    // Fallback to Firebase storage
                    privateKey = await this.getPrivateKeyFromFirebase(gmail);
                    source = 'firebase';
                    console.log(`Key recovered from Firebase storage for ${gmail}`);
                    
                    // Optionally save back to local for future use
                    try {
                        await this.savePrivateKeyLocally(gmail, privateKey);
                        console.log(`Key synced back to local storage for ${gmail}`);
                    } catch (syncError) {
                        console.warn(`Failed to sync key to local storage: ${syncError.message}`);
                    }
                } catch (firebaseError) {
                    throw new Error('Key not found in local or Firebase storage');
                }
            }

            res.json({
                message: 'Private key recovered successfully',
                privateKey,
                source,
                gmail
            });
        } catch (error) {
            console.error('Key recovery error:', error);
            res.status(500).json({ 
                error: 'Failed to recover private key', 
                details: error.message 
            });
        }
    }

    async checkKeyAvailability(req, res) {
        try {
            const gmail = req.user.gmail;
            const availability = {
                local: false,
                firebase: false,
                lastChecked: new Date().toISOString()
            };

            // Check local storage
            try {
                await this.getPrivateKeyLocally(gmail);
                availability.local = true;
            } catch (error) {
                availability.local = false;
            }

            // Check Firebase storage
            try {
                const exists = await this.checkPrivateKeyExistsInFirebase(gmail);
                availability.firebase = exists;
            } catch (error) {
                availability.firebase = false;
            }

            res.json({
                gmail,
                keyAvailability: availability,
                recommendation: this.getKeyRecommendation(availability)
            });
        } catch (error) {
            console.error('Check availability error:', error);
            res.status(500).json({ 
                error: 'Failed to check key availability', 
                details: error.message 
            });
        }
    }

    async syncKeys(req, res) {
        try {
            const gmail = req.user.gmail;
            const { direction } = req.body; // 'local-to-firebase' or 'firebase-to-local'

            let privateKey;
            let syncResult = {
                gmail,
                direction,
                success: false,
                message: ''
            };

            if (direction === 'local-to-firebase') {
                // Sync from local to Firebase
                privateKey = await this.getPrivateKeyLocally(gmail);
                await this.uploadPrivateKeyToFirebase(gmail, privateKey);
                syncResult.success = true;
                syncResult.message = 'Key synced from local to Firebase successfully';
            } else if (direction === 'firebase-to-local') {
                // Sync from Firebase to local
                privateKey = await this.getPrivateKeyFromFirebase(gmail);
                await this.savePrivateKeyLocally(gmail, privateKey);
                syncResult.success = true;
                syncResult.message = 'Key synced from Firebase to local successfully';
            } else {
                return res.status(400).json({ 
                    error: 'Invalid sync direction', 
                    details: 'Direction must be "local-to-firebase" or "firebase-to-local"' 
                });
            }

            res.json(syncResult);
        } catch (error) {
            console.error('Key sync error:', error);
            res.status(500).json({ 
                error: 'Failed to sync keys', 
                details: error.message 
            });
        }
    }

    async deleteKeys(req, res) {
        try {
            const gmail = req.user.gmail;
            const { location } = req.body; // 'local', 'firebase', or 'both'

            let deletionResult = {
                gmail,
                location,
                local: { deleted: false, error: null },
                firebase: { deleted: false, error: null }
            };

            if (location === 'local' || location === 'both') {
                try {
                    await this.deletePrivateKeyLocally(gmail);
                    deletionResult.local.deleted = true;
                } catch (error) {
                    deletionResult.local.error = error.message;
                }
            }

            if (location === 'firebase' || location === 'both') {
                try {
                    await this.deletePrivateKeyFromFirebase(gmail);
                    deletionResult.firebase.deleted = true;
                } catch (error) {
                    deletionResult.firebase.error = error.message;
                }
            }

            res.json({
                message: 'Key deletion completed',
                result: deletionResult
            });
        } catch (error) {
            console.error('Key deletion error:', error);
            res.status(500).json({ 
                error: 'Failed to delete keys', 
                details: error.message 
            });
        }
    }

    // Get all users (admin only - for testing)
    async getAllUsers(req, res) {
        try {
            // Remove sensitive data before sending
            const safeUsers = users.map(user => ({
                gmail: user.gmail,
                name: user.name,
                number: user.number,
                did: user.did,
                publicKey: user.publicKey,
                createdAt: user.createdAt
            }));

            res.json({
                users: safeUsers,
                count: safeUsers.length
            });
        } catch (error) {
            console.error('Get all users error:', error);
            res.status(500).json({ error: 'Failed to get users', details: error.message });
        }
    }

    // Update user profile
    async updateProfile(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const gmail = req.user.gmail;
            const { name, number } = req.body;

            const userIndex = users.findIndex(u => u.gmail === gmail);
            if (userIndex === -1) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Check if new number is already taken by another user
            if (number) {
                const existingUser = users.find(u => u.number === number && u.gmail !== gmail);
                if (existingUser) {
                    return res.status(409).json({ error: 'Phone number already taken' });
                }
            }

            // Update user data
            if (name) users[userIndex].name = name;
            if (number) users[userIndex].number = number;
            users[userIndex].updatedAt = new Date().toISOString();

            res.json({
                message: 'Profile updated successfully',
                user: {
                    gmail: users[userIndex].gmail,
                    name: users[userIndex].name,
                    number: users[userIndex].number,
                    did: users[userIndex].did,
                    publicKey: users[userIndex].publicKey,
                    updatedAt: users[userIndex].updatedAt
                }
            });
        } catch (error) {
            console.error('Update profile error:', error);
            res.status(500).json({ error: 'Failed to update profile', details: error.message });
        }
    }

    // Helper methods for encryption
    async encryptPrivateKey(privateKey, encryptionKey) {
        const cipher = crypto.createCipher('aes-256-cbc', encryptionKey);
        let encrypted = cipher.update(privateKey, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    }

    async decryptPrivateKey(encryptedKey, encryptionKey) {
        const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
        let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

    // Local storage methods
    async savePrivateKeyLocally(gmail, privateKey) {
        const dir = path.join(__dirname, '../user_keys');
        try {
            await fs.access(dir);
        } catch {
            await fs.mkdir(dir, { recursive: true });
        }
        
        const encryptedKey = await this.encryptPrivateKey(privateKey, ENCRYPTION_KEY);
        const keyPath = path.join(dir, `${gmail}_private.key`);
        await fs.writeFile(keyPath, encryptedKey, 'utf8');
    }

    async getPrivateKeyLocally(gmail) {
        const dir = path.join(__dirname, '../user_keys');
        const keyPath = path.join(dir, `${gmail}_private.key`);
        
        try {
            const encryptedKey = await fs.readFile(keyPath, 'utf8');
            return await this.decryptPrivateKey(encryptedKey, ENCRYPTION_KEY);
        } catch (error) {
            throw new Error(`Local key not found for ${gmail}: ${error.message}`);
        }
    }

    async deletePrivateKeyLocally(gmail) {
        const dir = path.join(__dirname, '../user_keys');
        const keyPath = path.join(dir, `${gmail}_private.key`);
        
        try {
            await fs.unlink(keyPath);
        } catch (error) {
            throw new Error(`Failed to delete local key for ${gmail}: ${error.message}`);
        }
    }

    // Firebase storage methods
    async uploadPrivateKeyToFirebase(gmail, privateKey) {
        try {
            const encryptedKey = await this.encryptPrivateKey(privateKey, ENCRYPTION_KEY);
            
            const fileName = `private_keys/${gmail}_private.key`;
            const file = bucket.file(fileName);
            
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
            
            console.log(`Private key uploaded to Firebase for ${gmail}`);
        } catch (error) {
            console.error('Error uploading to Firebase:', error);
            throw error;
        }
    }

    async getPrivateKeyFromFirebase(gmail) {
        try {
            const fileName = `private_keys/${gmail}_private.key`;
            const file = bucket.file(fileName);
            
            const [exists] = await file.exists();
            if (!exists) {
                throw new Error(`Private key not found for ${gmail}`);
            }
            
            const [data] = await file.download();
            const encryptedKey = data.toString();
            
            return await this.decryptPrivateKey(encryptedKey, ENCRYPTION_KEY);
        } catch (error) {
            throw new Error(`Firebase key not found for ${gmail}: ${error.message}`);
        }
    }

    async deletePrivateKeyFromFirebase(gmail) {
        try {
            const fileName = `private_keys/${gmail}_private.key`;
            const file = bucket.file(fileName);
            
            await file.delete();
            console.log(`Private key deleted from Firebase for ${gmail}`);
        } catch (error) {
            throw new Error(`Failed to delete Firebase key for ${gmail}: ${error.message}`);
        }
    }

    async checkPrivateKeyExistsInFirebase(gmail) {
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

    // Utility methods
    getKeyRecommendation(availability) {
        if (availability.local && availability.firebase) {
            return 'Keys are available in both locations. System is fully backed up.';
        } else if (availability.local && !availability.firebase) {
            return 'Key found locally but not in Firebase. Consider syncing to Firebase for backup.';
        } else if (!availability.local && availability.firebase) {
            return 'Key found in Firebase but not locally. Consider syncing to local for faster access.';
        } else {
            return 'No keys found. This may indicate a serious issue. Contact support.';
        }
    }
}

module.exports = new AuthController();
