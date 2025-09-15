// controllers/ipfsController.js
const { validationResult } = require('express-validator');
const { create } = require('ipfs-http-client');
const CryptoJS = require('crypto-js');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const admin = require('firebase-admin');

// Initialize IPFS client
const ipfs = create({
  url: process.env.IPFS_URL || 'https://ipfs.infura.io:5001/api/v0'
});

// Firebase setup (reuse from authController)
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
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your_encryption_key_32_chars_long';

// In-memory storage for user sensitive data (replace with database)
let userSensitiveData = new Map();

class IPFSController {
    // Upload sensitive user data to IPFS and store locally
    async uploadSensitiveData(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { data, dataType, description } = req.body;
            const userGmail = req.user.gmail;
            const userEncryptionKey = await this.getUserEncryptionKey(userGmail);

            // Encrypt sensitive data with user's specific key
            const encryptedData = CryptoJS.AES.encrypt(JSON.stringify(data), userEncryptionKey).toString();

            // Upload to IPFS
            const { cid } = await ipfs.add(encryptedData);
            const ipfsHash = cid.toString();

            // Store metadata locally
            const sensitiveDataRecord = {
                id: `${userGmail}_${Date.now()}`,
                ipfsHash,
                dataType,
                description,
                createdAt: new Date().toISOString(),
                userGmail,
                encrypted: true,
                size: encryptedData.length
            };

            // Save to local storage
            await this.saveSensitiveDataLocally(userGmail, sensitiveDataRecord);

            // Store in memory map
            if (!userSensitiveData.has(userGmail)) {
                userSensitiveData.set(userGmail, []);
            }
            userSensitiveData.get(userGmail).push(sensitiveDataRecord);

            res.json({
                message: 'Sensitive data uploaded and secured successfully',
                dataId: sensitiveDataRecord.id,
                ipfsHash,
                dataType,
                description,
                createdAt: sensitiveDataRecord.createdAt,
                size: sensitiveDataRecord.size
            });

        } catch (error) {
            console.error('Sensitive data upload error:', error);
            res.status(500).json({ error: 'Failed to upload sensitive data', details: error.message });
        }
    }

    // Retrieve user's sensitive data from IPFS
    async retrieveSensitiveData(req, res) {
        try {
            const { dataId } = req.params;
            const userGmail = req.user.gmail;

            // Get data record from local storage or memory
            const dataRecord = await this.getSensitiveDataRecord(userGmail, dataId);
            if (!dataRecord) {
                return res.status(404).json({ error: 'Sensitive data not found' });
            }

            // Get user's encryption key
            const userEncryptionKey = await this.getUserEncryptionKey(userGmail);

            // Retrieve from IPFS
            const stream = ipfs.cat(dataRecord.ipfsHash);
            let encryptedData = '';
            for await (const chunk of stream) {
                encryptedData += chunk.toString();
            }

            // Decrypt the data
            const bytes = CryptoJS.AES.decrypt(encryptedData, userEncryptionKey);
            const decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

            res.json({
                dataId: dataRecord.id,
                data: decryptedData,
                dataType: dataRecord.dataType,
                description: dataRecord.description,
                createdAt: dataRecord.createdAt,
                ipfsHash: dataRecord.ipfsHash
            });

        } catch (error) {
            console.error('Sensitive data retrieval error:', error);
            res.status(500).json({ error: 'Failed to retrieve sensitive data', details: error.message });
        }
    }

    // Get all user's sensitive data records (metadata only)
    async getUserSensitiveDataList(req, res) {
        try {
            const userGmail = req.user.gmail;
            
            // Get from local storage
            const localRecords = await this.getAllSensitiveDataLocally(userGmail);
            
            // Get from memory (as backup)
            const memoryRecords = userSensitiveData.get(userGmail) || [];

            // Combine and deduplicate
            const allRecords = this.deduplicateRecords([...localRecords, ...memoryRecords]);

            // Return metadata only (no actual sensitive data)
            const safeRecords = allRecords.map(record => ({
                dataId: record.id,
                dataType: record.dataType,
                description: record.description,
                createdAt: record.createdAt,
                ipfsHash: record.ipfsHash,
                size: record.size || 0
            }));

            res.json({
                userGmail,
                sensitiveDataRecords: safeRecords,
                count: safeRecords.length,
                totalSize: safeRecords.reduce((sum, record) => sum + (record.size || 0), 0)
            });

        } catch (error) {
            console.error('Get sensitive data list error:', error);
            res.status(500).json({ error: 'Failed to get sensitive data list', details: error.message });
        }
    }

    // Delete sensitive data (from IPFS and local storage)
    async deleteSensitiveData(req, res) {
        try {
            const { dataId } = req.params;
            const userGmail = req.user.gmail;

            // Get data record
            const dataRecord = await this.getSensitiveDataRecord(userGmail, dataId);
            if (!dataRecord) {
                return res.status(404).json({ error: 'Sensitive data not found' });
            }

            // Remove from local storage
            await this.deleteSensitiveDataLocally(userGmail, dataId);

            // Remove from memory
            if (userSensitiveData.has(userGmail)) {
                const userRecords = userSensitiveData.get(userGmail);
                const filteredRecords = userRecords.filter(record => record.id !== dataId);
                userSensitiveData.set(userGmail, filteredRecords);
            }

            // Note: IPFS data is immutable and can't be deleted, but we remove references
            res.json({
                message: 'Sensitive data deleted successfully',
                dataId,
                note: 'Data references removed. IPFS data remains immutable but inaccessible without the key.'
            });

        } catch (error) {
            console.error('Delete sensitive data error:', error);
            res.status(500).json({ error: 'Failed to delete sensitive data', details: error.message });
        }
    }

    // ADDED: Missing methods from router
    async uploadToIPFS(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { data, encrypt = false, encryptionKey } = req.body;
            let uploadData = data;

            // Encrypt data if requested
            if (encrypt && encryptionKey) {
                uploadData = CryptoJS.AES.encrypt(JSON.stringify(data), encryptionKey).toString();
            }

            const { cid } = await ipfs.add(uploadData);
            const hash = cid.toString();

            res.json({
                message: 'Data uploaded to IPFS successfully',
                ipfsHash: hash,
                encrypted: encrypt,
                size: uploadData.length
            });
        } catch (error) {
            console.error('IPFS upload error:', error);
            res.status(500).json({ error: 'Failed to upload to IPFS', details: error.message });
        }
    }

    async retrieveFromIPFS(req, res) {
        try {
            const { hash } = req.params;
            const { decrypt = false, encryptionKey } = req.query;

            const stream = ipfs.cat(hash);
            let data = '';

            for await (const chunk of stream) {
                data += chunk.toString();
            }

            // Decrypt if requested
            if (decrypt === 'true' && encryptionKey) {
                try {
                    const bytes = CryptoJS.AES.decrypt(data, encryptionKey);
                    data = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
                } catch (decryptError) {
                    return res.status(400).json({ error: 'Failed to decrypt data', details: decryptError.message });
                }
            }

            res.json({
                ipfsHash: hash,
                data,
                decrypted: decrypt === 'true'
            });
        } catch (error) {
            console.error('IPFS retrieval error:', error);
            res.status(404).json({ error: 'Failed to retrieve from IPFS', details: error.message });
        }
    }

    async pinToIPFS(req, res) {
        try {
            const { hash } = req.params;

            await ipfs.pin.add(hash);

            res.json({
                message: 'Data pinned to IPFS successfully',
                ipfsHash: hash
            });
        } catch (error) {
            console.error('IPFS pin error:', error);
            res.status(500).json({ error: 'Failed to pin to IPFS', details: error.message });
        }
    }

    // ADDED: New batch operations
    async batchUploadSensitiveData(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { dataItems } = req.body;
            const userGmail = req.user.gmail;

            if (dataItems.length > 10) {
                return res.status(400).json({ error: 'Maximum 10 items per batch' });
            }

            const results = [];
            const userEncryptionKey = await this.getUserEncryptionKey(userGmail);

            for (const item of dataItems) {
                try {
                    const { data, dataType, description } = item;

                    // Encrypt sensitive data
                    const encryptedData = CryptoJS.AES.encrypt(JSON.stringify(data), userEncryptionKey).toString();

                    // Upload to IPFS
                    const { cid } = await ipfs.add(encryptedData);
                    const ipfsHash = cid.toString();

                    const sensitiveDataRecord = {
                        id: `${userGmail}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                        ipfsHash,
                        dataType,
                        description,
                        createdAt: new Date().toISOString(),
                        userGmail,
                        encrypted: true,
                        size: encryptedData.length
                    };

                    await this.saveSensitiveDataLocally(userGmail, sensitiveDataRecord);

                    results.push({
                        success: true,
                        dataId: sensitiveDataRecord.id,
                        ipfsHash,
                        dataType,
                        description
                    });

                } catch (error) {
                    results.push({
                        success: false,
                        error: error.message,
                        dataType: item.dataType
                    });
                }
            }

            const summary = {
                total: results.length,
                successful: results.filter(r => r.success).length,
                failed: results.filter(r => !r.success).length
            };

            res.json({
                message: 'Batch upload completed',
                summary,
                results
            });

        } catch (error) {
            console.error('Batch upload error:', error);
            res.status(500).json({ error: 'Failed to batch upload sensitive data', details: error.message });
        }
    }

    // Helper methods with Firebase
    async getUserEncryptionKey(userGmail) {
        try {
            // Try local storage first
            return await this.getPrivateKeyLocally(userGmail);
        } catch (localError) {
            // Fallback to Firebase storage
            try {
                return await this.getPrivateKeyFromFirebase(userGmail);
            } catch (firebaseError) {
                throw new Error(`Failed to get user encryption key: ${firebaseError.message}`);
            }
        }
    }

    // Firebase methods (replacing S3)
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

    // Encryption methods
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

    // Local storage methods
    async saveSensitiveDataLocally(userGmail, dataRecord) {
        const dir = path.join(__dirname, '../user_sensitive_data');
        const userDir = path.join(dir, userGmail);
        
        try {
            await fs.access(userDir);
        } catch {
            await fs.mkdir(userDir, { recursive: true });
        }

        const filePath = path.join(userDir, 'sensitive_data_records.json');
        
        let existingRecords = [];
        try {
            const existingData = await fs.readFile(filePath, 'utf8');
            existingRecords = JSON.parse(existingData);
        } catch (error) {
            // File doesn't exist, start with empty array
        }

        existingRecords.push(dataRecord);
        await fs.writeFile(filePath, JSON.stringify(existingRecords, null, 2));
    }

    async getAllSensitiveDataLocally(userGmail) {
        const dir = path.join(__dirname, '../user_sensitive_data');
        const filePath = path.join(dir, userGmail, 'sensitive_data_records.json');
        
        try {
            const data = await fs.readFile(filePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            return []; // No records found
        }
    }

    async getSensitiveDataRecord(userGmail, dataId) {
        const localRecords = await this.getAllSensitiveDataLocally(userGmail);
        const memoryRecords = userSensitiveData.get(userGmail) || [];
        const allRecords = [...localRecords, ...memoryRecords];
        
        return allRecords.find(record => record.id === dataId);
    }

    async deleteSensitiveDataLocally(userGmail, dataId) {
        const dir = path.join(__dirname, '../user_sensitive_data');
        const filePath = path.join(dir, userGmail, 'sensitive_data_records.json');
        
        try {
            const existingRecords = await this.getAllSensitiveDataLocally(userGmail);
            const filteredRecords = existingRecords.filter(record => record.id !== dataId);
            await fs.writeFile(filePath, JSON.stringify(filteredRecords, null, 2));
        } catch (error) {
            console.error('Error deleting from local storage:', error);
        }
    }

    deduplicateRecords(records) {
        const seen = new Set();
        return records.filter(record => {
            const key = record.id;
            if (seen.has(key)) {
                return false;
            }
            seen.add(key);
            return true;
        });
    }
}

module.exports = new IPFSController();
