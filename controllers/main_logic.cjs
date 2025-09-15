const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const fs = require('fs').promises;
const path = require('path');
const { validationResult } = require('express-validator');
const mongoose = require('mongoose');
require('dotenv').config();

const User = require('../models/User'); // Adjust import path to your User mongoose model

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_change_this';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your_encryption_key_32_chars_long';

// Firebase Admin initialization
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    }),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  });
}

const bucket = admin.storage().bucket();

class MainController {
  // Signup function - store only non-sensitive user data in MongoDB
  async signup(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array(),
        });
      }

      const { gmail, password, name, number } = req.body;

      // Check if user already exists in MongoDB
      const existingUser = await User.findOne({
        $or: [{ gmail }, { number }],
      });
      if (existingUser) {
        return res.status(409).json({
          error: 'Account with this email or phone number already exists',
        });
      }

      // Hash password securely
      const hashedPassword = await bcrypt.hash(password, 12);

      // Generate public/private key pair for DID - private key NOT stored in DB
      const { publicKey, privateKey } = this.generateKeyPair();
      const did = this.generateDID(publicKey);

      // Generate session private key for encryption/storage (not stored in DB)
      const sessionPrivateKey = crypto.randomBytes(32).toString('hex');

      // Save private keys securely locally and to Firebase Storage (encrypted)
      try {
        await this.savePrivateKeyLocally(gmail, sessionPrivateKey);
        await this.uploadPrivateKeyToFirebase(gmail, sessionPrivateKey);
      } catch (storageError) {
        return res.status(500).json({
          error: 'Failed to secure private key storage',
          details: storageError.message,
        });
      }

      // Save user to MongoDB WITHOUT any private or sensitive keys
      const user = new User({
        gmail,
        password: hashedPassword,
        name,
        number,
        did,
        publicKey,
      });

      await user.save();

      // Generate JWT token
      const token = jwt.sign({ gmail, did, name }, JWT_SECRET, {
        expiresIn: '24h',
      });

      res.status(201).json({
        message: 'Account created successfully',
        token,
        user: {
          gmail: user.gmail,
          name: user.name,
          did: user.did,
          publicKey: user.publicKey,
        },
      });
    } catch (error) {
      console.error('Signup error:', error);
      res.status(500).json({
        error: 'Internal server error during signup',
        details: error.message,
      });
    }
  }

  // Login function - authenticate using MongoDB stored data
  async login(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array(),
        });
      }

      const { gmail, password } = req.body;

      // Find user from MongoDB
      const user = await User.findOne({ gmail });
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Compare hashed password
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate JWT token
      const token = jwt.sign(
        { gmail: user.gmail, did: user.did, name: user.name },
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
          publicKey: user.publicKey,
        },
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: 'Internal server error during login',
        details: error.message,
      });
    }
  }

  // Fetch user profile from MongoDB (exclude password)
  async getProfile(req, res) {
    try {
      const user = await User.findOne({ gmail: req.user.gmail }).select(
        '-password'
      );
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({
        gmail: user.gmail,
        name: user.name,
        number: user.number,
        did: user.did,
        publicKey: user.publicKey,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      });
    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({ error: 'Failed to get profile', details: error.message });
    }
  }

  // Retrieve private key from secure local or Firebase storage with fallback
  async recoverKey(req, res) {
    try {
      const gmail = req.user.gmail;
      const privateKey = await this.getPrivateKeyWithFallback(gmail);

      res.json({
        message: 'Private key recovered successfully',
        privateKey,
        source: 'recovered',
      });
    } catch (error) {
      console.error('Key recovery error:', error);
      res.status(500).json({
        error: 'Failed to recover private key',
        details: error.message,
      });
    }
  }

  // Check private key availability locally and on Firebase Storage
  async checkKeyAvailability(req, res) {
    try {
      const gmail = req.user.gmail;

      let localExists = false;
      try {
        const dir = path.join(__dirname, '../user_keys');
        const keyPath = path.join(dir, `${gmail}_private.key`);
        await fs.access(keyPath);
        localExists = true;
      } catch {
        localExists = false;
      }

      const firebaseExists = await this.checkPrivateKeyExistsInFirebase(gmail);

      res.json({
        gmail,
        keyAvailability: {
          local: localExists,
          firebase: firebaseExists,
        },
        recommendation:
          localExists && firebaseExists
            ? 'Keys available in both locations. Fully backed up.'
            : localExists && !firebaseExists
            ? 'Local key found but not in Firebase. Consider backup.'
            : !localExists && firebaseExists
            ? 'Firebase backup found but not local. Consider sync.'
            : 'No keys found. This is a serious issue.',
      });
    } catch (error) {
      console.error('Check availability error:', error);
      res.status(500).json({
        error: 'Failed to check key availability',
        details: error.message,
      });
    }
  }

  // Delete private keys from local and/or Firebase locations per user request
  async deleteKeys(req, res) {
    try {
      const gmail = req.user.gmail;
      const { location } = req.body; // 'local', 'firebase', or 'both'

      const result = { gmail, location };

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
          await this.deletePrivateKeyFromFirebase(gmail);
          result.firebaseDeleted = true;
        } catch (error) {
          result.firebaseError = error.message;
        }
      }

      res.json({
        message: 'Key deletion completed',
        result,
      });
    } catch (error) {
      console.error('Delete keys error:', error);
      res.status(500).json({
        error: 'Failed to delete keys',
        details: error.message,
      });
    }
  }

  /*
   * Helper Methods Below: Encryption, Firebase Storage wrappers, Private key local file methods,
   * Private key retrieval fallback, and Key pair generation, DID generation.
   */

  encryptPrivateKey(privateKey, encryptionKey) {
    const cipher = crypto.createCipher('aes-256-cbc', encryptionKey);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  decryptPrivateKey(encryptedKey, encryptionKey) {
    const decipher = crypto.createDecipher('aes-256-cbc', encryptionKey);
    let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  async savePrivateKeyLocally(gmail, privateKey) {
    try {
      const dir = path.join(__dirname, '../user_keys');
      try {
        await fs.access(dir);
      } catch {
        await fs.mkdir(dir, { recursive: true });
      }
      const encryptedKey = this.encryptPrivateKey(privateKey, ENCRYPTION_KEY);
      await fs.writeFile(path.join(dir, `${gmail}_private.key`), encryptedKey, 'utf8');
      console.log(`Private key saved locally for ${gmail}`);
    } catch (error) {
      console.error('Error saving private key locally:', error);
      throw error;
    }
  }

  async uploadPrivateKeyToFirebase(gmail, privateKey) {
    try {
      const encryptedKey = this.encryptPrivateKey(privateKey, ENCRYPTION_KEY);
      const fileName = `private_keys/${gmail}_private.key`;
      const file = bucket.file(fileName);
      await file.save(encryptedKey, {
        metadata: {
          contentType: 'text/plain',
          metadata: {
            encrypted: 'true',
            user: gmail,
            uploadTime: new Date().toISOString(),
          },
        },
      });
      console.log(`Private key uploaded to Firebase Storage for ${gmail}`);
    } catch (error) {
      console.error('Error uploading to Firebase Storage:', error);
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
      const privateKey = this.decryptPrivateKey(encryptedKey, ENCRYPTION_KEY);
      return privateKey;
    } catch (error) {
      console.error('Error retrieving from Firebase Storage:', error);
      throw error;
    }
  }

  async deletePrivateKeyFromFirebase(gmail) {
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

  async getPrivateKeyWithFallback(gmail) {
    try {
      const dir = path.join(__dirname, '../user_keys');
      const keyPath = path.join(dir, `${gmail}_private.key`);
      const encryptedKey = await fs.readFile(keyPath, 'utf8');
      return this.decryptPrivateKey(encryptedKey, ENCRYPTION_KEY);
    } catch (localError) {
      console.log(`Local key not found for ${gmail}, trying Firebase...`);
      try {
        const privateKey = await this.getPrivateKeyFromFirebase(gmail);
        try {
          await this.savePrivateKeyLocally(gmail, privateKey);
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

  generateDID(publicKey) {
    return `did:key:${publicKey.substring(0, 44)}`;
  }

  generateKeyPair() {
    const keyPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };
  }
}

module.exports = new MainController();
