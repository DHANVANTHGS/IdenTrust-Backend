const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  gmail: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true, // hashed password
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  number: {
    type: String,
    required: true,
    unique: true,
  },
  did: {
    type: String,
    required: true,
    unique: true, // Decentralized Identifier string
  },
  publicKey: {
    type: String,
    required: true,
  },
  roles: {
    type: [String], // e.g., ['user', 'admin']
    default: ['user'],
  },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  }
});

// Pre-save middleware to update updatedAt timestamp
userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('User', userSchema);
