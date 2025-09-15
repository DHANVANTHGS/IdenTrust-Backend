const { validationResult } = require('express-validator');
const { revocationRegistry } = require('../utils/blockchain');

class RevocationController {
  async revokeCredential(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Validation failed', details: errors.array() });
      }

      const { credentialHash, reason } = req.body;

      const tx = await revocationRegistry.revokeCredential(credentialHash, reason);
      await tx.wait();

      res.json({
        message: 'Credential revoked successfully',
        credentialHash,
        reason,
        transactionHash: tx.hash
      });
    } catch (error) {
      console.error('Credential revocation error:', error);
      res.status(500).json({ error: 'Failed to revoke credential', details: error.message });
    }
  }

  async getRevocationStatus(req, res) {
    try {
      const { hash } = req.params;

      if (!hash) {
        return res.status(400).json({ error: 'Credential hash parameter is required' });
      }

      const isRevoked = await revocationRegistry.isRevoked(hash);

      res.json({
        credentialHash: hash,
        revoked: isRevoked
      });
    } catch (error) {
      console.error('Revocation status check error:', error);
      res.status(500).json({ error: 'Failed to check revocation status', details: error.message });
    }
  }

  async getRevocationInfo(req, res) {
    try {
      const { hash } = req.params;

      if (!hash) {
        return res.status(400).json({ error: 'Credential hash parameter is required' });
      }

      const [revoked, revokedAt, reason] = await revocationRegistry.getRevocationInfo(hash);

      res.json({
        credentialHash: hash,
        revoked,
        revokedAt: revokedAt.toNumber ? revokedAt.toNumber() : revokedAt,
        reason
      });
    } catch (error) {
      console.error('Get revocation info error:', error);
      res.status(500).json({ error: 'Failed to get revocation info', details: error.message });
    }
  }
}

module.exports = new RevocationController();
