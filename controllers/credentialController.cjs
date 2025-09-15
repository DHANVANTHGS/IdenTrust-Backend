// controllers/credentialController.js
const { validationResult } = require('express-validator');
const { credentialRegistry, ethers, revocationRegistry } = require('../utils/blockchain');

class CredentialController {
    async issueCredential(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { ipfsHash, holderDID, schemaId, expiresAt } = req.body;

            // Generate a unique credential hash for this issuance
            const credentialHash = ethers.utils.keccak256(
                ethers.utils.toUtf8Bytes(`${ipfsHash}_${holderDID}_${Date.now()}`)
            );

            const tx = await credentialRegistry.issueCredential(
                credentialHash,
                ipfsHash,
                holderDID,
                schemaId,
                expiresAt
            );
            await tx.wait();

            res.json({
                message: 'Credential issued successfully',
                credentialHash,
                transactionHash: tx.hash,
                issuer: tx.from
            });
        } catch (error) {
            console.error('Credential issuance error:', error);
            res.status(500).json({ error: 'Failed to issue credential', details: error.message });
        }
    }

    async getCredential(req, res) {
        try {
            const { hash } = req.params;

            const [ipfsHash, issuer, holderDID, schemaId, issuedAt, expiresAt] =
                await credentialRegistry.getCredential(hash);

            // Check if credential is revoked
            const isRevoked = await revocationRegistry.isRevoked(hash);

            res.json({
                credentialHash: hash,
                ipfsHash,
                issuer,
                holderDID,
                schemaId,
                issuedAt: issuedAt.toString(),
                expiresAt: expiresAt.toString(),
                isRevoked,
                status: isRevoked ? 'revoked' : 'active'
            });
        } catch (error) {
            console.error('Get credential error:', error);
            res.status(404).json({ error: 'Credential not found', details: error.message });
        }
    }

    async verifyCredential(req, res) {
        try {
            const { hash } = req.params;

            // Verify credential validity
            const [valid, reason] = await credentialRegistry.verifyCredential(hash);
            
            // Check revocation status
            const isRevoked = await revocationRegistry.isRevoked(hash);

            // Get credential details for additional verification
            let credentialDetails = null;
            try {
                const [ipfsHash, issuer, holderDID, schemaId, issuedAt, expiresAt] =
                    await credentialRegistry.getCredential(hash);
                
                credentialDetails = {
                    ipfsHash,
                    issuer,
                    holderDID,
                    schemaId,
                    issuedAt: issuedAt.toString(),
                    expiresAt: expiresAt.toString(),
                    expired: Date.now() / 1000 > expiresAt.toNumber()
                };
            } catch (detailError) {
                console.warn('Could not fetch credential details:', detailError.message);
            }

            const overallValid = valid && !isRevoked && (credentialDetails ? !credentialDetails.expired : true);

            res.json({
                credentialHash: hash,
                valid: overallValid,
                reason: !overallValid ? (isRevoked ? 'Credential has been revoked' : (credentialDetails?.expired ? 'Credential has expired' : reason)) : 'Valid credential',
                details: {
                    blockchainValid: valid,
                    isRevoked,
                    ...credentialDetails
                }
            });
        } catch (error) {
            console.error('Credential verification error:', error);
            res.status(500).json({ error: 'Failed to verify credential', details: error.message });
        }
    }

    async getIssuerCredentials(req, res) {
        try {
            const { address } = req.params;

            const credentialHashes = await credentialRegistry.getIssuerCredentials(address);
            
            // Get details for each credential
            const credentials = await Promise.all(
                credentialHashes.map(async (hash) => {
                    try {
                        const [ipfsHash, issuer, holderDID, schemaId, issuedAt, expiresAt] =
                            await credentialRegistry.getCredential(hash);
                        
                        const isRevoked = await revocationRegistry.isRevoked(hash);
                        
                        return {
                            credentialHash: hash,
                            ipfsHash,
                            holderDID,
                            schemaId,
                            issuedAt: issuedAt.toString(),
                            expiresAt: expiresAt.toString(),
                            isRevoked,
                            status: isRevoked ? 'revoked' : 'active'
                        };
                    } catch (err) {
                        return {
                            credentialHash: hash,
                            error: err.message
                        };
                    }
                })
            );

            res.json({
                issuer: address,
                credentials,
                count: credentials.length
            });
        } catch (error) {
            console.error('Get issuer credentials error:', error);
            res.status(500).json({ error: 'Failed to get issuer credentials', details: error.message });
        }
    }

    async getHolderCredentials(req, res) {
        try {
            const { did } = req.params;

            const credentialHashes = await credentialRegistry.getHolderCredentials(did);
            
            // Get details for each credential
            const credentials = await Promise.all(
                credentialHashes.map(async (hash) => {
                    try {
                        const [ipfsHash, issuer, holderDID, schemaId, issuedAt, expiresAt] =
                            await credentialRegistry.getCredential(hash);
                        
                        const isRevoked = await revocationRegistry.isRevoked(hash);
                        
                        return {
                            credentialHash: hash,
                            ipfsHash,
                            issuer,
                            schemaId,
                            issuedAt: issuedAt.toString(),
                            expiresAt: expiresAt.toString(),
                            isRevoked,
                            status: isRevoked ? 'revoked' : 'active'
                        };
                    } catch (err) {
                        return {
                            credentialHash: hash,
                            error: err.message
                        };
                    }
                })
            );

            res.json({
                holder: did,
                credentials,
                count: credentials.length
            });
        } catch (error) {
            console.error('Get holder credentials error:', error);
            res.status(500).json({ error: 'Failed to get holder credentials', details: error.message });
        }
    }

    async batchVerifyCredentials(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { credentialHashes } = req.body;

            const results = await Promise.all(
                credentialHashes.map(async (hash) => {
                    try {
                        const [valid, reason] = await credentialRegistry.verifyCredential(hash);
                        const isRevoked = await revocationRegistry.isRevoked(hash);
                        
                        return {
                            credentialHash: hash,
                            valid: valid && !isRevoked,
                            reason: !valid ? reason : (isRevoked ? 'Revoked' : 'Valid'),
                            isRevoked
                        };
                    } catch (error) {
                        return {
                            credentialHash: hash,
                            valid: false,
                            reason: error.message,
                            error: true
                        };
                    }
                })
            );

            const summary = {
                total: results.length,
                valid: results.filter(r => r.valid).length,
                invalid: results.filter(r => !r.valid && !r.error).length,
                revoked: results.filter(r => r.isRevoked).length,
                errors: results.filter(r => r.error).length
            };

            res.json({
                message: 'Batch verification completed',
                summary,
                results
            });
        } catch (error) {
            console.error('Batch verify credentials error:', error);
            res.status(500).json({ error: 'Failed to batch verify credentials', details: error.message });
        }
    }
}

module.exports = new CredentialController();
