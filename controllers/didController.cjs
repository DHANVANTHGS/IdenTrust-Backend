// controllers/didController.js
const { validationResult } = require('express-validator');
const { didRegistry, ethers } = require('../utils/blockchain');
const crypto = require('crypto');

class DIDController {
    async createDID(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { did, document } = req.body;

            // Validate DID format
            if (!this.isValidDIDFormat(did)) {
                return res.status(400).json({ error: 'Invalid DID format' });
            }

            // Check if DID already exists
            try {
                await didRegistry.getDIDDocument(did);
                return res.status(409).json({ error: 'DID already exists' });
            } catch (error) {
                // DID doesn't exist, which is what we want
            }

            const tx = await didRegistry.createDID(did, document);
            await tx.wait();

            res.json({
                message: 'DID created successfully',
                did,
                transactionHash: tx.hash,
                blockNumber: tx.blockNumber,
                gasUsed: tx.gasUsed?.toString()
            });
        } catch (error) {
            console.error('DID creation error:', error);
            res.status(500).json({ error: 'Failed to create DID', details: error.message });
        }
    }

    async updateDID(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { did, document } = req.body;

            // Validate DID format
            if (!this.isValidDIDFormat(did)) {
                return res.status(400).json({ error: 'Invalid DID format' });
            }

            // Check if DID exists
            try {
                const [existingDoc, owner] = await didRegistry.getDIDDocument(did);
                
                // Verify ownership (in production, you'd verify signature)
                if (owner.toLowerCase() !== req.user.address?.toLowerCase()) {
                    return res.status(403).json({ error: 'Not authorized to update this DID' });
                }
            } catch (error) {
                return res.status(404).json({ error: 'DID not found' });
            }

            const tx = await didRegistry.updateDID(did, document);
            await tx.wait();

            res.json({
                message: 'DID updated successfully',
                did,
                transactionHash: tx.hash,
                blockNumber: tx.blockNumber,
                gasUsed: tx.gasUsed?.toString()
            });
        } catch (error) {
            console.error('DID update error:', error);
            res.status(500).json({ error: 'Failed to update DID', details: error.message });
        }
    }

    async transferDID(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { did, newOwner } = req.body;

            // Check if DID exists and get current owner
            try {
                const [document, currentOwner] = await didRegistry.getDIDDocument(did);
                
                // Verify current ownership
                if (currentOwner.toLowerCase() !== req.user.address?.toLowerCase()) {
                    return res.status(403).json({ error: 'Not authorized to transfer this DID' });
                }
            } catch (error) {
                return res.status(404).json({ error: 'DID not found' });
            }

            const tx = await didRegistry.transferOwnership(did, newOwner);
            await tx.wait();

            res.json({
                message: 'DID ownership transferred successfully',
                did,
                newOwner,
                transactionHash: tx.hash
            });
        } catch (error) {
            console.error('DID transfer error:', error);
            res.status(500).json({ error: 'Failed to transfer DID', details: error.message });
        }
    }

    async getDIDDocument(req, res) {
        try {
            const { did } = req.params;

            if (!this.isValidDIDFormat(did)) {
                return res.status(400).json({ error: 'Invalid DID format' });
            }

            const [document, owner, created, updated] = await didRegistry.getDIDDocument(did);

            res.json({
                did,
                document: JSON.parse(document),
                owner,
                metadata: {
                    created: created.toString(),
                    updated: updated.toString(),
                    createdDate: new Date(created.toNumber() * 1000).toISOString(),
                    updatedDate: new Date(updated.toNumber() * 1000).toISOString()
                }
            });
        } catch (error) {
            console.error('Get DID error:', error);
            res.status(404).json({ error: 'DID not found', details: error.message });
        }
    }

    async getOwnerDIDs(req, res) {
        try {
            const { address } = req.params;

            if (!ethers.utils.isAddress(address)) {
                return res.status(400).json({ error: 'Invalid Ethereum address' });
            }

            const dids = await didRegistry.getOwnerDIDs(address);
            
            // Get details for each DID
            const didDetails = await Promise.all(
                dids.map(async (did) => {
                    try {
                        const [document, owner, created, updated] = await didRegistry.getDIDDocument(did);
                        return {
                            did,
                            document: JSON.parse(document),
                            created: created.toString(),
                            updated: updated.toString()
                        };
                    } catch (err) {
                        return {
                            did,
                            error: err.message
                        };
                    }
                })
            );

            res.json({ 
                owner: address, 
                dids: didDetails,
                count: dids.length 
            });
        } catch (error) {
            console.error('Get owner DIDs error:', error);
            res.status(500).json({ error: 'Failed to get owner DIDs', details: error.message });
        }
    }

    async resolveDID(req, res) {
        try {
            const { did } = req.params;

            if (!this.isValidDIDFormat(did)) {
                return res.status(400).json({ error: 'Invalid DID format' });
            }

            const [document, owner, created, updated] = await didRegistry.getDIDDocument(did);
            const parsedDocument = JSON.parse(document);

            // Return W3C DID Document format
            const w3cDocument = {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "controller": owner,
                ...parsedDocument,
                "proof": {
                    "type": "EthereumBlockchain",
                    "created": new Date(created.toNumber() * 1000).toISOString(),
                    "updated": new Date(updated.toNumber() * 1000).toISOString(),
                    "blockchainAccountId": `eip155:11155111:${owner}` // Sepolia chain ID
                }
            };

            res.json(w3cDocument);
        } catch (error) {
            console.error('Resolve DID error:', error);
            res.status(404).json({ error: 'DID not found', details: error.message });
        }
    }

    async verifyDIDOwnership(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { did, signature, challenge } = req.body;

            // Get DID owner
            const [document, owner] = await didRegistry.getDIDDocument(did);

            // Verify signature (simplified - in production use proper signature verification)
            const recoveredAddress = ethers.utils.verifyMessage(challenge, signature);
            
            const isOwner = owner.toLowerCase() === recoveredAddress.toLowerCase();

            res.json({
                did,
                isOwner,
                owner,
                recoveredAddress,
                message: isOwner ? 'Ownership verified' : 'Ownership verification failed'
            });
        } catch (error) {
            console.error('Verify DID ownership error:', error);
            res.status(500).json({ error: 'Failed to verify DID ownership', details: error.message });
        }
    }

    async getDIDHistory(req, res) {
        try {
            const { did } = req.params;

            if (!this.isValidDIDFormat(did)) {
                return res.status(400).json({ error: 'Invalid DID format' });
            }

            // Get current DID info
            const [document, owner, created, updated] = await didRegistry.getDIDDocument(did);

            // In a real implementation, you'd query blockchain events for history
            const history = [
                {
                    action: 'created',
                    timestamp: created.toString(),
                    date: new Date(created.toNumber() * 1000).toISOString(),
                    owner
                }
            ];

            if (updated.toNumber() > created.toNumber()) {
                history.push({
                    action: 'updated',
                    timestamp: updated.toString(),
                    date: new Date(updated.toNumber() * 1000).toISOString(),
                    owner
                });
            }

            res.json({
                did,
                history,
                currentOwner: owner,
                currentDocument: JSON.parse(document)
            });
        } catch (error) {
            console.error('Get DID history error:', error);
            res.status(404).json({ error: 'DID not found', details: error.message });
        }
    }

    async batchCreateDIDs(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { dids } = req.body;

            if (dids.length > 10) {
                return res.status(400).json({ error: 'Maximum 10 DIDs per batch' });
            }

            const results = [];

            for (const didData of dids) {
                try {
                    const { did, document } = didData;

                    if (!this.isValidDIDFormat(did)) {
                        results.push({
                            did,
                            success: false,
                            error: 'Invalid DID format'
                        });
                        continue;
                    }

                    const tx = await didRegistry.createDID(did, document);
                    await tx.wait();

                    results.push({
                        did,
                        success: true,
                        transactionHash: tx.hash
                    });
                } catch (error) {
                    results.push({
                        did: didData.did,
                        success: false,
                        error: error.message
                    });
                }
            }

            const summary = {
                total: results.length,
                successful: results.filter(r => r.success).length,
                failed: results.filter(r => !r.success).length
            };

            res.json({
                message: 'Batch DID creation completed',
                summary,
                results
            });
        } catch (error) {
            console.error('Batch create DIDs error:', error);
            res.status(500).json({ error: 'Failed to batch create DIDs', details: error.message });
        }
    }

    // Utility methods
    isValidDIDFormat(did) {
        // Basic DID format validation: did:method:specific-id
        const didRegex = /^did:[a-z0-9]+:[a-zA-Z0-9._%-]*[a-zA-Z0-9._%-]$/;
        return didRegex.test(did);
    }

    generateChallenge() {
        return crypto.randomBytes(32).toString('hex');
    }
}

module.exports = new DIDController();
