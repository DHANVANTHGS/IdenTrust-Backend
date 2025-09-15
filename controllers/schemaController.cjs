const { validationResult } = require('express-validator');
const { schemaRegistry } = require('../utils/blockchain.cjs');

class SchemaController {
    async createSchema(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ error: 'Validation failed', details: errors.array() });
            }

            const { schemaId, name, description, schemaJSON, version } = req.body;

            const tx = await schemaRegistry.createSchema(
                schemaId,
                name,
                description,
                JSON.stringify(schemaJSON),
                version
            );
            await tx.wait();

            res.json({
                message: 'Schema created successfully',
                schemaId,
                transactionHash: tx.hash
            });
        } catch (error) {
            console.error('Schema creation error:', error);
            res.status(500).json({ error: 'Failed to create schema', details: error.message });
        }
    }

    async getSchema(req, res) {
        try {
            const { schemaId } = req.params;

            const [name, description, schemaJSON, creator, version, created] =
                await schemaRegistry.getSchema(schemaId);

            res.json({
                schemaId,
                name,
                description,
                schemaJSON: JSON.parse(schemaJSON),
                creator,
                version: version.toString(),
                created: created.toString()
            });
        } catch (error) {
            console.error('Get schema error:', error);
            res.status(404).json({ error: 'Schema not found', details: error.message });
        }
    }

    async getAllSchemas(req, res) {
        try {
            const schemas = await schemaRegistry.getAllSchemas();

            res.json({
                schemas,
                count: schemas.length
            });
        } catch (error) {
            console.error('Get all schemas error:', error);
            res.status(500).json({ error: 'Failed to get schemas', details: error.message });
        }
    }

    async getCreatorSchemas(req, res) {
        try {
            const { address } = req.params;
            const schemas = await schemaRegistry.getCreatorSchemas(address);

            res.json({
                creator: address,
                schemas
            });
        } catch (error) {
            console.error('Get creator schemas error:', error);
            res.status(500).json({ error: 'Failed to get creator schemas', details: error.message });
        }
    }
}

module.exports = new SchemaController();
