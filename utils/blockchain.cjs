// utils/blockchain.js
const { ethers } = require('ethers');
const contractAddresses = require('../contract-addresses.json');

// Contract ABIs (you need to add your actual ABIs here)
const CREDENTIAL_REGISTRY_ABI = [
    "function issueCredential(bytes32 credentialHash, string memory ipfsHash, string memory holderDID, string memory schemaId, uint256 expiresAt) public",
    "function getCredential(bytes32 credentialHash) public view returns (string memory ipfsHash, address issuer, string memory holderDID, string memory schemaId, uint256 issuedAt, uint256 expiresAt)",
    "function verifyCredential(bytes32 credentialHash) public view returns (bool valid, string memory reason)",
    "function getIssuerCredentials(address issuer) public view returns (bytes32[] memory)",
    "function getHolderCredentials(string memory holderDID) public view returns (bytes32[] memory)"
];

const DID_REGISTRY_ABI = [
    "function createDID(string memory did, string memory document) public",
    "function updateDID(string memory did, string memory newDocument) public",
    "function getDIDDocument(string memory did) public view returns (string memory document, address owner, uint256 created, uint256 updated)",
    "function getOwnerDIDs(address owner) public view returns (string[] memory)"
];

const REVOCATION_REGISTRY_ABI = [
    "function revokeCredential(bytes32 credentialHash, string memory reason) public",
    "function isRevoked(bytes32 credentialHash) public view returns (bool)",
    "function getRevocationInfo(bytes32 credentialHash) public view returns (bool revoked, uint256 revokedAt, string memory reason)"
];

const SCHEMA_REGISTRY_ABI = [
    "function createSchema(string memory schemaId, string memory name, string memory description, string memory schemaJSON, uint256 version) public",
    "function getSchema(string memory schemaId) public view returns (string memory name, string memory description, string memory schemaJSON, address creator, uint256 version, uint256 created)"
];

// Initialize provider and contracts
const provider = new ethers.providers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
const wallet = new ethers.Wallet(process.env.SEPOLIA_PRIVATE_KEY, provider);

// Initialize contracts
const credentialRegistry = new ethers.Contract(contractAddresses.credentialRegistry, CREDENTIAL_REGISTRY_ABI, wallet);
const didRegistry = new ethers.Contract(contractAddresses.didRegistry, DID_REGISTRY_ABI, wallet);
const revocationRegistry = new ethers.Contract(contractAddresses.revocationRegistry, REVOCATION_REGISTRY_ABI, wallet);
const schemaRegistry = new ethers.Contract(contractAddresses.schemaRegistry, SCHEMA_REGISTRY_ABI, wallet);

module.exports = {
    provider,
    wallet,
    credentialRegistry,
    didRegistry,
    revocationRegistry,
    schemaRegistry,
    ethers
};
