// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract CredentialRegistry {
    struct Credential {
        bytes32 credentialHash;
        string ipfsHash;
        address issuer;
        string holderDID;
        string schemaId;
        uint256 issuedAt;
        uint256 expiresAt;
        bool exists;
    }
    
    mapping(bytes32 => Credential) public credentials;
    mapping(address => bytes32[]) public issuerCredentials;
    mapping(string => bytes32[]) public holderCredentials;
    
    event CredentialIssued(
        bytes32 indexed credentialHash,
        address indexed issuer,
        string indexed holderDID,
        string schemaId,
        uint256 timestamp
    );
    
    modifier onlyIssuer(bytes32 credentialHash) {
        require(credentials[credentialHash].issuer == msg.sender, "Not credential issuer");
        _;
    }
    
    function issueCredential(
        bytes32 credentialHash,
        string memory ipfsHash,
        string memory holderDID,
        string memory schemaId,
        uint256 expiresAt
    ) public {
        require(!credentials[credentialHash].exists, "Credential already exists");
        require(bytes(ipfsHash).length > 0, "IPFS hash cannot be empty");
        require(bytes(holderDID).length > 0, "Holder DID cannot be empty");
        require(bytes(schemaId).length > 0, "Schema ID cannot be empty");
        require(expiresAt > block.timestamp, "Expiry must be in future");
        
        credentials[credentialHash] = Credential({
            credentialHash: credentialHash,
            ipfsHash: ipfsHash,
            issuer: msg.sender,
            holderDID: holderDID,
            schemaId: schemaId,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            exists: true
        });
        
        issuerCredentials[msg.sender].push(credentialHash);
        holderCredentials[holderDID].push(credentialHash);
        
        emit CredentialIssued(credentialHash, msg.sender, holderDID, schemaId, block.timestamp);
    }
    
    function getCredential(bytes32 credentialHash) 
        public 
        view 
        returns (
            string memory ipfsHash,
            address issuer,
            string memory holderDID,
            string memory schemaId,
            uint256 issuedAt,
            uint256 expiresAt
        ) 
    {
        require(credentials[credentialHash].exists, "Credential does not exist");
        Credential memory cred = credentials[credentialHash];
        return (cred.ipfsHash, cred.issuer, cred.holderDID, cred.schemaId, cred.issuedAt, cred.expiresAt);
    }
    
    function verifyCredential(bytes32 credentialHash) public view returns (bool valid, string memory reason) {
        if (!credentials[credentialHash].exists) {
            return (false, "Credential does not exist");
        }
        
        Credential memory cred = credentials[credentialHash];
        
        if (block.timestamp > cred.expiresAt) {
            return (false, "Credential expired");
        }
        
        return (true, "Valid credential");
    }
    
    function getIssuerCredentials(address issuer) public view returns (bytes32[] memory) {
        return issuerCredentials[issuer];
    }
    
    function getHolderCredentials(string memory holderDID) public view returns (bytes32[] memory) {
        return holderCredentials[holderDID];
    }
}
