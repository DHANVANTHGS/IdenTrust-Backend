// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// Use relative import
import  "./CredentialRegistry.sol";

contract RevocationRegistry {
    CredentialRegistry public credentialRegistry;
    
    mapping(bytes32 => bool) public revokedCredentials;
    mapping(bytes32 => uint256) public revocationTime;
    mapping(bytes32 => string) public revocationReason;
    
    event CredentialRevoked(
        bytes32 indexed credentialHash,
        address indexed revoker,
        string reason,
        uint256 timestamp
    );
    
    constructor(address _credentialRegistry) {
        credentialRegistry = CredentialRegistry(_credentialRegistry);
    }
    
    modifier onlyIssuer(bytes32 credentialHash) {
        (, address issuer, , , ,) = credentialRegistry.getCredential(credentialHash);
        require(issuer == msg.sender, "Only issuer can revoke");
        _;
    }
    
    function revokeCredential(bytes32 credentialHash, string memory reason) 
        public 
        onlyIssuer(credentialHash) 
    {
        require(!revokedCredentials[credentialHash], "Credential already revoked");
        require(bytes(reason).length > 0, "Revocation reason required");
        
        revokedCredentials[credentialHash] = true;
        revocationTime[credentialHash] = block.timestamp;
        revocationReason[credentialHash] = reason;
        
        emit CredentialRevoked(credentialHash, msg.sender, reason, block.timestamp);
    }
    
    function isRevoked(bytes32 credentialHash) public view returns (bool) {
        return revokedCredentials[credentialHash];
    }
    
    function getRevocationInfo(bytes32 credentialHash) 
        public 
        view 
        returns (bool revoked, uint256 revokedAt, string memory reason) 
    {
        return (
            revokedCredentials[credentialHash],
            revocationTime[credentialHash],
            revocationReason[credentialHash]
        );
    }
    
    function verifyCredentialStatus(bytes32 credentialHash) 
        public 
        view 
        returns (bool valid, string memory status) 
    {
        if (revokedCredentials[credentialHash]) {
            return (false, "Credential revoked");
        }
        
        (bool credValid, string memory credReason) = credentialRegistry.verifyCredential(credentialHash);
        return (credValid, credReason);
    }
}
