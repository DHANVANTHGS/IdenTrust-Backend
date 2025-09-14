// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./DIDRegistry.sol";
import "./CredentialRegistry.sol";
import "./RevocationRegistry.sol";
import "./SchemaRegistry.sol";

contract SSIManager {
    DIDRegistry public didRegistry;
    CredentialRegistry public credentialRegistry;
    RevocationRegistry public revocationRegistry;
    SchemaRegistry public schemaRegistry;
    
    event SSIEcosystemInitialized(address indexed initializer, uint256 timestamp);
    
    constructor() {
        didRegistry = new DIDRegistry();
        schemaRegistry = new SchemaRegistry();
        credentialRegistry = new CredentialRegistry();
        revocationRegistry = new RevocationRegistry(address(credentialRegistry));
        
        emit SSIEcosystemInitialized(msg.sender, block.timestamp);
    }
    
    function getContractAddresses() 
        public 
        view 
        returns (
            address did,
            address credential,
            address revocation,
            address schema
        ) 
    {
        return (
            address(didRegistry),
            address(credentialRegistry),
            address(revocationRegistry),
            address(schemaRegistry)
        );
    }
    
    // Comprehensive verification function
    function verifyCredentialCompletely(bytes32 credentialHash) 
        public 
        view 
        returns (
            bool valid,
            string memory status,
            address issuer,
            string memory holderDID
        ) 
    {
        // Check if credential exists
        try credentialRegistry.getCredential(credentialHash) returns (
            string memory,
            address _issuer,
            string memory _holderDID,
            string memory,
            uint256,
            uint256
        ) {
            issuer = _issuer;
            holderDID = _holderDID;
            
            // Check revocation status
            (bool statusValid, string memory statusMsg) = revocationRegistry.verifyCredentialStatus(credentialHash);
            
            return (statusValid, statusMsg, issuer, holderDID);
        } catch {
            return (false, "Credential not found", address(0), "");
        }
    }
}
