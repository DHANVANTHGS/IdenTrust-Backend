// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract DIDRegistry {
    struct DIDDocument {
        string document;
        address owner;
        uint256 created;
        uint256 updated;
        bool exists;
    }
    
    mapping(string => DIDDocument) public didDocuments;
    mapping(address => string[]) public ownerDIDs;
    
    event DIDCreated(string indexed did, address indexed owner, uint256 timestamp);
    event DIDUpdated(string indexed did, address indexed owner, uint256 timestamp);
    event OwnershipTransferred(string indexed did, address indexed oldOwner, address indexed newOwner);
    
    modifier onlyDIDOwner(string memory did) {
        require(didDocuments[did].owner == msg.sender, "Not DID owner");
        _;
    }
    
    modifier didExists(string memory did) {
        require(didDocuments[did].exists, "DID does not exist");
        _;
    }
    
    function createDID(string memory did, string memory document) public {
        require(!didDocuments[did].exists, "DID already exists");
        require(bytes(did).length > 0, "DID cannot be empty");
        require(bytes(document).length > 0, "Document cannot be empty");
        
        didDocuments[did] = DIDDocument({
            document: document,
            owner: msg.sender,
            created: block.timestamp,
            updated: block.timestamp,
            exists: true
        });
        
        ownerDIDs[msg.sender].push(did);
        
        emit DIDCreated(did, msg.sender, block.timestamp);
    }
    
    function updateDID(string memory did, string memory newDocument) 
        public 
        onlyDIDOwner(did) 
        didExists(did) 
    {
        require(bytes(newDocument).length > 0, "Document cannot be empty");
        
        didDocuments[did].document = newDocument;
        didDocuments[did].updated = block.timestamp;
        
        emit DIDUpdated(did, msg.sender, block.timestamp);
    }
    
    function transferOwnership(string memory did, address newOwner) 
        public 
        onlyDIDOwner(did) 
        didExists(did) 
    {
        require(newOwner != address(0), "Invalid new owner address");
        require(newOwner != msg.sender, "Cannot transfer to self");
        
        address oldOwner = didDocuments[did].owner;
        didDocuments[did].owner = newOwner;
        didDocuments[did].updated = block.timestamp;
        
        // Remove from old owner's list
        _removeDIDFromOwner(oldOwner, did);
        
        // Add to new owner's list
        ownerDIDs[newOwner].push(did);
        
        emit OwnershipTransferred(did, oldOwner, newOwner);
    }
    
    function getDIDDocument(string memory did) 
        public 
        view 
        returns (string memory document, address owner, uint256 created, uint256 updated) 
    {
        require(didDocuments[did].exists, "DID does not exist");
        DIDDocument memory didDoc = didDocuments[did];
        return (didDoc.document, didDoc.owner, didDoc.created, didDoc.updated);
    }
    
    function getOwnerDIDs(address owner) public view returns (string[] memory) {
        return ownerDIDs[owner];
    }
    
    function _removeDIDFromOwner(address owner, string memory did) private {
        string[] storage dids = ownerDIDs[owner];
        for (uint i = 0; i < dids.length; i++) {
            if (keccak256(bytes(dids[i])) == keccak256(bytes(did))) {
                dids[i] = dids[dids.length - 1];
                dids.pop();
                break;
            }
        }
    }
}
