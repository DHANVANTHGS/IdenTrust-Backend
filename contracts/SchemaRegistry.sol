// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract SchemaRegistry {
    struct Schema {
        string schemaId;
        string name;
        string description;
        string schemaJSON;
        address creator;
        uint256 version;
        uint256 created;
        bool exists;
    }
    
    mapping(string => Schema) public schemas;
    mapping(address => string[]) public creatorSchemas;
    string[] public allSchemas;
    
    event SchemaCreated(
        string indexed schemaId,
        address indexed creator,
        string name,
        uint256 version,
        uint256 timestamp
    );
    
    modifier onlySchemaCreator(string memory schemaId) {
        require(schemas[schemaId].creator == msg.sender, "Not schema creator");
        _;
    }
    
    function createSchema(
        string memory schemaId,
        string memory name,
        string memory description,
        string memory schemaJSON,
        uint256 version
    ) public {
        require(!schemas[schemaId].exists, "Schema already exists");
        require(bytes(schemaId).length > 0, "Schema ID cannot be empty");
        require(bytes(name).length > 0, "Name cannot be empty");
        require(bytes(schemaJSON).length > 0, "Schema JSON cannot be empty");
        require(version > 0, "Version must be greater than 0");
        
        schemas[schemaId] = Schema({
            schemaId: schemaId,
            name: name,
            description: description,
            schemaJSON: schemaJSON,
            creator: msg.sender,
            version: version,
            created: block.timestamp,
            exists: true
        });
        
        creatorSchemas[msg.sender].push(schemaId);
        allSchemas.push(schemaId);
        
        emit SchemaCreated(schemaId, msg.sender, name, version, block.timestamp);
    }
    
    function getSchema(string memory schemaId) 
        public 
        view 
        returns (
            string memory name,
            string memory description,
            string memory schemaJSON,
            address creator,
            uint256 version,
            uint256 created
        ) 
    {
        require(schemas[schemaId].exists, "Schema does not exist");
        Schema memory schema = schemas[schemaId];
        return (schema.name, schema.description, schema.schemaJSON, schema.creator, schema.version, schema.created);
    }
    
    function getCreatorSchemas(address creator) public view returns (string[] memory) {
        return creatorSchemas[creator];
    }
    
    function getAllSchemas() public view returns (string[] memory) {
        return allSchemas;
    }
    
    function schemaExists(string memory schemaId) public view returns (bool) {
        return schemas[schemaId].exists;
    }
}
