// scripts/deploy.js
async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying contracts with account:", deployer.address);

    // Deploy main SSI Manager (deploys all other contracts)
    const SSIManager = await ethers.getContractFactory("SSIManager");
    const ssiManager = await SSIManager.deploy();
    await ssiManager.deployed();

    console.log("SSI Manager deployed to:", ssiManager.address);

    // Get individual contract addresses
    const addresses = await ssiManager.getContractAddresses();
    console.log("DID Registry:", addresses.did);
    console.log("Credential Registry:", addresses.credential);
    console.log("Revocation Registry:", addresses.revocation);
    console.log("Schema Registry:", addresses.schema);

    // Save addresses to file for frontend
    const fs = require('fs');
    const contractAddresses = {
        ssiManager: ssiManager.address,
        didRegistry: addresses.did,
        credentialRegistry: addresses.credential,
        revocationRegistry: addresses.revocation,
        schemaRegistry: addresses.schema,
        network: network.name,
        deployer: deployer.address
    };

    fs.writeFileSync(
        'contract-addresses.json', 
        JSON.stringify(contractAddresses, null, 2)
    );

    console.log("Contract addresses saved to contract-addresses.json");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
