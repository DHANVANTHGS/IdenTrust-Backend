// scripts/deploy.js
const hre = require("hardhat");
const fs = require("fs");

async function main() {
    const [deployer] = await hre.ethers.getSigners();
    console.log("Deploying contracts with account:", deployer.address);

    // Deploy main SSI Manager (which deploys other contracts internally)
    const SSIManager = await hre.ethers.getContractFactory("SSIManager");
    const ssiManager = await SSIManager.deploy();
    await ssiManager.deployed();

    console.log("SSI Manager deployed to:", ssiManager.address);

    // Get individual contract addresses from SSI Manager
    const addresses = await ssiManager.getContractAddresses();

    console.log("DID Registry:", addresses.did);
    console.log("Credential Registry:", addresses.credential);
    console.log("Revocation Registry:", addresses.revocation);
    console.log("Schema Registry:", addresses.schema);

    // Save contract addresses and deployment info to JSON file for frontend use
    const contractAddresses = {
        ssiManager: ssiManager.address,
        didRegistry: addresses.did,
        credentialRegistry: addresses.credential,
        revocationRegistry: addresses.revocation,
        schemaRegistry: addresses.schema,
        network: hre.network.name,
        deployer: deployer.address
    };

    fs.writeFileSync(
        "contract-addresses.json",
        JSON.stringify(contractAddresses, null, 2)
    );

    console.log("Contract addresses saved to contract-addresses.json");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Deployment failed:", error);
        process.exit(1);
    });
