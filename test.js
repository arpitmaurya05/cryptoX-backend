require("dotenv").config();
const { ethers } = require("ethers");

async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
  
  // Paste your wallet address here
  const address = "0xb0e790af04182da2915b01627c4f7a0897668456";
  
  const balance = await provider.getBalance(address);
  console.log("Raw balance (wei):", balance.toString());
  console.log("Balance (ETH):", ethers.formatEther(balance));
}

main().catch(console.error);