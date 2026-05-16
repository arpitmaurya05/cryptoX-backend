const { ethers } = require("ethers");
const CryptoJS = require("crypto-js");

const ENCRYPTION_SECRET = process.env.WALLET_SECRET || "cryptox_wallet_secret_2026";

// Generate a new wallet
const generateWallet = () => {
  const wallet = ethers.Wallet.createRandom();
  return {
    address: wallet.address,
    privateKey: wallet.privateKey,
    mnemonic: wallet.mnemonic?.phrase || "",
  };
};

// Encrypt private key with user's password
const encryptPrivateKey = (privateKey, password) => {
  const secret = `${ENCRYPTION_SECRET}_${password}`;
  return CryptoJS.AES.encrypt(privateKey, secret).toString();
};

// Decrypt private key
const decryptPrivateKey = (encryptedKey, password) => {
  const secret = `${ENCRYPTION_SECRET}_${password}`;
  const bytes = CryptoJS.AES.decrypt(encryptedKey, secret);
  return bytes.toString(CryptoJS.enc.Utf8);
};

// Get wallet from private key
const getWallet = (privateKey) => {
  const provider = new ethers.JsonRpcProvider(
    process.env.RPC_URL || "https://rpc.sepolia.org"
  );
  return new ethers.Wallet(privateKey, provider);
};

// Get wallet balance
const getBalance = async (address) => {
  const provider = new ethers.JsonRpcProvider(
    process.env.RPC_URL || "https://rpc.sepolia.org"
  );
  const balance = await provider.getBalance(address);
  return ethers.formatEther(balance);
};

module.exports = {
  generateWallet,
  encryptPrivateKey,
  decryptPrivateKey,
  getWallet,
  getBalance,
};