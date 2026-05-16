const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const { ethers } = require("ethers");
const User = require("../models/User");
const {
  decryptPrivateKey,
  getWallet,
  getBalance,
} = require("../utils/wallet");

// ── Middleware: verify JWT ──
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

// ── GET /api/wallet/balance ──
router.get("/balance", auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user?.walletAddress)
      return res.status(404).json({ message: "No wallet found" });

    const balance = await getBalance(user.walletAddress);
    res.json({ address: user.walletAddress, balance });
  } catch (err) {
    console.error("BALANCE ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/wallet/send ──
router.post("/send", auth, async (req, res) => {
  const { to, amount, message, password } = req.body;

  try {
    if (!to || !amount || !password)
      return res.status(400).json({ message: "to, amount and password are required" });

    const user = await User.findById(req.userId);
    if (!user?.encryptedKey)
      return res.status(404).json({ message: "No wallet found" });

    // Decrypt private key using user's password
    const privateKey = decryptPrivateKey(user.encryptedKey, password);
    if (!privateKey)
      return res.status(401).json({ message: "Wrong password" });

    // Get wallet with provider
    const wallet = getWallet(privateKey);

    // Send ETH
    const tx = await wallet.sendTransaction({
      to,
      value: ethers.parseEther(amount.toString()),
    });

    await tx.wait();

    // Now call smart contract to record transaction
    try {
      const contractAddress = process.env.CONTRACT_ADDRESS;
      const contractABI = [
        "function sendEth(address payable _receiver, uint256 amount, string memory _message) public"
      ];

      const contract = new ethers.Contract(contractAddress, contractABI, wallet);
      const contractTx = await contract.sendEth(
        to,
        ethers.parseEther(amount.toString()),
        message || ""
      );
      await contractTx.wait();
    } catch (contractErr) {
      console.log("Contract recording failed (non-critical):", contractErr.message);
    }

    res.json({
      message: "Transaction sent successfully!",
      txHash: tx.hash,
      from: user.walletAddress,
      to,
      amount,
    });
  } catch (err) {
    console.error("SEND ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/wallet/info ──
router.get("/info", auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("walletAddress firstName lastName email");
    if (!user?.walletAddress)
      return res.status(404).json({ message: "No wallet found" });

    const balance = await getBalance(user.walletAddress);
    res.json({
      address: user.walletAddress,
      balance,
      name: `${user.firstName} ${user.lastName}`,
      email: user.email,
    });
  } catch (err) {
    console.error("INFO ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

router.get("/transactions", auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user?.walletAddress)
      return res.status(404).json({ message: "No wallet found" });

    const address = user.walletAddress;
    const baseURL = `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`;

    const [sentRes, receivedRes] = await Promise.all([
      fetch(baseURL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0", id: 1,
          method: "alchemy_getAssetTransfers",
          params: [{ fromBlock: "0x0", toBlock: "latest", fromAddress: address, category: ["external"], withMetadata: true, maxCount: "0x14" }]
        })
      }),
      fetch(baseURL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0", id: 2,
          method: "alchemy_getAssetTransfers",
          params: [{ fromBlock: "0x0", toBlock: "latest", toAddress: address, category: ["external"], withMetadata: true, maxCount: "0x14" }]
        })
      })
    ]);

    const sentData     = await sentRes.json();
    const receivedData = await receivedRes.json();
    const sent         = (sentData.result?.transfers || []).map(tx => ({ ...tx, type: "sent" }));
    const received     = (receivedData.result?.transfers || []).map(tx => ({ ...tx, type: "received" }));
    const all          = [...sent, ...received].sort((a, b) =>
      new Date(b.metadata?.blockTimestamp) - new Date(a.metadata?.blockTimestamp)
    );

    res.json({ transactions: all, address });
  } catch (err) {
    console.error("TRANSACTIONS ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});
module.exports = router;