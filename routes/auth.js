const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const { ethers } = require("ethers");
const crypto = require("crypto");
const User = require("../models/User");

// ── Helper: Generate JWT ──
const generateToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "7d" });

// ── Helper: Generate random nonce ──
const generateNonce = () => crypto.randomBytes(16).toString("hex");


// ════════════════════════════════
//  EMAIL AUTH
// ════════════════════════════════

// POST /api/auth/signup
router.post("/signup", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    if (!firstName || !lastName || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "Email already registered" });

    const user = await User.create({
      firstName, lastName, email, password, authType: "email",
    });

    res.status(201).json({
      message: "Account created successfully",
      token: generateToken(user._id),
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("SIGNUP ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

// POST /api/auth/login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required" });

    const user = await User.findOne({ email });

    if (!user)
      return res.status(401).json({ message: "Invalid email or password" });

    const isMatch = await user.matchPassword(password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    res.json({
      message: "Login successful",
      token: generateToken(user._id),
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});


// ════════════════════════════════
//  METAMASK AUTH
// ════════════════════════════════

// GET /api/auth/metamask/nonce/:address
router.get("/metamask/nonce/:address", async (req, res) => {
  const address = req.params.address.toLowerCase();

  try {
    let user = await User.findOne({ walletAddress: address });

    if (!user) {
      user = await User.create({
        walletAddress: address,
        nonce: generateNonce(),
        authType: "metamask",
      });
    } else {
      user.nonce = generateNonce();
      await user.save();
    }

    res.json({
      nonce: user.nonce,
      message: `Sign this message to login to Cryptico: ${user.nonce}`,
    });
  } catch (err) {
    console.error("NONCE ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

// POST /api/auth/metamask/verify
router.post("/metamask/verify", async (req, res) => {
  const { address, signature } = req.body;

  try {
    if (!address || !signature)
      return res.status(400).json({ message: "Address and signature required" });

    const user = await User.findOne({ walletAddress: address.toLowerCase() });
    if (!user)
      return res.status(404).json({ message: "Wallet not found. Please try again." });

    const message = `Sign this message to login to Cryptico: ${user.nonce}`;
    const recoveredAddress = ethers.verifyMessage(message, signature);

    if (recoveredAddress.toLowerCase() !== address.toLowerCase())
      return res.status(401).json({ message: "Signature verification failed" });

    user.nonce = generateNonce();
    await user.save();

    res.json({
      message: "MetaMask login successful",
      token: generateToken(user._id),
      user: {
        id: user._id,
        walletAddress: user.walletAddress,
        authType: "metamask",
      },
    });
  } catch (err) {
    console.error("VERIFY ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});


// ════════════════════════════════
//  WALLET MANAGEMENT
// ════════════════════════════════

// POST /api/auth/save-wallet
router.post("/save-wallet", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { walletAddress } = req.body;

    const user = await User.findByIdAndUpdate(
      decoded.id,
      { walletAddress: walletAddress ? walletAddress.toLowerCase() : null },
      { new: true }
    ).select("-password -nonce");

    res.json({ message: "Wallet saved", user });
  } catch (err) {
    console.error("SAVE WALLET ERROR:", err.message);
    res.status(401).json({ message: "Invalid token" });
  }
});

// GET /api/auth/get-wallet
router.get("/get-wallet", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("walletAddress");
    res.json({ walletAddress: user.walletAddress || null });
  } catch (err) {
    console.error("GET WALLET ERROR:", err.message);
    res.status(401).json({ message: "Invalid token" });
  }
});


// ════════════════════════════════
//  PROTECTED ROUTE
// ════════════════════════════════

// GET /api/auth/me
router.get("/me", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password -nonce");
    res.json(user);
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

module.exports = router;