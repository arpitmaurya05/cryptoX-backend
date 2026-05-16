const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { generateWallet, encryptPrivateKey, decryptPrivateKey } = require("../utils/wallet");
 

// ── Helper: generate JWT ──
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "7d" });
};
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
router.post("/signup", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  try {
    if (!firstName || !lastName || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "Email already registered" });

    // Auto-generate wallet
    const wallet = generateWallet();
    const encryptedKey = encryptPrivateKey(wallet.privateKey, password);

    // ✅ Verify wallet was generated before saving
    if (!wallet.address || !encryptedKey) {
      return res.status(500).json({ message: "Wallet generation failed" });
    }

    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      walletAddress: wallet.address.toLowerCase(),
      encryptedKey,
    });

    // ✅ Verify wallet was saved
    if (!user.walletAddress) {
      return res.status(500).json({ message: "Wallet not saved properly" });
    }

    res.status(201).json({
      message: "Account created successfully",
      token: generateToken(user._id),
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phone: user.phone || "",
        country: user.country || "",
        bio: user.bio || "",
        username: user.username || "",
        walletAddress: user.walletAddress,
      },
    });
  } catch (err) {
    console.error("SIGNUP ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid credentials" });

    // ✅ Auto-fix missing wallet on login
    if (!user.walletAddress || !user.encryptedKey) {
      console.log("⚠️ Generating missing wallet for:", email);
      const wallet = generateWallet();
      const encryptedKey = encryptPrivateKey(wallet.privateKey, password);
      user.walletAddress = wallet.address.toLowerCase();
      user.encryptedKey = encryptedKey;
      await user.save();
      console.log("✅ Wallet generated:", wallet.address);
    }

    res.json({
      message: "Login successful",
      token: generateToken(user._id),
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phone: user.phone || "",
        country: user.country || "",
        bio: user.bio || "",
        username: user.username || "",
        walletAddress: user.walletAddress,
      },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err.message);
    res.status(500).json({ message: err.message });
  }
});

router.put("/update-profile", auth, async (req, res) => {
  try {
    const { firstName, lastName, phone, country, bio, username } = req.body;
    const user = await User.findByIdAndUpdate(
      req.userId,
      { firstName, lastName, phone, country, bio, username },
      { new: true }
    ).select("-password -encryptedKey");
    res.json({
      message: "Profile updated successfully",
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phone: user.phone,
        country: user.country,
        bio: user.bio,
        username: user.username,
        walletAddress: user.walletAddress,
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;