const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema(
  {
    firstName:     { type: String, trim: true },
    lastName:      { type: String, trim: true },
    email:         { type: String, unique: true, sparse: true, lowercase: true },
    password:      { type: String, minlength: 6 },
    authType:      { type: String, enum: ["email", "metamask"], default: "email" },

    // ── Built-in wallet ──
    walletAddress: { type: String, unique: true, sparse: true, lowercase: true },
    encryptedKey:  { type: String },
    walletMnemonic:{ type: String },

    // ── Profile fields ──
    phone:         { type: String, default: "", trim: true },
    country:       { type: String, default: "", trim: true },
    bio:           { type: String, default: "", trim: true },
    username:      { type: String, default: "", trim: true },

    // ── MetaMask ──
    nonce:         { type: String },
  },
  { timestamps: true }
);

// ── Hash password on save (only if modified) ──
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password") || !this.password) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// ── Helper method to compare passwords ──
UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// ── Warn if user saved without wallet ──
UserSchema.post("save", function (doc) {
  if (!doc.walletAddress && doc.email) {
    console.warn("⚠️ WARNING: User saved without wallet:", doc.email);
  }
});

module.exports = mongoose.model("User", UserSchema);