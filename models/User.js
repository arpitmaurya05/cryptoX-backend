const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema(
  {
    firstName:     { type: String, trim: true },
    lastName:      { type: String, trim: true },
    email:         { type: String, unique: true, sparse: true, lowercase: true },
    password:      { type: String, minlength: 6 },
    walletAddress: { type: String, unique: true, sparse: true, lowercase: true },
    nonce:         { type: String },
    authType:      { type: String, enum: ["email", "metamask"], default: "email" },
  },
  { timestamps: true }
);

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password") || !this.password) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model("User", UserSchema);
