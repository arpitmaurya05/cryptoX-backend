require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

mongoose.connect(process.env.MONGO_URI).then(async () => {
  const users = await User.find({}, 'email walletAddress encryptedKey');
  users.forEach(u => {
    console.log('Email:', u.email);
    console.log('Wallet:', u.walletAddress);
    console.log('Has Key:', !!u.encryptedKey);
    console.log('---');
  });
  mongoose.disconnect();
});
