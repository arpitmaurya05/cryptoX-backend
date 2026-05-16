require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');
const { generateWallet, encryptPrivateKey } = require('./utils/wallet');

mongoose.connect(process.env.MONGO_URI).then(async () => {
  // Get all users without a wallet
  const users = await User.find({ 
    $or: [
      { walletAddress: { $exists: false } },
      { walletAddress: null },
      { encryptedKey: { $exists: false } },
      { encryptedKey: null }
    ]
  });

  console.log(`Found ${users.length} users without wallets`);

  for (const user of users) {
    if (!user.email) {
      console.log('Skipping user with no email:', user._id);
      continue;
    }

    const wallet = generateWallet();
    // Use a default password since we can't recover original
    const encryptedKey = encryptPrivateKey(wallet.privateKey, '123456');

    await User.findByIdAndUpdate(user._id, {
      walletAddress: wallet.address.toLowerCase(),
      encryptedKey,
    });

    console.log('✅ Fixed:', user.email, '→', wallet.address);
  }

  console.log('Done!');
  mongoose.disconnect();
});
