require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

mongoose.connect(process.env.MONGO_URI).then(async () => {
  const result = await User.deleteMany({ email: { $exists: false } });
  console.log('✅ Deleted junk users:', result.deletedCount);
  mongoose.disconnect();
});
