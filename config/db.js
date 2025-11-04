const mongoose = require('mongoose');

const connectDB = async (uri, opts = {}) => {
  const MONGO_URI = uri || process.env.MONGO_URI || 'mongodb://localhost:27017/dos';
  // useNewUrlParser and useUnifiedTopology are deprecated in Mongoose 6+
  const options = Object.assign({}, opts);

  let attempts = 0;
  const maxAttempts = 5;
  const retryDelay = 3000;

  while (attempts < maxAttempts) {
    try {
      await mongoose.connect(MONGO_URI, options);
      console.log('MongoDB connected');
      return mongoose.connection;
    } catch (err) {
      attempts += 1;
      console.error(`MongoDB connection attempt ${attempts} failed:`, err.message || err);
      if (attempts >= maxAttempts) throw err;
      await new Promise(r => setTimeout(r, retryDelay));
    }
  }
};

module.exports = connectDB;
