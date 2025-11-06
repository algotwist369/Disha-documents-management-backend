const mongoose = require('mongoose');

const connectDB = async (uri, opts = {}) => {
  const MONGO_URI = uri || process.env.MONGO_URI || 'mongodb://localhost:27017/dos';
  
  // Performance-optimized connection options
  const defaultOptions = {
    maxPoolSize: 10, // Maximum number of connections in the pool
    minPoolSize: 2, // Minimum number of connections
    serverSelectionTimeoutMS: 5000, // How long to try selecting a server
    socketTimeoutMS: 45000, // How long to wait for a socket
    family: 4, // Use IPv4, skip trying IPv6
    // Connection pool settings
    maxIdleTimeMS: 30000, // Close connections after 30 seconds of inactivity
    // Write concern for better performance
    writeConcern: {
      w: 'majority',
      j: true,
      wtimeout: 5000
    }
  };
  
  const options = Object.assign({}, defaultOptions, opts);

  let attempts = 0;
  const maxAttempts = 5;
  const retryDelay = 3000;

  while (attempts < maxAttempts) {
    try {
      await mongoose.connect(MONGO_URI, options);
      console.log('MongoDB connected');
      console.log(`Connection pool: min=${options.minPoolSize}, max=${options.maxPoolSize}`);
      
      // Set mongoose options for better performance
      mongoose.set('strictQuery', false); // Allow flexible queries
      
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
