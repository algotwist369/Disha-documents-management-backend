const rateLimit = require('express-rate-limit');

const createRateLimiter = (options = {}) => {
  return rateLimit({
    windowMs: options.windowMs || 60 * 1000, // 1 minute
    max: options.max || 10, // limit each IP to 10 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many requests, please try again later.' },
    // Skip failed requests (don't count them)
    skipFailedRequests: false,
    // Trust proxy - match Express app setting
    // This allows rate limiting to work correctly when behind a reverse proxy
    trustProxy: true,
  });
};

module.exports = { createRateLimiter };
