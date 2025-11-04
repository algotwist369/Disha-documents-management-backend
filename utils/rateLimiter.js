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
    // Trust proxy - only use forwarded IP if behind a trusted proxy
    validate: { trustProxy: false },
  });
};

module.exports = { createRateLimiter };
