const hpp = require('hpp');

// ========== SECURITY MIDDLEWARE ==========

// 1. NoSQL Injection Prevention (Custom implementation for Express 5)
// Removes $ and . from request data to prevent NoSQL injection
const noSQLInjectionProtection = (req, res, next) => {
  const sanitize = (obj) => {
    if (obj && typeof obj === 'object') {
      for (const key in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          // Check if key contains $ or .
          if (key.includes('$') || key.includes('.')) {
            console.warn(`⚠️  NoSQL Injection attempt detected! Key: ${key}`);
            delete obj[key];
            continue;
          }
          
          // Recursively sanitize nested objects
          if (typeof obj[key] === 'object' && obj[key] !== null) {
            sanitize(obj[key]);
          }
          
          // Sanitize string values
          if (typeof obj[key] === 'string') {
            // Remove dangerous characters
            if (obj[key].includes('$') || obj[key].match(/\.\$/)) {
              obj[key] = obj[key].replace(/\$/g, '_').replace(/\.\$/g, '_');
            }
          }
        }
      }
    }
    return obj;
  };

  try {
    // Sanitize request body
    if (req.body) {
      req.body = sanitize(req.body);
    }

    // Sanitize query parameters
    if (req.query) {
      req.query = sanitize(req.query);
    }

    // Sanitize URL parameters
    if (req.params) {
      req.params = sanitize(req.params);
    }

    next();
  } catch (error) {
    console.error('Sanitization error:', error);
    next();
  }
};

// 2. XSS Protection (Cross-Site Scripting)
// Note: xss-clean is deprecated, using helmet and CSP instead
// Manual sanitization in validators

// 3. HTTP Parameter Pollution Prevention
// Prevents duplicate parameters in query strings
const parameterPollutionProtection = hpp({
  whitelist: ['page', 'limit', 'sort', 'search', 'fileType', 'action', 'severity', 'status']
});

// 4. Additional Security Checks
const additionalSecurityChecks = (req, res, next) => {
  // Check for suspicious patterns
  const suspiciousPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /onerror=/gi,
    /onload=/gi,
    /<iframe/gi,
    /eval\(/gi,
    /expression\(/gi
  ];

  const checkString = (str) => {
    if (typeof str !== 'string') return false;
    return suspiciousPatterns.some(pattern => pattern.test(str));
  };

  const checkObject = (obj) => {
    if (!obj || typeof obj !== 'object') return false;
    
    for (let key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        const value = obj[key];
        if (typeof value === 'string' && checkString(value)) {
          return true;
        } else if (typeof value === 'object' && value !== null) {
          if (checkObject(value)) return true;
        }
      }
    }
    return false;
  };

  // Check request body
  if (req.body && checkObject(req.body)) {
    console.warn('⚠️  Potential XSS attack detected in request body');
    return res.status(400).json({
      success: false,
      message: 'Invalid input detected. Request blocked for security reasons.'
    });
  }

  // Check query parameters
  if (req.query && checkObject(req.query)) {
    console.warn('⚠️  Potential XSS attack detected in query parameters');
    return res.status(400).json({
      success: false,
      message: 'Invalid input detected. Request blocked for security reasons.'
    });
  }

  next();
};

// 5. Request Size Limiting (Already in server.js but adding check)
const requestSizeCheck = (req, res, next) => {
  // Additional check for unusually large requests
  const contentLength = req.headers['content-length'];
  if (contentLength && parseInt(contentLength) > 50 * 1024 * 1024) { // 50MB
    console.warn('⚠️  Request too large:', contentLength);
    return res.status(413).json({
      success: false,
      message: 'Request entity too large'
    });
  }
  next();
};

// 6. IP Whitelisting Check for Admin Routes (optional)
const adminIPCheck = (req, res, next) => {
  // Skip if not in production or no IP whitelist configured
  if (process.env.NODE_ENV !== 'production' || !process.env.ADMIN_IP_WHITELIST) {
    return next();
  }

  const allowedIPs = process.env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
  const clientIP = req.ip || req.connection.remoteAddress;

  if (!allowedIPs.includes(clientIP)) {
    console.warn(`⚠️  Unauthorized admin access attempt from IP: ${clientIP}`);
    return res.status(403).json({
      success: false,
      message: 'Access denied from this IP address'
    });
  }

  next();
};

module.exports = {
  noSQLInjectionProtection,
  parameterPollutionProtection,
  additionalSecurityChecks,
  requestSizeCheck,
  adminIPCheck
};

