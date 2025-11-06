/**
 * Performance Monitoring Middleware
 * Tracks response times and logs slow requests
 */

const performance = require('perf_hooks').performance;

// Configuration
const SLOW_REQUEST_THRESHOLD = 1000; // Log requests slower than 1 second
const ENABLE_PERFORMANCE_LOGGING = process.env.ENABLE_PERFORMANCE_LOGGING !== 'false';

const performanceMonitor = (req, res, next) => {
  if (!ENABLE_PERFORMANCE_LOGGING) {
    return next();
  }

  const startTime = performance.now();
  const startMemory = process.memoryUsage();

  // Override res.end to capture response time
  const originalEnd = res.end;
  res.end = function(...args) {
    const endTime = performance.now();
    const duration = endTime - startTime;
    const endMemory = process.memoryUsage();
    
    // Log slow requests
    if (duration > SLOW_REQUEST_THRESHOLD) {
      console.warn(`⚠️  Slow request detected: ${req.method} ${req.originalUrl}`);
      console.warn(`   Duration: ${duration.toFixed(2)}ms`);
      console.warn(`   Status: ${res.statusCode}`);
      console.warn(`   Memory: ${((endMemory.heapUsed - startMemory.heapUsed) / 1024 / 1024).toFixed(2)}MB`);
    }
    
    // Add performance header in development
    if (process.env.NODE_ENV !== 'production') {
      res.setHeader('X-Response-Time', `${duration.toFixed(2)}ms`);
    }
    
    // Call original end
    originalEnd.apply(this, args);
  };

  next();
};

module.exports = performanceMonitor;

