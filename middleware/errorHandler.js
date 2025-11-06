/**
 * Comprehensive Error Handler Middleware
 * Handles all types of errors and provides user-friendly messages
 */

const errorHandler = (err, req, res, next) => {
  // Log error details
  console.error('Error occurred:', {
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    user: req.user?.id || 'anonymous',
    timestamp: new Date().toISOString()
  });

  // Default error
  let statusCode = err.statusCode || err.status || 500;
  let message = err.message || 'An error occurred';
  let errorCode = err.code || 'INTERNAL_ERROR';
  let details = null;

  // Handle specific error types
  if (err.name === 'ValidationError') {
    // Mongoose validation error
    statusCode = 400;
    message = 'Validation failed';
    errorCode = 'VALIDATION_ERROR';
    details = Object.values(err.errors || {}).map(e => ({
      field: e.path,
      message: e.message
    }));
  } else if (err.name === 'CastError') {
    // Mongoose cast error (invalid ID format)
    statusCode = 400;
    message = 'Invalid ID format';
    errorCode = 'INVALID_ID';
  } else if (err.name === 'MongoServerError' && err.code === 11000) {
    // MongoDB duplicate key error
    statusCode = 409;
    message = 'Duplicate entry. This record already exists.';
    errorCode = 'DUPLICATE_ENTRY';
    const field = Object.keys(err.keyPattern || {})[0];
    if (field) {
      details = { field, message: `${field} already exists` };
    }
  } else if (err.name === 'JsonWebTokenError') {
    // JWT error
    statusCode = 401;
    message = 'Invalid or expired token. Please login again.';
    errorCode = 'INVALID_TOKEN';
  } else if (err.name === 'TokenExpiredError') {
    // JWT expired
    statusCode = 401;
    message = 'Token expired. Please login again.';
    errorCode = 'TOKEN_EXPIRED';
  } else if (err.name === 'MulterError') {
    // File upload error
    statusCode = 400;
    message = err.message || 'File upload error';
    errorCode = 'UPLOAD_ERROR';
    if (err.code === 'LIMIT_FILE_SIZE') {
      message = 'File size exceeds the maximum allowed limit';
    } else if (err.code === 'LIMIT_FILE_COUNT') {
      message = 'Too many files uploaded';
    } else if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      message = 'Unexpected file field';
    }
  } else if (err.code === 'ENOENT') {
    // File not found
    statusCode = 404;
    message = 'File not found';
    errorCode = 'FILE_NOT_FOUND';
  } else if (err.code === 'EACCES' || err.code === 'EPERM') {
    // Permission denied
    statusCode = 403;
    message = 'Permission denied. Insufficient file system permissions.';
    errorCode = 'PERMISSION_DENIED';
  } else if (err.type === 'entity.parse.failed') {
    // JSON parse error
    statusCode = 400;
    message = 'Invalid JSON format in request body';
    errorCode = 'INVALID_JSON';
  } else if (err.type === 'entity.too.large') {
    // Request too large
    statusCode = 413;
    message = 'Request payload too large';
    errorCode = 'PAYLOAD_TOO_LARGE';
  }

  // Don't expose internal error details in production
  const isDevelopment = process.env.NODE_ENV !== 'production';
  
  // Build error response
  const errorResponse = {
    success: false,
    message: message,
    error: errorCode,
    ...(isDevelopment && { 
      stack: err.stack,
      originalError: err.message 
    }),
    ...(details && { details })
  };

  // Send error response
  res.status(statusCode).json(errorResponse);
};

// Async error wrapper - wraps async route handlers to catch errors
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// 404 Not Found handler
const notFoundHandler = (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
    error: 'ROUTE_NOT_FOUND'
  });
};

module.exports = {
  errorHandler,
  asyncHandler,
  notFoundHandler
};

