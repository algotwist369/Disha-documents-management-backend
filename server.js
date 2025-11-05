const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const {
  noSQLInjectionProtection,
  parameterPollutionProtection,
  additionalSecurityChecks,
  requestSizeCheck
} = require('./middleware/securityMiddleware');

dotenv.config();

// Validate critical environment variables
const requiredEnvVars = ['MONGO_URI', 'JWT_SECRET'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  console.error(`Missing required environment variables: ${missingVars.join(', ')}`);
  console.error('Please set these variables in your .env file');
  process.exit(1);
}

const app = express();

// Security middleware - helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  frameguard: {
    action: 'deny' // Prevent clickjacking
  },
  noSniff: true, // Prevent MIME type sniffing
  xssFilter: true, // Enable XSS filter
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));

// CORS configuration - restrict origins in production
// Split and trim to allow values like "https://369.ciphra.in" even if spaces exist in .env
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
  : process.env.NODE_ENV === 'production' 
    ? [] // Production: require explicit ALLOWED_ORIGINS
    : ['http://localhost:3000', 'http://localhost:5173']; // Development fallback

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, postman, etc)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV !== 'production') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Compression middleware for better performance
app.use(compression());

// Request logging
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('combined')); // Apache-style logs for production
} else {
  app.use(morgan('dev')); // Colored, concise logs for development
}

// Body parser with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Trust proxy for correct IP and proto when behind reverse proxy
// This is CRITICAL for getting real client IPs in production
app.set('trust proxy', true);

// Middleware to log IP extraction details (for debugging)
app.use((req, res, next) => {
    // Only log in development or if explicitly enabled
    if (process.env.NODE_ENV !== 'production' || process.env.DEBUG_IP === 'true') {
        const { getClientIP } = require('./utils/ipExtractor');
        const extractedIP = getClientIP(req);
        console.log('📡 Request IP Info:', {
            extractedIP,
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'x-real-ip': req.headers['x-real-ip'],
            'cf-connecting-ip': req.headers['cf-connecting-ip'],
            'req.ip': req.ip,
            'remoteAddress': req.connection?.remoteAddress || req.socket?.remoteAddress
        });
    }
    next();
});

// ========== SECURITY MIDDLEWARE ==========
// NoSQL Injection Prevention
app.use(noSQLInjectionProtection);

// Parameter Pollution Prevention
app.use(parameterPollutionProtection);

// Additional Security Checks (XSS, etc.)
app.use(additionalSecurityChecks);

// Request Size Check
app.use(requestSizeCheck);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    success: true, 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Routes
app.use('/api/users', require('./routes/userRoutes'));
app.use('/api/documents', require('./routes/documentRoutes'));
app.use('/api/categories', require('./routes/categoryRoutes'));
app.use('/api/super-admin', require('./routes/superAdminRoutes'));

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(err.status || 500).json({ 
    success: false, 
    message: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message 
  });
});

const PORT = process.env.PORT || 5000;
let server;
let io;

// Create HTTP server
const httpServer = http.createServer(app);

// Initialize Socket.IO with CORS
io = new Server(httpServer, {
  cors: {
  origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Log allowed origins for easier debugging in production
console.log('Allowed CORS origins:', allowedOrigins);

// Socket.IO connection handling
io.on('connection', async (socket) => {
  console.log('Client connected:', socket.id);

  // Store user ID from handshake auth
  const token = socket.handshake.auth.token;
  
  // Update session with socket ID and join user room for notifications
  if (token) {
    try {
      const Session = require('./models/sessionModel');
      const jwt = require('jsonwebtoken');
      const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-prod';
      
      const decoded = jwt.verify(token, JWT_SECRET);
      const userId = decoded.id;

      await Session.updateOne(
        { token },
        { 
          socketId: socket.id,
          lastActivity: Date.now()
        }
      );
      console.log(`Socket ${socket.id} linked to session`);

      // Join user-specific room for notifications (only if not super admin)
      if (userId) {
        const User = require('./models/userModel');
        const user = await User.findById(userId);
        if (user && user.role !== 'super_admin') {
          socket.join(`user-${userId}`);
          console.log(`User ${userId} joined notification room: user-${userId}`);
        }
      }
    } catch (err) {
      console.error('Session update error:', err);
    }
  }

  // Join super admin room (for receiving alerts)
  socket.on('join-super-admin', (data) => {
    socket.join('super-admin-room');
    console.log(`Socket ${socket.id} joined super-admin-room`);
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Export io for use in other files
global.io = io;

const start = async () => {
  try {
    await connectDB();
    server = httpServer.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`Health check: http://localhost:${PORT}/health`);
      console.log(`Socket.IO ready for real-time communication`);
    });
  } catch (err) {
    console.error('Failed to start server due to DB error', err);
    process.exit(1);
  }
};

// Graceful shutdown handler
const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  if (server) {
    server.close(async () => {
      console.log('HTTP server closed.');
      
      // Close database connection
      try {
        const mongoose = require('mongoose');
        await mongoose.connection.close();
        console.log('MongoDB connection closed.');
      } catch (err) {
        console.error('Error closing MongoDB connection:', err);
      }
      
      console.log('Graceful shutdown completed.');
      process.exit(0);
    });

    // Force shutdown after 10 seconds
    setTimeout(() => {
      console.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  } else {
    process.exit(0);
  }
};

// Listen for termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Global error handler middleware (must be last)
app.use((err, req, res, next) => {
  console.error('Global error handler:', err.message || err);
  
  // Don't expose internal error details in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'An internal server error occurred' 
    : err.message || 'An error occurred';
  
  res.status(err.status || 500).json({
    success: false,
    message: message
  });
});

// Handle uncaught exceptions and unhandled rejections
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('unhandledRejection');
});

start();

module.exports = app;
