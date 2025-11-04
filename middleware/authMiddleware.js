const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const User = require('../models/userModel');
const BlacklistedToken = require('../models/blacklistedToken');

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-prod';

// Verify token, attach user to req.user
const protect = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Not authorized, token missing' });
    }

    const token = authHeader.split(' ')[1];
    
    // Check if token is blacklisted
    const blacklisted = await BlacklistedToken.findOne({ token });
    if (blacklisted) {
      return res.status(401).json({ 
        success: false, 
        message: 'Token has been revoked. Please login again.',
        reason: blacklisted.reason
      });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.id) return res.status(401).json({ success: false, message: 'Invalid token' });

    // Load minimal user data
    const user = await User.findById(decoded.id).select('-password');
    if (!user) return res.status(401).json({ success: false, message: 'User not found' });

    // Store token in request for logout use
    req.token = token;
    req.user = user;
    next();
  } catch (err) {
    console.error('Auth error:', err.message || err);
    return res.status(401).json({ success: false, message: 'Not authorized' });
  }
};

// Role-based guard (exact match)
const requireRole = (role) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, message: 'Not authenticated' });
  if (req.user.role !== role) return res.status(403).json({ success: false, message: 'Forbidden' });
  next();
};

// Super admin only guard
const requireSuperAdmin = (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, message: 'Not authenticated' });
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ success: false, message: 'Super admin access required' });
  }
  next();
};

// Minimum role guard (allows higher roles)
// e.g., requireMinRole('admin') allows both 'admin' and 'super_admin'
const requireMinRole = (minRole) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, message: 'Not authenticated' });
  
  const roleHierarchy = {
    user: 1,
    admin: 2,
    super_admin: 3
  };

  const userRoleLevel = roleHierarchy[req.user.role] || 0;
  const requiredRoleLevel = roleHierarchy[minRole] || 0;

  if (userRoleLevel < requiredRoleLevel) {
    return res.status(403).json({ success: false, message: `${minRole} access or higher required` });
  }
  
  next();
};

module.exports = {
  protect,
  requireRole,
  requireSuperAdmin,
  requireMinRole,
};
