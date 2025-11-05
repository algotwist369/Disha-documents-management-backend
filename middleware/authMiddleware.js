const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const User = require('../models/userModel');
const BlacklistedToken = require('../models/blacklistedToken');
const Session = require('../models/sessionModel');
const UserSecuritySettings = require('../models/userSecuritySettings');

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

    // Validate that token is associated with an active session
    // This prevents multiple tabs/devices from using the same token
    const activeSession = await Session.findOne({ 
      user: user._id, 
      token: token 
    });
    
    if (!activeSession) {
      return res.status(401).json({ 
        success: false, 
        message: 'Session expired or invalid. Please login again.',
        reason: 'session_not_found'
      });
    }

    // Check if session has expired (use custom timeout if enabled)
    const now = new Date();
    if (activeSession.expiresAt < now) {
      await Session.deleteOne({ _id: activeSession._id });
      return res.status(401).json({ 
        success: false, 
        message: 'Session expired. Please login again.',
        reason: 'session_expired'
      });
    }

    // Check custom session timeout from security settings
    try {
      const securitySettings = await UserSecuritySettings.findOne({ user: user._id });
      if (securitySettings?.customSessionTimeout?.enabled) {
        const timeoutMinutes = securitySettings.customSessionTimeout.timeoutMinutes || 30;
        const timeoutMs = timeoutMinutes * 60 * 1000;
        const sessionAge = now - activeSession.lastActivity;
        
        if (sessionAge > timeoutMs) {
          await Session.deleteOne({ _id: activeSession._id });
          return res.status(401).json({ 
            success: false, 
            message: `Session timeout. Maximum inactivity time is ${timeoutMinutes} minutes. Please login again.`,
            reason: 'session_timeout'
          });
        }
      }
    } catch (err) {
      console.error('Error checking custom session timeout:', err);
      // Continue if there's an error checking security settings
    }

    // Update last activity
    activeSession.lastActivity = new Date();
    await activeSession.save();

    // Store token and session in request for logout use
    req.token = token;
    req.user = user;
    req.session = activeSession;
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
