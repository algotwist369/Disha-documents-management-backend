const User = require('../models/userModel');
const sendMail = require('../utils/sendMail');
const AuditLog = require('../models/auditLog');
const SecurityAlert = require('../models/securityAlertModel');
const Session = require('../models/sessionModel');
const UserSecuritySettings = require('../models/userSecuritySettings');
const PendingLoginRequest = require('../models/pendingLoginRequest');
const BlacklistedToken = require('../models/blacklistedToken');
const jwt = require('jsonwebtoken');
const { parseDeviceInfo } = require('../utils/deviceParser');
const { getClientIP } = require('../utils/ipExtractor');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-prod';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// Generate JWT token
const generateToken = (userId) => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// Register a new user
const registerUser = async (req, res) => {
    try {
        const { name, phone, password } = req.body;

        // Validation
        if (!name || !phone || !password) {
            return res.status(400).json({ success: false, message: 'Name, phone, and password are required' });
        }

        if (password.length < 8) {
            return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long' });
        }

        // Basic phone validation (10-15 digits)
        const phoneRegex = /^\+?[1-9]\d{9,14}$/;
        if (!phoneRegex.test(phone.replace(/[\s-]/g, ''))) {
            return res.status(400).json({ success: false, message: 'Invalid phone number format' });
        }

        // Check if user already exists
        let user = await User.findOne({ phone });
        if (user) {
            return res.status(400).json({ success: false, message: 'User already exists' });
        }

        // Create new user
        user = new User({ name, phone, password });
        await user.save();

        // Generate token for immediate login
        const token = generateToken(user._id);

        res.status(201).json({ 
            success: true,
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Login user
const loginUser = async (req, res) => {
    try {
        const { phone, password } = req.body;

        // Validation
        if (!phone || !password) {
            return res.status(400).json({ success: false, message: 'Phone and password are required' });
        }

        // Find user by phone
        const user = await User.findOne({ phone });
        if (!user) return res.status(400).json({ success: false, message: 'Invalid credentials' });

        // Check lock
        if (user.isLocked) {
            const lockTimeRemaining = Math.ceil((user.lockUntil - Date.now()) / (60 * 1000)); // minutes remaining
            return res.status(403).json({ 
                success: false, 
                message: `Account locked due to multiple failed login attempts. Please try again after ${lockTimeRemaining} minutes.`,
                locked: true,
                minutesRemaining: lockTimeRemaining
            });
        }

        // ===== SECURITY SETTINGS CHECK =====
        const securitySettings = await UserSecuritySettings.findOne({ user: user._id });
        
        if (securitySettings) {
            // 1. IP Whitelist Check
            if (securitySettings.enforceIpWhitelist && securitySettings.ipWhitelist && securitySettings.ipWhitelist.length > 0) {
                const allowedIPs = securitySettings.ipWhitelist.map(item => item.ip ? item.ip.trim() : '').filter(ip => ip);
                const userIP = getClientIP(req);
                
                // Normalize IPs for comparison (handle IPv4, IPv6, etc.)
                const normalizeIP = (ip) => {
                    if (!ip) return null;
                    let normalized = String(ip).trim();
                    // Remove IPv6 brackets
                    if (normalized.startsWith('[') && normalized.endsWith(']')) {
                        normalized = normalized.slice(1, -1);
                    }
                    // Handle IPv6-mapped IPv4
                    if (normalized.startsWith('::ffff:')) {
                        normalized = normalized.replace('::ffff:', '');
                    }
                    // Remove any whitespace
                    normalized = normalized.replace(/\s+/g, '');
                    return normalized.toLowerCase();
                };
                
                const normalizedUserIP = normalizeIP(userIP);
                const normalizedAllowedIPs = allowedIPs.map(normalizeIP).filter(Boolean);
                
                // Debug logging
                console.log('🔐 IP Whitelist Check:', {
                    enforceIpWhitelist: securitySettings.enforceIpWhitelist,
                    userIP: userIP,
                    normalizedUserIP: normalizedUserIP,
                    allowedIPs: allowedIPs,
                    normalizedAllowedIPs: normalizedAllowedIPs,
                    match: normalizedAllowedIPs.includes(normalizedUserIP)
                });
                
                if (!normalizedAllowedIPs.includes(normalizedUserIP)) {
                    // Create security alert for unauthorized IP attempt
                    try {
                        const alert = await SecurityAlert.create({
                            user: user._id,
                            alertType: 'suspicious_activity',
                            severity: 'high',
                            message: `Login attempt from unauthorized IP: ${userIP}. Allowed IPs: ${normalizedAllowedIPs.join(', ')}`,
                            ip: userIP,
                            userAgent: req.headers['user-agent']
                        });

                        // Emit real-time alert to super admin room and broadcast fallback
                        if (global.io) {
                            const payload = {
                                alert: {
                                    ...alert.toObject(),
                                    user: {
                                        _id: user._id,
                                        name: user.name,
                                        phone: user.phone,
                                        role: user.role
                                    }
                                }
                            };
                            // Preferred: send to super-admin-room
                            try { global.io.to('super-admin-room').emit('new-security-alert', payload); } catch (e) { console.error('Socket emit to room failed:', e); }
                            // Fallback: broadcast to all connected clients (will be filtered client-side)
                            try { global.io.emit('new-security-alert', payload); } catch (e) { console.error('Global socket emit failed:', e); }
                        }

                        // Send email to admin (use fallback address if ADMIN_EMAIL not set)
                        const adminEmail = process.env.ADMIN_EMAIL || 'ankitdos14@gmail.com';
                        try {
                            await sendMail({
                                to: adminEmail,
                                subject: `🚨 UNAUTHORIZED IP: Login Attempt - ${user.name}`,
                                text: `SECURITY ALERT - UNAUTHORIZED IP\n\nUser: ${user.name}\nPhone: ${user.phone}\nRole: ${user.role}\n\nUNAUTHORIZED IP DETECTED: ${getClientIP(req)}\nNormalized User IP: ${normalizedUserIP}\nAllowed IPs: ${normalizedAllowedIPs.join(', ')}\n\nUser Agent: ${req.headers['user-agent']}\nTime: ${new Date().toISOString()}\n\nThis login attempt has been BLOCKED. Please review and take appropriate action.`
                            });
                        } catch (err) {
                            console.error('sendMail error:', err);
                        }
                    } catch (e) {
                        console.error('Security alert creation error:', e);
                    }

                    return res.status(403).json({ 
                        success: false, 
                        message: 'Access denied. Your IP address is not authorized for this account. Please contact administrator.',
                        reason: 'unauthorized_ip'
                    });
                }
            }

            // 2. Time-based Login Restrictions
            if (securitySettings.allowedLoginHours.enabled) {
                const currentHour = new Date().getHours();
                const { startHour, endHour } = securitySettings.allowedLoginHours;
                
                let isWithinAllowedHours = false;
                if (startHour <= endHour) {
                    // Normal range (e.g., 9 AM to 5 PM)
                    isWithinAllowedHours = currentHour >= startHour && currentHour <= endHour;
                } else {
                    // Overnight range (e.g., 10 PM to 6 AM)
                    isWithinAllowedHours = currentHour >= startHour || currentHour <= endHour;
                }

                if (!isWithinAllowedHours) {
                    return res.status(403).json({ 
                        success: false, 
                        message: `Login is only allowed between ${startHour}:00 and ${endHour}:00. Current time: ${currentHour}:00`,
                        reason: 'outside_allowed_hours'
                    });
                }
            }
        }

        const match = await user.comparePassword(password);
        if (!match) {
            const attemptInfo = await user.incLoginAttempts();
            
            // Create security alert for failed login attempts
            if (attemptInfo.attemptsUsed >= 2) {
                try {
                    const severity = attemptInfo.isLocked ? 'critical' : attemptInfo.attemptsUsed === 2 ? 'high' : 'medium';
                    const alert = await SecurityAlert.create({
                        user: user._id,
                        alertType: attemptInfo.isLocked ? 'account_locked' : 'failed_login',
                        severity: severity,
                        message: attemptInfo.isLocked 
                            ? `Account locked after ${attemptInfo.attemptsUsed} failed login attempts`
                            : `${attemptInfo.attemptsUsed} failed login attempts (${attemptInfo.attemptsRemaining} remaining)`,
                        attemptsCount: attemptInfo.attemptsUsed,
                        ip: getClientIP(req),
                        userAgent: req.headers['user-agent']
                    });

                    // Emit real-time alert to super admin room and broadcast fallback
                    if (global.io) {
                        const payload = {
                            alert: {
                                ...alert.toObject(),
                                user: {
                                    _id: user._id,
                                    name: user.name,
                                    phone: user.phone,
                                    role: user.role
                                }
                            }
                        };
                        try { global.io.to('super-admin-room').emit('new-security-alert', payload); } catch (e) { console.error('Socket emit to room failed:', e); }
                        try { global.io.emit('new-security-alert', payload); } catch (e) { console.error('Global socket emit failed:', e); }
                    }
                } catch (e) {
                    console.error('Security alert creation error:', e);
                }

                // Send email notification to admin (fallback to configured address)
                const adminEmail = process.env.ADMIN_EMAIL || 'ankitdos14@gmail.com';
                const emailSubject = attemptInfo.isLocked 
                    ? `🔒 CRITICAL: Account Locked - ${user.name}`
                    : `⚠️ WARNING: Multiple Failed Login Attempts - ${user.name}`;
                
                const emailText = `SECURITY ALERT\n\nUser: ${user.name}\nPhone: ${user.phone}\nRole: ${user.role}\nStatus: ${attemptInfo.isLocked ? 'ACCOUNT LOCKED' : 'SUSPICIOUS ACTIVITY'}\n\nFailed Login Attempts: ${attemptInfo.attemptsUsed}\nRemaining Attempts: ${attemptInfo.attemptsRemaining}\n\nIP Address: ${getClientIP(req)}\nUser Agent: ${req.headers['user-agent']}\nTime: ${new Date().toISOString()}\n\n${attemptInfo.isLocked ? 'Account has been automatically locked for 30 minutes.' : 'Please monitor this account for suspicious activity.'}\n\nLogin to admin panel to view more details or take action.`;

                try {
                    await sendMail({ to: adminEmail, subject: emailSubject, text: emailText });
                } catch (err) {
                    console.error('sendMail error:', err);
                }
            }
            
            if (attemptInfo.isLocked) {
                    // Account just got locked - terminate active sessions and blacklist tokens
                    try {
                        const sessions = await Session.find({ user: user._id });
                        for (const session of sessions) {
                            if (global.io && session.socketId) {
                                global.io.to(session.socketId).emit('force-logout', {
                                    message: `Account locked! Too many failed login attempts. You have been logged out.`,
                                    reason: 'account_locked'
                                });

                                const socket = global.io.sockets.sockets.get(session.socketId);
                                if (socket) socket.disconnect(true);
                            }

                            // Blacklist token
                            try {
                                if (session.token) {
                                    await BlacklistedToken.create({
                                        token: session.token,
                                        user: user._id,
                                        reason: 'account_locked',
                                        expiresAt: session.expiresAt || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
                                    });
                                }
                            } catch (be) {
                                console.error('Error blacklisting token after auto-lock:', be);
                            }
                        }

                        await Session.deleteMany({ user: user._id });
                    } catch (e) {
                        console.error('Error terminating sessions after auto-lock:', e);
                    }

                    // Account just got locked
                    return res.status(403).json({ 
                        success: false, 
                        message: `Account locked! Too many failed login attempts. Please try again after ${attemptInfo.lockTime} minutes.`,
                        locked: true,
                        lockTime: attemptInfo.lockTime
                    });
            } else {
                // Show remaining attempts
                return res.status(400).json({ 
                    success: false, 
                    message: `Invalid credentials. You have ${attemptInfo.attemptsRemaining} attempt${attemptInfo.attemptsRemaining !== 1 ? 's' : ''} remaining before your account is locked.`,
                    attemptsRemaining: attemptInfo.attemptsRemaining,
                    attemptsUsed: attemptInfo.attemptsUsed
                });
            }
        }

        // Successful login: reset attempts
        await user.resetLoginAttempts();

        // Audit log
        try {
            const auditLog = await AuditLog.create({ 
                user: user._id, 
                document: null, 
                action: 'login', 
                ip: getClientIP(req), 
                userAgent: req.headers['user-agent'] 
            });

            // Emit real-time audit log to super admin
            if (global.io) {
                global.io.to('super-admin-room').emit('new-audit-log', {
                    log: {
                        ...auditLog.toObject(),
                        user: {
                            _id: user._id,
                            name: user.name,
                            phone: user.phone,
                            role: user.role
                        }
                    }
                });
            }
        } catch (e) { 
            console.error('audit log error', e); 
        }

        // Generate JWT token
        const token = generateToken(user._id);

        // ===== DEVICE/SESSION MANAGEMENT: Check for existing sessions =====
        try {
            // ALWAYS check for existing sessions first
            const existingSessions = await Session.find({ user: user._id });
            
            // Determine max devices allowed for this user
            let maxDevices = 1; // Default: single device
            if (securitySettings && securitySettings.allowMultipleDevices) {
                maxDevices = securitySettings.maxDevices || 1;
            }
            
            // Parse device information for new login
            const deviceInfo = parseDeviceInfo(req.headers['user-agent'], getClientIP(req));
            
            // SINGLE DEVICE MODE (maxDevices === 1): Require approval if existing session exists
            // MULTI-DEVICE MODE: Require approval if max device limit reached
            // This ensures approval/rejection flow works for both modes
            if ((maxDevices === 1 && existingSessions.length > 0) || 
                (maxDevices > 1 && existingSessions.length >= maxDevices)) {
                
                // Create pending login request
                const expiresAt = new Date();
                expiresAt.setMinutes(expiresAt.getMinutes() + 5); // 5 minutes to approve
                
                const pendingRequest = await PendingLoginRequest.create({
                    user: user._id,
                    token,
                    deviceInfo,
                    status: 'pending',
                    expiresAt
                });
                
                // Send approval request to existing device(s) via Socket.IO
                const approvalData = {
                    requestId: pendingRequest._id,
                    deviceInfo: deviceInfo,
                    user: {
                        name: user.name,
                        phone: user.phone
                    },
                    message: 'Someone is trying to login to your account from another device',
                    expiresIn: 300 // 5 minutes in seconds
                };

                console.log(`📨 Sending login approval request to ${existingSessions.length} existing session(s)`);
                
                for (const existingSession of existingSessions) {
                    console.log(`  - Session ID: ${existingSession._id}, Socket ID: ${existingSession.socketId || 'NOT SET'}`);
                    
                    if (global.io && existingSession.socketId) {
                        // Check if socket is still connected
                        const socket = global.io.sockets.sockets.get(existingSession.socketId);
                        if (socket && socket.connected) {
                            console.log(`  ✅ Emitting to socket ${existingSession.socketId}`);
                            global.io.to(existingSession.socketId).emit('login-approval-request', approvalData);
                        } else {
                            console.log(`  ⚠️ Socket ${existingSession.socketId} is not connected, trying to emit anyway`);
                            global.io.to(existingSession.socketId).emit('login-approval-request', approvalData);
                        }
                    } else {
                        console.log(`  ❌ Cannot emit: global.io=${!!global.io}, socketId=${!!existingSession.socketId}`);
                        // Try to find socket by user ID if socketId is missing
                        if (global.io && !existingSession.socketId) {
                            console.log(`  🔍 Searching for socket by user ID...`);
                            // Broadcast to all sockets and let them filter (not ideal but fallback)
                            global.io.emit('login-approval-request', approvalData);
                        }
                    }
                }
                
                console.log(`✅ Login approval request created for user: ${user.name} (maxDevices: ${maxDevices}, existingSessions: ${existingSessions.length})`);
                
                // Return "pending approval" response - user must wait for approval
                return res.status(202).json({
                    success: false,
                    pending: true,
                    requestId: pendingRequest._id,
                    message: 'Login approval required. Please approve from your existing device.',
                    expiresIn: 300
                });
            }

            // For single device mode, ensure no existing sessions before creating new one
            // This is a safety measure in case we reach here without approval flow
            if (maxDevices === 1) {
                const remainingSessions = await Session.find({ user: user._id });
                if (remainingSessions.length > 0) {
                    // Force logout any remaining sessions
                    for (const session of remainingSessions) {
                        if (global.io && session.socketId) {
                            global.io.to(session.socketId).emit('force-logout', {
                                message: 'You have been logged out because you logged in from another device.',
                                reason: 'new_device_login'
                            });
                            const socket = global.io.sockets.sockets.get(session.socketId);
                            if (socket) {
                                socket.disconnect(true);
                            }
                        }
                    }
                    await Session.deleteMany({ user: user._id });
                    console.log(`Cleaned up ${remainingSessions.length} existing session(s) for user: ${user.name}`);
                }
            }

            const expiresAt = new Date();
            if (securitySettings && securitySettings.customSessionTimeout.enabled) {
                const timeoutMinutes = securitySettings.customSessionTimeout.timeoutMinutes;
                expiresAt.setMinutes(expiresAt.getMinutes() + timeoutMinutes);
            } else {
                expiresAt.setDate(expiresAt.getDate() + 7); // Default: 7 days expiry
            }

            // Create new session - unique constraint on user field prevents duplicates
            // Even if two tabs try simultaneously, MongoDB will only allow one
            try {
                await Session.create({
                    user: user._id,
                    token,
                    deviceInfo,
                    expiresAt
                });
            } catch (sessionCreateError) {
                // Handle duplicate key error (race condition)
                if (sessionCreateError.code === 11000) {
                    // Session already exists, delete it and try again
                    await Session.deleteMany({ user: user._id });
                    await Session.create({
                        user: user._id,
                        token,
                        deviceInfo,
                        expiresAt
                    });
                    console.log(`Race condition handled: Recreated session for user: ${user.name}`);
                } else {
                    throw sessionCreateError;
                }
            }

        } catch (sessionError) {
            console.error('Session management error:', sessionError);
            // Continue with login even if session management fails
        }

        // Notify admin about login
        const adminEmail = process.env.ADMIN_EMAIL || 'ankitdos14@gmail.com';
        sendMail({
            to: adminEmail,
            subject: `User login: ${user.name} (${user._id})`,
            text: `User ${user.name} with phone ${user.phone} logged in at ${new Date().toISOString()} from IP ${getClientIP(req)} UA ${req.headers['user-agent']}`
        }).catch(err => console.error('sendMail error', err));

        res.status(200).json({ 
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// delete user - Admin and Super Admin
const deleteUser = async (req, res) => {
    try {
        // Check if user is authenticated (should be set by protect middleware)
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Not authenticated' });
        }

        // Role check handled by requireMinRole('admin') middleware
        // This allows both 'admin' and 'super_admin' to delete users

        const { userId } = req.params;

        // Validate userId
        if (!userId || !userId.match(/^[0-9a-fA-F]{24}$/)) {
            return res.status(400).json({ success: false, message: 'Invalid user ID' });
        }

        // Prevent self-deletion
        if (userId === req.user._id.toString()) {
            return res.status(400).json({ success: false, message: 'Cannot delete your own account' });
        }

        // Find and delete user by ID
        const user = await User.findByIdAndDelete(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.status(200).json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Approve login request
const approveLoginRequest = async (req, res) => {
    try {
        const { requestId } = req.params;
        
        // Find pending request
        const pendingRequest = await PendingLoginRequest.findById(requestId);
        if (!pendingRequest || pendingRequest.status !== 'pending') {
            return res.status(404).json({ success: false, message: 'Login request not found or already processed' });
        }
        
        // Verify request belongs to logged-in user
        if (pendingRequest.user.toString() !== req.user._id.toString()) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }
        
        // Mark as approved
        pendingRequest.status = 'approved';
        await pendingRequest.save();
        
        // Delete existing sessions (current device will be logged out)
        const existingSessions = await Session.find({ user: req.user._id });
        for (const session of existingSessions) {
            if (global.io && session.socketId) {
                global.io.to(session.socketId).emit('force-logout', {
                    message: 'You approved login from another device.',
                    reason: 'approved_new_device'
                });
                
                const socket = global.io.sockets.sockets.get(session.socketId);
                if (socket) {
                    socket.disconnect(true);
                }
            }
            await Session.deleteOne({ _id: session._id });
        }
        
        // Create new session for the approved device
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days
        
        await Session.create({
            user: pendingRequest.user,
            token: pendingRequest.token,
            deviceInfo: pendingRequest.deviceInfo,
            expiresAt
        });
        
        // Notify the new device via Socket.IO (they need to poll or listen)
        if (global.io) {
            global.io.emit('login-request-approved', {
                requestId: pendingRequest._id,
                userId: pendingRequest.user,
                token: pendingRequest.token
            });
        }
        
        console.log(`Login request approved for user: ${req.user.name}`);
        
        res.json({ 
            success: true, 
            message: 'Login approved. You will be logged out from this device.',
            redirectToLogin: true
        });
    } catch (error) {
        console.error('Approve login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Reject login request
const rejectLoginRequest = async (req, res) => {
    try {
        const { requestId } = req.params;
        
        // Find pending request
        const pendingRequest = await PendingLoginRequest.findById(requestId);
        if (!pendingRequest || pendingRequest.status !== 'pending') {
            return res.status(404).json({ success: false, message: 'Login request not found or already processed' });
        }
        
        // Verify request belongs to logged-in user
        if (pendingRequest.user.toString() !== req.user._id.toString()) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }
        
        // Mark as rejected
        pendingRequest.status = 'rejected';
        await pendingRequest.save();
        
        // Notify the new device via Socket.IO
        if (global.io) {
            global.io.emit('login-request-rejected', {
                requestId: pendingRequest._id,
                userId: pendingRequest.user
            });
        }
        
        console.log(`Login request rejected for user: ${req.user.name}`);
        
        res.json({ 
            success: true, 
            message: 'Login request rejected successfully'
        });
    } catch (error) {
        console.error('Reject login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Check login request status (for new device polling)
const checkLoginRequestStatus = async (req, res) => {
    try {
        const { requestId } = req.params;
        
        const pendingRequest = await PendingLoginRequest.findById(requestId).populate('user', 'name phone role');
        if (!pendingRequest) {
            return res.status(404).json({ success: false, message: 'Login request not found' });
        }
        
        res.json({ 
            success: true, 
            status: pendingRequest.status,
            token: pendingRequest.status === 'approved' ? pendingRequest.token : null,
            user: pendingRequest.status === 'approved' ? pendingRequest.user : null
        });
    } catch (error) {
        console.error('Check login status error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Logout user - Blacklist token and delete session
const logoutUser = async (req, res) => {
    try {
        const token = req.token; // Set by protect middleware
        const userId = req.user._id;

        // Blacklist the token
        try {
            await BlacklistedToken.create({
                token,
                user: userId,
                reason: 'logout',
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
            });
        } catch (err) {
            // Token might already be blacklisted, ignore duplicate error
            if (err.code !== 11000) {
                console.error('Blacklist token error:', err);
            }
        }

        // Delete session
        await Session.deleteOne({ user: userId });

        // Create audit log
        try {
            const auditLog = await AuditLog.create({
                user: userId,
                document: null,
                action: 'logout',
                ip: getClientIP(req),
                userAgent: req.headers['user-agent']
            });

            // Emit real-time audit log to super admin
            if (global.io) {
                global.io.to('super-admin-room').emit('new-audit-log', {
                    log: {
                        ...auditLog.toObject(),
                        user: {
                            _id: req.user._id,
                            name: req.user.name,
                            phone: req.user.phone,
                            role: req.user.role
                        }
                    }
                });
            }
        } catch (e) {
            console.error('audit log error', e);
        }

        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

module.exports = {
    registerUser,
    loginUser,
    logoutUser,
    deleteUser,
    approveLoginRequest,
    rejectLoginRequest,
    checkLoginRequestStatus
};

// ========== ADDITIONAL ENDPOINTS ==========
// List basic users (for permissions selection)
// Returns minimal fields and is available to any authenticated user
module.exports.listUsersBasic = async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Not authenticated' });
        }

        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 100, 200);
        const skip = (page - 1) * limit;

        const search = (req.query.search || '').trim();
        const query = {};
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } }
            ];
        }

        const [users, total] = await Promise.all([
            User.find(query)
                .select('_id name phone role')
                .sort({ name: 1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            User.countDocuments(query)
        ]);

        res.json({
            success: true,
            count: users.length,
            total,
            page,
            pages: Math.ceil(total / limit),
            data: users
        });
    } catch (error) {
        console.error('listUsersBasic error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Update notification preferences
const updateNotificationPreferences = async (req, res) => {
    try {
        const user = req.user;
        if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

        // Don't allow super admin to change notification preferences
        if (user.role === 'super_admin') {
            return res.status(403).json({ success: false, message: 'Super admin cannot change notification preferences' });
        }

        const { email, emailOnView, emailOnDownload, dashboardOnView, dashboardOnDownload } = req.body;

        const updateData = {
            'notifications.emailOnView': emailOnView !== undefined ? emailOnView : user.notifications?.emailOnView || false,
            'notifications.emailOnDownload': emailOnDownload !== undefined ? emailOnDownload : user.notifications?.emailOnDownload || false,
            'notifications.dashboardOnView': dashboardOnView !== undefined ? dashboardOnView : user.notifications?.dashboardOnView !== false,
            'notifications.dashboardOnDownload': dashboardOnDownload !== undefined ? dashboardOnDownload : user.notifications?.dashboardOnDownload !== false
        };

        // Update email if provided
        if (email !== undefined) {
            // Basic email validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (email && !emailRegex.test(email)) {
                return res.status(400).json({ success: false, message: 'Invalid email format' });
            }
            updateData.email = email || '';
        }

        const updatedUser = await User.findByIdAndUpdate(
            user._id,
            { $set: updateData },
            { new: true, select: 'name phone email role notifications' }
        );

        res.json({ success: true, data: updatedUser });
    } catch (error) {
        console.error('updateNotificationPreferences error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Get notifications for current user
const getNotifications = async (req, res) => {
    try {
        const user = req.user;
        if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

        // Don't return notifications for super admin
        if (user.role === 'super_admin') {
            return res.json({ success: true, data: [], count: 0 });
        }

        const Notification = require('../models/notificationModel');
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 20, 100);
        const skip = (page - 1) * limit;

        const [notifications, total] = await Promise.all([
            Notification.find({ user: user._id })
                .populate('document', 'originalName companyName')
                .populate('viewedBy', 'name phone')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            Notification.countDocuments({ user: user._id })
        ]);

        res.json({
            success: true,
            data: notifications,
            count: notifications.length,
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('getNotifications error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Mark notification as read
const markNotificationRead = async (req, res) => {
    try {
        const user = req.user;
        const { notificationId } = req.params;
        if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

        const Notification = require('../models/notificationModel');
        const notification = await Notification.findOne({ _id: notificationId, user: user._id });

        if (!notification) {
            return res.status(404).json({ success: false, message: 'Notification not found' });
        }

        notification.read = true;
        await notification.save();

        res.json({ success: true, data: notification });
    } catch (error) {
        console.error('markNotificationRead error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Delete notification
const deleteNotification = async (req, res) => {
    try {
        const user = req.user;
        const { notificationId } = req.params;
        if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

        const Notification = require('../models/notificationModel');
        const notification = await Notification.findOneAndDelete({ _id: notificationId, user: user._id });

        if (!notification) {
            return res.status(404).json({ success: false, message: 'Notification not found' });
        }

        res.json({ success: true, message: 'Notification deleted' });
    } catch (error) {
        console.error('deleteNotification error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Delete all notifications
const deleteAllNotifications = async (req, res) => {
    try {
        const user = req.user;
        if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

        // Don't allow super admin
        if (user.role === 'super_admin') {
            return res.status(403).json({ success: false, message: 'Super admin cannot delete notifications' });
        }

        const Notification = require('../models/notificationModel');
        await Notification.deleteMany({ user: user._id });

        res.json({ success: true, message: 'All notifications deleted' });
    } catch (error) {
        console.error('deleteAllNotifications error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Get current user profile (for email)
const getCurrentUser = async (req, res) => {
    try {
        const user = req.user;
        if (!user) return res.status(401).json({ success: false, message: 'Not authenticated' });

        const currentUser = await User.findById(user._id).select('name phone email role notifications').lean();
        res.json({ success: true, data: currentUser });
    } catch (error) {
        console.error('getCurrentUser error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

module.exports.updateNotificationPreferences = updateNotificationPreferences;
module.exports.getNotifications = getNotifications;
module.exports.markNotificationRead = markNotificationRead;
module.exports.deleteNotification = deleteNotification;
module.exports.deleteAllNotifications = deleteAllNotifications;
module.exports.getCurrentUser = getCurrentUser;