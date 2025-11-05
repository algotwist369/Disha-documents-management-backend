const User = require('../models/userModel');
const Category = require('../models/categoryModel');
const Doc = require('../models/docModel');
const AuditLog = require('../models/auditLog');
const SecurityAlert = require('../models/securityAlertModel');
const { getClientIP } = require('../utils/ipExtractor');
const UserSecuritySettings = require('../models/userSecuritySettings');
const Session = require('../models/sessionModel');
const BlacklistedToken = require('../models/blacklistedToken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// ==================== USER MANAGEMENT ====================

// Get all users with pagination and filters
const getAllUsers = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 20, 100);
        const skip = (page - 1) * limit;

        const query = {};
        
        // Filter by role
        if (req.query.role) {
            query.role = req.query.role;
        }

        // Search by name or phone
        if (req.query.search) {
            query.$or = [
                { name: { $regex: req.query.search, $options: 'i' } },
                { phone: { $regex: req.query.search, $options: 'i' } }
            ];
        }

        const [users, total] = await Promise.all([
            User.find(query)
                .select('-password')
                .sort({ createdAt: -1 })
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
        console.error('getAllUsers error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Get single user by ID
const getUserById = async (req, res) => {
    try {
        const user = await User.findById(req.params.userId).select('-password');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Get user's document count
        const documentCount = await Doc.countDocuments({ user: user._id });

        res.json({
            success: true,
            data: { ...user.toObject(), documentCount }
        });
    } catch (error) {
        console.error('getUserById error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Update user details
const updateUser = async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, phone, role } = req.body;

        // Validate userId
        if (!userId.match(/^[0-9a-fA-F]{24}$/)) {
            return res.status(400).json({ success: false, message: 'Invalid user ID' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Prevent changing super_admin role unless requester is super_admin
        if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
            return res.status(403).json({ success: false, message: 'Cannot modify super admin' });
        }

        // Update fields
        if (name) user.name = name;
        if (phone) {
            // Check if phone already exists for another user
            const existingUser = await User.findOne({ phone, _id: { $ne: userId } });
            if (existingUser) {
                return res.status(400).json({ success: false, message: 'Phone number already in use' });
            }
            user.phone = phone;
        }
        if (role && ['user', 'admin', 'super_admin'].includes(role)) {
            user.role = role;
        }

        user.updatedAt = Date.now();
        await user.save();

        res.json({
            success: true,
            message: 'User updated successfully',
            data: {
                id: user._id,
                name: user.name,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (error) {
        console.error('updateUser error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Update user password
const updateUserPassword = async (req, res) => {
    try {
        const { userId } = req.params;
        const { newPassword } = req.body;

        // Validate
        if (!newPassword || newPassword.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 8 characters long' 
            });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Prevent changing super_admin password unless requester is super_admin
        if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
            return res.status(403).json({ success: false, message: 'Cannot modify super admin password' });
        }

        // Update password (will be hashed by pre-save hook)
        user.password = newPassword;
        user.updatedAt = Date.now();
        await user.save();

        res.json({
            success: true,
            message: 'Password updated successfully'
        });
    } catch (error) {
        console.error('updateUserPassword error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Reset user account (unlock and clear failed attempts)
const resetUserAccount = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Prevent resetting super_admin account unless requester is super_admin
        if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
            return res.status(403).json({ success: false, message: 'Cannot modify super admin account' });
        }

        // Reset failed login attempts and unlock account
        await user.resetLoginAttempts();

        res.json({
            success: true,
            message: 'User account unlocked and login attempts reset successfully'
        });
    } catch (error) {
        console.error('resetUserAccount error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Lock user account manually (super admin can lock any account)
const lockUserAccount = async (req, res) => {
    try {
        const { userId } = req.params;
        const { lockDuration } = req.body; // Duration in minutes, default 30

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Prevent locking super_admin account unless requester is super_admin
        if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
            return res.status(403).json({ success: false, message: 'Cannot lock super admin account' });
        }

        // Prevent locking own account
        if (userId === req.user._id.toString()) {
            return res.status(400).json({ success: false, message: 'Cannot lock your own account' });
        }

        // Lock the account
        const duration = lockDuration || 30; // Default 30 minutes
        const LOCK_TIME = duration * 60 * 1000;
        user.lockUntil = Date.now() + LOCK_TIME;
        user.failedLoginAttempts = 5; // Set to max attempts to indicate manual lock
        user.updatedAt = Date.now();
        await user.save();

        // Create security alert for account lock (manual)
        try {
            const alert = await SecurityAlert.create({
                user: user._id,
                alertType: 'account_locked',
                severity: 'critical',
                message: `Account locked by administrator for ${duration} minute(s)`,
                ip: getClientIP(req),
                userAgent: req.headers['user-agent']
            });

            // Emit real-time alert to super admin room
            if (global.io) {
                global.io.to('super-admin-room').emit('new-security-alert', {
                    alert: {
                        ...alert.toObject(),
                        user: { _id: user._id, name: user.name, phone: user.phone, role: user.role }
                    }
                });
            }

            // Send email notification to admin (fallback to configured address)
            try {
                const sendMail = require('../utils/sendMail');
                const adminEmail = process.env.ADMIN_EMAIL || 'adoc4421@gmail.com';
                await sendMail({
                    to: adminEmail,
                    subject: `🔒 Account Locked by Admin - ${user.name}`,
                    text: `User ${user.name} (${user.phone}) was locked by an administrator for ${duration} minute(s).\n\nIP: ${getClientIP(req)}\nUser Agent: ${req.headers['user-agent']}\nTime: ${new Date().toISOString()}`
                });
            } catch (err) {
                console.error('Error sending lock notification email:', err);
            }
        } catch (e) {
            console.error('Error creating security alert for manual lock:', e);
        }

        // Terminate and blacklist all active sessions for this user so they are logged out immediately
        try {
            const sessions = await Session.find({ user: user._id });
            for (const session of sessions) {
                // Notify via Socket.IO
                if (global.io && session.socketId) {
                    global.io.to(session.socketId).emit('force-logout', {
                        message: 'Your account has been locked by administrator. You have been logged out.',
                        reason: 'account_locked'
                    });

                    const socket = global.io.sockets.sockets.get(session.socketId);
                    if (socket) socket.disconnect(true);
                }

                // Blacklist token if present
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
                    // Non-fatal
                    console.error('Error blacklisting token for locked account:', be);
                }
            }

            // Delete sessions
            await Session.deleteMany({ user: user._id });
        } catch (e) {
            console.error('Error terminating sessions for locked user:', e);
        }

        res.json({
            success: true,
            message: `User account locked for ${duration} minutes successfully`,
            lockDuration: duration
        });
    } catch (error) {
        console.error('lockUserAccount error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Delete user
const deleteUserBySuperAdmin = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Prevent deleting super_admin
        if (user.role === 'super_admin') {
            return res.status(403).json({ success: false, message: 'Cannot delete super admin' });
        }

        // Prevent self-deletion
        if (userId === req.user._id.toString()) {
            return res.status(400).json({ success: false, message: 'Cannot delete your own account' });
        }

        await user.deleteOne();

        res.json({
            success: true,
            message: 'User deleted successfully'
        });
    } catch (error) {
        console.error('deleteUserBySuperAdmin error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// ==================== CATEGORY MANAGEMENT ====================

// Get all categories
const getAllCategories = async (req, res) => {
    try {
        const query = {};
        
        // Filter by active status
        if (req.query.isActive !== undefined) {
            query.isActive = req.query.isActive === 'true';
        }

        const categories = await Category.find(query)
            .populate('createdBy', 'name')
            .sort({ name: 1 })
            .lean();

        res.json({
            success: true,
            count: categories.length,
            data: categories
        });
    } catch (error) {
        console.error('getAllCategories error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Create category
const createCategory = async (req, res) => {
    try {
        const { name, description, isActive } = req.body;

        // Validate
        if (!name || name.trim().length === 0) {
            return res.status(400).json({ success: false, message: 'Category name is required' });
        }

        // Check if category already exists
        const existingCategory = await Category.findOne({ 
            name: name.trim().toUpperCase() 
        });
        if (existingCategory) {
            return res.status(400).json({ success: false, message: 'Category already exists' });
        }

        // Create category
        const category = new Category({
            name: name.trim().toUpperCase(),
            description: description?.trim() || '',
            isActive: isActive !== undefined ? isActive : true,
            createdBy: req.user._id
        });

        await category.save();

        res.status(201).json({
            success: true,
            message: 'Category created successfully',
            data: category
        });
    } catch (error) {
        console.error('createCategory error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Update category
const updateCategory = async (req, res) => {
    try {
        const { categoryId } = req.params;
        const { name, description, isActive } = req.body;

        const category = await Category.findById(categoryId);
        if (!category) {
            return res.status(404).json({ success: false, message: 'Category not found' });
        }

        // Update fields
        if (name) {
            const upperName = name.trim().toUpperCase();
            // Check if new name already exists
            const existing = await Category.findOne({ 
                name: upperName,
                _id: { $ne: categoryId }
            });
            if (existing) {
                return res.status(400).json({ success: false, message: 'Category name already exists' });
            }
            category.name = upperName;
        }
        
        if (description !== undefined) category.description = description.trim();
        if (isActive !== undefined) category.isActive = isActive;
        
        category.updatedAt = Date.now();
        await category.save();

        res.json({
            success: true,
            message: 'Category updated successfully',
            data: category
        });
    } catch (error) {
        console.error('updateCategory error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Delete category
const deleteCategory = async (req, res) => {
    try {
        const { categoryId } = req.params;

        const category = await Category.findById(categoryId);
        if (!category) {
            return res.status(404).json({ success: false, message: 'Category not found' });
        }

        // Check if category is in use
        const documentsUsingCategory = await Doc.countDocuments({ 
            fileType: category.name 
        });

        if (documentsUsingCategory > 0) {
            return res.status(400).json({ 
                success: false, 
                message: `Cannot delete category. ${documentsUsingCategory} documents are using it.`,
                documentsCount: documentsUsingCategory
            });
        }

        await category.deleteOne();

        res.json({
            success: true,
            message: 'Category deleted successfully'
        });
    } catch (error) {
        console.error('deleteCategory error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// ==================== SYSTEM STATISTICS ====================

// Get comprehensive system stats
const getSystemStats = async (req, res) => {
    try {
        const [
            totalUsers,
            totalAdmins,
            totalSuperAdmins,
            totalDocuments,
            totalCategories,
            recentUsers,
            recentDocuments,
            documentsByCategory,
            auditLogCount
        ] = await Promise.all([
            User.countDocuments({ role: 'user' }),
            User.countDocuments({ role: 'admin' }),
            User.countDocuments({ role: 'super_admin' }),
            Doc.countDocuments(),
            Category.countDocuments({ isActive: true }),
            User.countDocuments({ 
                createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } 
            }),
            Doc.countDocuments({ 
                createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } 
            }),
            Doc.aggregate([
                { $unwind: '$fileType' },
                { $group: { _id: '$fileType', count: { $sum: 1 } } },
                { $sort: { count: -1 } },
                { $limit: 10 }
            ]),
            AuditLog.countDocuments()
        ]);

        res.json({
            success: true,
            data: {
                users: {
                    total: totalUsers + totalAdmins + totalSuperAdmins,
                    regular: totalUsers,
                    admins: totalAdmins,
                    superAdmins: totalSuperAdmins,
                    recentlyJoined: recentUsers
                },
                documents: {
                    total: totalDocuments,
                    recentlyUploaded: recentDocuments,
                    byCategory: documentsByCategory.map(cat => ({
                        category: cat._id,
                        count: cat.count
                    }))
                },
                categories: {
                    total: totalCategories
                },
                auditLogs: {
                    total: auditLogCount
                }
            }
        });
    } catch (error) {
        console.error('getSystemStats error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Get all documents (for super admin)
const getAllDocuments = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 20, 100);
        const skip = (page - 1) * limit;

        const query = {};

        // Filter by user
        if (req.query.userId) {
            query.user = req.query.userId;
        }

        // Filter by category (ObjectId)
        if (req.query.category) {
            query.category = req.query.category;
        }
        // Filter by fileType (string or comma-separated)
        if (req.query.fileType) {
            const fileTypes = Array.isArray(req.query.fileType)
                ? req.query.fileType
                : req.query.fileType.split(',').map(t => t.trim());
            query.fileType = { $in: fileTypes };
        }

        // Search
        if (req.query.search) {
            query.$or = [
                { companyName: { $regex: req.query.search, $options: 'i' } },
                { originalName: { $regex: req.query.search, $options: 'i' } }
            ];
        }

        const [documents, total] = await Promise.all([
            Doc.find(query)
                .populate('user', 'name phone role')
                .populate('category', 'name description')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            Doc.countDocuments(query)
        ]);

        res.json({
            success: true,
            count: documents.length,
            total,
            page,
            pages: Math.ceil(total / limit),
            data: documents
        });
    } catch (error) {
        console.error('getAllDocuments error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Get audit logs
const getAuditLogs = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 50, 200);
        const skip = (page - 1) * limit;

        const query = {};

        // Filter by user
        if (req.query.userId) {
            query.user = req.query.userId;
        }

        // Filter by action
        if (req.query.action) {
            query.action = req.query.action;
        }

        // Date range
        if (req.query.dateFrom || req.query.dateTo) {
            query.createdAt = {};
            if (req.query.dateFrom) {
                query.createdAt.$gte = new Date(req.query.dateFrom);
            }
            if (req.query.dateTo) {
                query.createdAt.$lte = new Date(req.query.dateTo);
            }
        }

        const [logs, total] = await Promise.all([
            AuditLog.find(query)
                .populate('user', 'name phone role')
                .populate('document', 'companyName originalName')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            AuditLog.countDocuments(query)
        ]);

        res.json({
            success: true,
            count: logs.length,
            total,
            page,
            pages: Math.ceil(total / limit),
            data: logs
        });
    } catch (error) {
        console.error('getAuditLogs error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// ==================== SECURITY ALERTS ====================

// Get security alerts with filters
const getSecurityAlerts = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 20, 100);
        const skip = (page - 1) * limit;

        const query = {};

        // Filter by severity
        if (req.query.severity) {
            query.severity = req.query.severity;
        }

        // Filter by alert type
        if (req.query.alertType) {
            query.alertType = req.query.alertType;
        }

        // Filter by read status
        if (req.query.isRead !== undefined) {
            query.isRead = req.query.isRead === 'true';
        }

        // Date range
        if (req.query.dateFrom || req.query.dateTo) {
            query.createdAt = {};
            if (req.query.dateFrom) {
                query.createdAt.$gte = new Date(req.query.dateFrom);
            }
            if (req.query.dateTo) {
                query.createdAt.$lte = new Date(req.query.dateTo);
            }
        }

        const [alerts, total, unreadCount] = await Promise.all([
            SecurityAlert.find(query)
                .populate('user', 'name phone role')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean(),
            SecurityAlert.countDocuments(query),
            SecurityAlert.countDocuments({ isRead: false })
        ]);

        res.json({
            success: true,
            count: alerts.length,
            total,
            unreadCount,
            page,
            pages: Math.ceil(total / limit),
            data: alerts
        });
    } catch (error) {
        console.error('getSecurityAlerts error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Mark security alert as read
const markAlertAsRead = async (req, res) => {
    try {
        const { alertId } = req.params;

        const alert = await SecurityAlert.findById(alertId);
        if (!alert) {
            return res.status(404).json({ success: false, message: 'Alert not found' });
        }

        alert.isRead = true;
        alert.readBy = req.user._id;
        alert.readAt = Date.now();
        await alert.save();

        res.json({
            success: true,
            message: 'Alert marked as read'
        });
    } catch (error) {
        console.error('markAlertAsRead error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Mark all alerts as read
const markAllAlertsAsRead = async (req, res) => {
    try {
        await SecurityAlert.updateMany(
            { isRead: false },
            { 
                isRead: true, 
                readBy: req.user._id, 
                readAt: Date.now() 
            }
        );

        res.json({
            success: true,
            message: 'All alerts marked as read'
        });
    } catch (error) {
        console.error('markAllAlertsAsRead error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Delete security alert
const deleteSecurityAlert = async (req, res) => {
    try {
        const { alertId } = req.params;

        const alert = await SecurityAlert.findByIdAndDelete(alertId);
        if (!alert) {
            return res.status(404).json({ success: false, message: 'Alert not found' });
        }

        res.json({
            success: true,
            message: 'Alert deleted successfully'
        });
    } catch (error) {
        console.error('deleteSecurityAlert error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// ==================== USER SECURITY SETTINGS ====================

// Get user security settings
const getUserSecuritySettings = async (req, res) => {
    try {
        const { userId } = req.params;
        
        let settings = await UserSecuritySettings.findOne({ user: userId })
            .populate('createdBy', 'name phone')
            .populate('lastModifiedBy', 'name phone');
        
        // If no settings exist, return default settings
        if (!settings) {
            return res.json({
                success: true,
                data: {
                    user: userId,
                    maxDevices: 1,
                    allowMultipleDevices: false,
                    ipWhitelist: [],
                    enforceIpWhitelist: false,
                    allowedLoginHours: { enabled: false, startHour: 0, endHour: 23 },
                    customMaxLoginAttempts: { enabled: false, maxAttempts: 3 },
                    customSessionTimeout: { enabled: false, timeoutMinutes: 30 },
                    accountRestrictions: {
                        canUploadDocuments: true,
                        canDeleteDocuments: true,
                        canDownloadDocuments: true,
                        canViewOthersDocuments: true
                    }
                },
                isDefault: true
            });
        }
        
        res.json({ success: true, data: settings });
    } catch (error) {
        console.error('getUserSecuritySettings error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Update user security settings
const updateUserSecuritySettings = async (req, res) => {
    try {
        const { userId } = req.params;
        const updates = req.body;
        
        // Validate user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        // Find or create security settings
        let settings = await UserSecuritySettings.findOne({ user: userId });
        
        if (!settings) {
            settings = new UserSecuritySettings({
                user: userId,
                createdBy: req.user._id
            });
        }
        
        // Update fields
        if (updates.maxDevices !== undefined) {
            settings.maxDevices = Math.max(1, Math.min(10, updates.maxDevices));
        }
        if (updates.allowMultipleDevices !== undefined) {
            settings.allowMultipleDevices = updates.allowMultipleDevices;
        }
        if (updates.enforceIpWhitelist !== undefined) {
            settings.enforceIpWhitelist = updates.enforceIpWhitelist;
        }
        if (updates.ipWhitelist !== undefined) {
            settings.ipWhitelist = updates.ipWhitelist.map(item => ({
                ip: item.ip,
                description: item.description || '',
                addedBy: req.user._id
            }));
        }
        if (updates.allowedLoginHours !== undefined) {
            settings.allowedLoginHours = updates.allowedLoginHours;
        }
        if (updates.customMaxLoginAttempts !== undefined) {
            settings.customMaxLoginAttempts = updates.customMaxLoginAttempts;
        }
        if (updates.customSessionTimeout !== undefined) {
            settings.customSessionTimeout = updates.customSessionTimeout;
        }
        if (updates.accountRestrictions !== undefined) {
            settings.accountRestrictions = {
                ...settings.accountRestrictions,
                ...updates.accountRestrictions
            };
        }
        if (updates.notifyOnLogin !== undefined) {
            settings.notifyOnLogin = updates.notifyOnLogin;
        }
        if (updates.notes !== undefined) {
            settings.notes = updates.notes;
        }
        
        settings.lastModifiedBy = req.user._id;
        await settings.save();
        
        res.json({
            success: true,
            message: 'Security settings updated successfully',
            data: settings
        });
    } catch (error) {
        console.error('updateUserSecuritySettings error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Add IP to whitelist
const addIpToWhitelist = async (req, res) => {
    try {
        const { userId } = req.params;
        const { ip, description } = req.body;
        
        if (!ip) {
            return res.status(400).json({ success: false, message: 'IP address is required' });
        }
        
        // Normalize and validate IP
        const normalizedIP = ip.trim().replace(/\s+/g, '');
        
        // Validate IP format (basic IPv4)
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(normalizedIP)) {
            return res.status(400).json({ success: false, message: 'Invalid IP address format. Please provide a valid IPv4 address (e.g., 192.168.1.100)' });
        }
        
        let settings = await UserSecuritySettings.findOne({ user: userId });
        
        if (!settings) {
            settings = new UserSecuritySettings({
                user: userId,
                createdBy: req.user._id
            });
        }
        
        // Check if IP already exists (normalize both for comparison)
        const ipExists = settings.ipWhitelist.some(item => {
            const existingIP = item.ip ? item.ip.trim().replace(/\s+/g, '') : '';
            return existingIP.toLowerCase() === normalizedIP.toLowerCase();
        });
        if (ipExists) {
            return res.status(400).json({ success: false, message: 'IP address already in whitelist' });
        }
        
        settings.ipWhitelist.push({
            ip: normalizedIP,
            description: (description || '').trim(),
            addedBy: req.user._id
        });
        
        settings.lastModifiedBy = req.user._id;
        await settings.save();
        
        res.json({
            success: true,
            message: 'IP address added to whitelist',
            data: settings
        });
    } catch (error) {
        console.error('addIpToWhitelist error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Remove IP from whitelist
const removeIpFromWhitelist = async (req, res) => {
    try {
        const { userId, ip } = req.params;
        
        const settings = await UserSecuritySettings.findOne({ user: userId });
        if (!settings) {
            return res.status(404).json({ success: false, message: 'Security settings not found' });
        }
        
        const initialLength = settings.ipWhitelist.length;
        settings.ipWhitelist = settings.ipWhitelist.filter(item => item.ip !== ip);
        
        if (settings.ipWhitelist.length === initialLength) {
            return res.status(404).json({ success: false, message: 'IP address not found in whitelist' });
        }
        
        settings.lastModifiedBy = req.user._id;
        await settings.save();
        
        res.json({
            success: true,
            message: 'IP address removed from whitelist',
            data: settings
        });
    } catch (error) {
        console.error('removeIpFromWhitelist error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Get user active sessions
const getUserActiveSessions = async (req, res) => {
    try {
        const { userId } = req.params;
        
        const sessions = await Session.find({ user: userId }).sort({ createdAt: -1 });
        
        res.json({
            success: true,
            count: sessions.length,
            data: sessions
        });
    } catch (error) {
        console.error('getUserActiveSessions error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Terminate user session
const terminateUserSession = async (req, res) => {
    try {
        const { sessionId } = req.params;
        
        const session = await Session.findById(sessionId);
        if (!session) {
            return res.status(404).json({ success: false, message: 'Session not found' });
        }
        
        // Disconnect via Socket.IO
        if (global.io && session.socketId) {
            global.io.to(session.socketId).emit('force-logout', {
                message: 'Your session has been terminated by administrator.',
                reason: 'admin_action'
            });
            
            const socket = global.io.sockets.sockets.get(session.socketId);
            if (socket) {
                socket.disconnect(true);
            }
        }
        
        // Delete session
        await Session.findByIdAndDelete(sessionId);
        
        res.json({
            success: true,
            message: 'Session terminated successfully'
        });
    } catch (error) {
        console.error('terminateUserSession error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Terminate all user sessions
const terminateAllUserSessions = async (req, res) => {
    try {
        const { userId } = req.params;
        
        const sessions = await Session.find({ user: userId });
        
        // Disconnect all sessions via Socket.IO
        for (const session of sessions) {
            if (global.io && session.socketId) {
                global.io.to(session.socketId).emit('force-logout', {
                    message: 'All your sessions have been terminated by administrator.',
                    reason: 'admin_action'
                });
                
                const socket = global.io.sockets.sockets.get(session.socketId);
                if (socket) {
                    socket.disconnect(true);
                }
            }
        }
        
        // Delete all sessions
        await Session.deleteMany({ user: userId });
        
        res.json({
            success: true,
            message: `${sessions.length} session(s) terminated successfully`
        });
    } catch (error) {
        console.error('terminateAllUserSessions error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

module.exports = {
    // User management
    getAllUsers,
    getUserById,
    updateUser,
    updateUserPassword,
    resetUserAccount,
    lockUserAccount,
    deleteUserBySuperAdmin,
    
    // Category management
    getAllCategories,
    createCategory,
    updateCategory,
    deleteCategory,
    
    // System stats and monitoring
    getSystemStats,
    getAllDocuments,
    getAuditLogs,
    
    // Security alerts
    getSecurityAlerts,
    markAlertAsRead,
    markAllAlertsAsRead,
    deleteSecurityAlert,
    
    // User security settings
    getUserSecuritySettings,
    updateUserSecuritySettings,
    addIpToWhitelist,
    removeIpFromWhitelist,
    getUserActiveSessions,
    terminateUserSession,
    terminateAllUserSessions
};

