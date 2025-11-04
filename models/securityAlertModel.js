const mongoose = require('mongoose');

const securityAlertSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    alertType: {
        type: String,
        enum: ['failed_login', 'account_locked', 'suspicious_activity'],
        required: true
    },
    severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'medium'
    },
    message: {
        type: String,
        required: true
    },
    attemptsCount: {
        type: Number,
        default: 0
    },
    ip: {
        type: String
    },
    userAgent: {
        type: String
    },
    isRead: {
        type: Boolean,
        default: false
    },
    readBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    readAt: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date,
        default: function() {
            // Auto-delete after 7 days
            return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        }
    }
});

// Indexes for performance
securityAlertSchema.index({ user: 1, createdAt: -1 });
securityAlertSchema.index({ isRead: 1, createdAt: -1 });
securityAlertSchema.index({ severity: 1, isRead: 1 });
securityAlertSchema.index({ alertType: 1, createdAt: -1 });

// TTL index - MongoDB will automatically delete documents after expiresAt
// expireAfterSeconds: 0 means delete immediately when expiresAt is reached
securityAlertSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const SecurityAlert = mongoose.model('SecurityAlert', securityAlertSchema);
module.exports = SecurityAlert;

