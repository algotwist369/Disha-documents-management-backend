const mongoose = require('mongoose');

const pendingLoginRequestSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    token: {
        type: String,
        required: true
    },
    deviceInfo: {
        userAgent: String,
        ip: String,
        browser: String,
        os: String,
        device: String
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    expiresAt: {
        type: Date,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Auto-expire after expiresAt
pendingLoginRequestSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Index for performance
pendingLoginRequestSchema.index({ user: 1, status: 1 });

const PendingLoginRequest = mongoose.model('PendingLoginRequest', pendingLoginRequestSchema);
module.exports = PendingLoginRequest;

