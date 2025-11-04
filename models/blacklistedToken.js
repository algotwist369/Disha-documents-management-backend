const mongoose = require('mongoose');

const blacklistedTokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    reason: {
        type: String,
        enum: ['logout', 'force_logout', 'password_change', 'account_locked', 'security_breach'],
        default: 'logout'
    },
    blacklistedAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date,
        required: true,
        default: function() {
            // Auto-delete after 7 days (same as token expiry)
            return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        }
    }
});

// TTL index - Auto-delete blacklisted tokens after expiry
blacklistedTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Note: token already has unique index from schema definition
// Additional index for user lookups
blacklistedTokenSchema.index({ user: 1 });

const BlacklistedToken = mongoose.model('BlacklistedToken', blacklistedTokenSchema);
module.exports = BlacklistedToken;

