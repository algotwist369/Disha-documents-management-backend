const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        unique: true // Only one active session per user
    },
    token: {
        type: String,
        required: true
    },
    socketId: {
        type: String,
        default: null
    },
    deviceInfo: {
        userAgent: String,
        ip: String,
        browser: String,
        os: String,
        device: String
    },
    lastActivity: {
        type: Date,
        default: Date.now
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date,
        required: true
    }
});

// Index for automatic cleanup of expired sessions
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Note: user already has unique index from schema definition
// Note: token index added separately if needed for queries

const Session = mongoose.model('Session', sessionSchema);
module.exports = Session;

