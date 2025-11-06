const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    phone: {
        type: String,
        required: true,
        trim: true,
        unique: true
    },
    email: {
        type: String,
        trim: true,
        lowercase: true,
        default: ''
    },
    password: {
        type: String,
        required: true,
        trim: true
    },
    // brute-force protection
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'super_admin'],
        default: 'user'
    },
    // Notification preferences
    notifications: {
        emailOnView: { type: Boolean, default: false },
        emailOnDownload: { type: Boolean, default: false },
        dashboardOnView: { type: Boolean, default: true },
        dashboardOnDownload: { type: Boolean, default: true }
    }
});

// Indexes for performance
// Note: phone already has unique index from schema definition
userSchema.index({ role: 1 });
userSchema.index({ email: 1 }); // For email lookups
userSchema.index({ createdAt: -1 }); // For sorting by creation date

// Hash password before save
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// Compare password helper
userSchema.methods.comparePassword = async function (candidate) {
    return bcrypt.compare(candidate, this.password);
};

// Check if account is locked
userSchema.virtual('isLocked').get(function () {
    return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Increment failed attempts and return info
userSchema.methods.incLoginAttempts = async function () {
    const LOCK_TIME = 30 * 60 * 1000; // 30 minutes
    const MAX_ATTEMPTS = 3;
    
    if (this.lockUntil && this.lockUntil < Date.now()) {
        // lock expired, reset
        this.failedLoginAttempts = 1;
        this.lockUntil = null;
    } else {
        this.failedLoginAttempts = (this.failedLoginAttempts || 0) + 1;
        if (this.failedLoginAttempts >= MAX_ATTEMPTS && !this.isLocked) {
            this.lockUntil = Date.now() + LOCK_TIME;
        }
    }
    await this.save();
    
    // Return info about attempts
    return {
        attemptsUsed: this.failedLoginAttempts,
        attemptsRemaining: Math.max(0, MAX_ATTEMPTS - this.failedLoginAttempts),
        isLocked: this.failedLoginAttempts >= MAX_ATTEMPTS,
        lockTime: LOCK_TIME / (60 * 1000) // in minutes
    };
};

// Reset login attempts after successful login
userSchema.methods.resetLoginAttempts = async function () {
    this.failedLoginAttempts = 0;
    this.lockUntil = null;
    await this.save();
};

const User = mongoose.model('User', userSchema);
module.exports = User;