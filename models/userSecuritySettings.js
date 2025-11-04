const mongoose = require('mongoose');

const userSecuritySettingsSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        unique: true // One security setting per user
    },
    
    // Device Management
    maxDevices: {
        type: Number,
        default: 1, // By default, only 1 device allowed
        min: 1,
        max: 10
    },
    allowMultipleDevices: {
        type: Boolean,
        default: false
    },
    
    // IP Whitelist
    ipWhitelist: [{
        ip: String,
        description: String,
        addedAt: { type: Date, default: Date.now },
        addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
    }],
    enforceIpWhitelist: {
        type: Boolean,
        default: false
    },
    
    // Time-based restrictions
    allowedLoginHours: {
        enabled: { type: Boolean, default: false },
        startHour: { type: Number, default: 0, min: 0, max: 23 }, // 0-23 (24-hour format)
        endHour: { type: Number, default: 23, min: 0, max: 23 }
    },
    
    // Login attempt restrictions
    customMaxLoginAttempts: {
        enabled: { type: Boolean, default: false },
        maxAttempts: { type: Number, default: 3, min: 1, max: 10 }
    },
    
    // Session timeout
    customSessionTimeout: {
        enabled: { type: Boolean, default: false },
        timeoutMinutes: { type: Number, default: 30, min: 5, max: 1440 } // 5 min to 24 hours
    },
    
    // Two-factor authentication (placeholder for future)
    twoFactorAuth: {
        enabled: { type: Boolean, default: false },
        method: { type: String, enum: ['email', 'sms', 'app'], default: 'email' }
    },
    
    // Account restrictions
    accountRestrictions: {
        canUploadDocuments: { type: Boolean, default: true },
        canDeleteDocuments: { type: Boolean, default: true },
        canDownloadDocuments: { type: Boolean, default: true },
        canViewOthersDocuments: { type: Boolean, default: true }
    },
    
    // Geo-location restrictions (placeholder for future)
    geoRestrictions: {
        enabled: { type: Boolean, default: false },
        allowedCountries: [String],
        blockedCountries: [String]
    },
    
    // Notification preferences
    notifyOnLogin: {
        enabled: { type: Boolean, default: false },
        methods: [{ type: String, enum: ['email', 'sms'] }]
    },
    
    // Metadata
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    lastModifiedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    notes: {
        type: String,
        maxlength: 500
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Note: user already has unique index from schema definition

// Update timestamp on save
userSecuritySettingsSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

const UserSecuritySettings = mongoose.model('UserSecuritySettings', userSecuritySettingsSchema);
module.exports = UserSecuritySettings;

