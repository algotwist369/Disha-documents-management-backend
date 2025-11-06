const mongoose = require('mongoose');

const docSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    companyName: {
        type: String,
        required: true,
        trim: true
    },
    fileType: [{
        type: String,
        enum: ['Company ITR', 'Company GST', 'Persional ITR', 'BankStatement', 'Land Doc', 'Shop Doc', 'Flat Doc', 'Hotel Doc', 'Other'],
        required: true
    }],
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category',
        required: false  // Optional to maintain backward compatibility
    },
    filePath: {
        type: String,
        required: true,
        trim: true
    },
    originalName: {
        type: String,
        required: false,
        trim: true
    },
    mimeType: {
        type: String,
        required: false,
        trim: true
    },
    size: {
        type: Number,
        required: false
    },
    isCompressed: {
        type: Boolean,
        default: false
    },
    permissionToView: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }],
    permissionToDownload: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }],
    permissionToDelete: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }],
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Indexes for performance - optimized for common queries
docSchema.index({ user: 1, createdAt: -1 }); // User's documents sorted by date
docSchema.index({ companyName: 1 }); // Company name searches
docSchema.index({ fileType: 1 }); // File type filtering
docSchema.index({ user: 1, fileType: 1 }); // User + file type combo
docSchema.index({ category: 1 }); // Category filtering
docSchema.index({ user: 1, category: 1 }); // User + category combo
docSchema.index({ permissionToView: 1 }); // Permission lookups
docSchema.index({ permissionToDownload: 1 }); // Download permission lookups
docSchema.index({ permissionToDelete: 1 }); // Delete permission lookups
docSchema.index({ createdAt: -1 }); // Global date sorting
docSchema.index({ user: 1, permissionToView: 1 }); // Combined user + view permission
docSchema.index({ user: 1, permissionToDownload: 1 }); // Combined user + download permission
// Text index for search across company name and original file name
docSchema.index({ companyName: 'text', originalName: 'text' });
// Compound index for common query patterns
docSchema.index({ user: 1, createdAt: -1, fileType: 1 }); // User docs by date and type

const Doc = mongoose.model('Document', docSchema);

module.exports = Doc;