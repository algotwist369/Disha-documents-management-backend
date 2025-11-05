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

// Indexes for performance
docSchema.index({ user: 1, createdAt: -1 });
docSchema.index({ companyName: 1 });
docSchema.index({ fileType: 1 });
docSchema.index({ user: 1, fileType: 1 });
docSchema.index({ category: 1 });
docSchema.index({ user: 1, category: 1 });
docSchema.index({ permissionToView: 1 });
// Text index for search across company name and original file name
docSchema.index({ companyName: 'text', originalName: 'text' });

const Doc = mongoose.model('Document', docSchema);

module.exports = Doc;