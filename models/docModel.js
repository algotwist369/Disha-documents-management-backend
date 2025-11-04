const mongoose = require('mongoose');

const docSchema = new mongoose.Schema({
    user:{
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
        enum: ['ITR', 'GST', 'BankStatement', 'Other'],
        required: true
    }],
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
    createdAt: {
        type: Date,
        default: Date.now
    },
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
// Text index for search across company name and original file name
docSchema.index({ companyName: 'text', originalName: 'text' });

const Doc = mongoose.model('Document', docSchema);

module.exports = Doc;