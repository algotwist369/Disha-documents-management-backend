const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        uppercase: true
    },
    description: {
        type: String,
        trim: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
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
// Note: name already has unique index from schema definition
categorySchema.index({ isActive: 1 });
categorySchema.index({ createdAt: -1 }); // For sorting
categorySchema.index({ createdBy: 1 }); // For filtering by creator

const Category = mongoose.model('Category', categorySchema);
module.exports = Category;

