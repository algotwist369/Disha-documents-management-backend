const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const Category = require('../models/categoryModel');

// Get active categories (accessible to all authenticated users)
router.get('/', protect, async (req, res) => {
    try {
        const categories = await Category.find({ isActive: true })
            .select('name description')
            .sort({ name: 1 })
            .lean();

        res.json({
            success: true,
            count: categories.length,
            data: categories
        });
    } catch (error) {
        console.error('getCategories error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

module.exports = router;

