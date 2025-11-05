const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const Category = require('../models/categoryModel');

// Get active categories (accessible to all authenticated users)
router.get('/', protect, async (req, res) => {
    try {
        // Allow filtering by isActive if provided, otherwise default to active only
        const query = {};
        if (req.query.isActive !== undefined) {
            query.isActive = req.query.isActive === 'true';
        } else {
            query.isActive = true; // Default to active categories
        }

        const categories = await Category.find(query)
            .select('_id name description isActive')
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

