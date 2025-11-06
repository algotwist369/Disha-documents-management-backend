const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const Category = require('../models/categoryModel');
const { categoryCache } = require('../utils/cache');

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

        // Check cache first
        const cacheKey = `categories_${query.isActive}`;
        const cachedCategories = categoryCache.get(cacheKey);
        if (cachedCategories) {
            return res.json(cachedCategories);
        }

        const categories = await Category.find(query)
            .select('_id name description isActive')
            .sort({ name: 1 })
            .lean();

        const response = {
            success: true,
            count: categories.length,
            data: categories
        };

        // Cache for 10 minutes
        categoryCache.set(cacheKey, response, 600000);

        res.json(response);
    } catch (error) {
        console.error('getCategories error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

module.exports = router;

