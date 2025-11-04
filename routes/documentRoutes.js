const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const { createRateLimiter } = require('../utils/rateLimiter');
const { uploadSingle, multerErrorHandler } = require('../utils/uploadFiles');
const docController = require('../controllers/documentController');

const limiter = createRateLimiter({ windowMs: 60 * 1000, max: 20 });

// Search and stats endpoints (must be before :id routes)
router.get('/search', protect, docController.searchDocuments);
router.get('/stats', protect, docController.getDocumentStats);
router.get('/category/:category', protect, docController.getDocumentsByCategory);

// Document CRUD operations
router.post('/', protect, uploadSingle('file'), multerErrorHandler, docController.createDocument);
router.get('/', protect, docController.getDocuments);
router.get('/:id', protect, docController.getDocumentById);
router.put('/:id', protect, uploadSingle('file'), multerErrorHandler, docController.updateDocument);
router.delete('/:id', protect, docController.deleteDocument);

// File operations (view/download) - HTTPS enforced in production only
router.get('/:id/view', protect, limiter, docController.viewDocumentFile);
router.get('/:id/download', protect, limiter, docController.downloadDocumentFile);

module.exports = router;
