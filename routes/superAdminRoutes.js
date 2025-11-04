const express = require('express');
const router = express.Router();
const { protect, requireSuperAdmin } = require('../middleware/authMiddleware');
const superAdminController = require('../controllers/superAdminController');

// All routes require super admin access
router.use(protect);
router.use(requireSuperAdmin);

// ==================== USER MANAGEMENT ====================
router.get('/users', superAdminController.getAllUsers);
router.get('/users/:userId', superAdminController.getUserById);
router.put('/users/:userId', superAdminController.updateUser);
router.put('/users/:userId/password', superAdminController.updateUserPassword);
router.post('/users/:userId/reset-account', superAdminController.resetUserAccount);
router.post('/users/:userId/lock-account', superAdminController.lockUserAccount);
router.delete('/users/:userId', superAdminController.deleteUserBySuperAdmin);

// ==================== CATEGORY MANAGEMENT ====================
router.get('/categories', superAdminController.getAllCategories);
router.post('/categories', superAdminController.createCategory);
router.put('/categories/:categoryId', superAdminController.updateCategory);
router.delete('/categories/:categoryId', superAdminController.deleteCategory);

// ==================== SYSTEM MONITORING ====================
router.get('/stats', superAdminController.getSystemStats);
router.get('/documents', superAdminController.getAllDocuments);
router.get('/audit-logs', superAdminController.getAuditLogs);

// ==================== SECURITY ALERTS ====================
router.get('/security-alerts', superAdminController.getSecurityAlerts);
router.put('/security-alerts/:alertId/read', superAdminController.markAlertAsRead);
router.put('/security-alerts/read-all', superAdminController.markAllAlertsAsRead);
router.delete('/security-alerts/:alertId', superAdminController.deleteSecurityAlert);

// ==================== USER SECURITY SETTINGS ====================
router.get('/users/:userId/security-settings', superAdminController.getUserSecuritySettings);
router.put('/users/:userId/security-settings', superAdminController.updateUserSecuritySettings);
router.post('/users/:userId/ip-whitelist', superAdminController.addIpToWhitelist);
router.delete('/users/:userId/ip-whitelist/:ip', superAdminController.removeIpFromWhitelist);
router.get('/users/:userId/sessions', superAdminController.getUserActiveSessions);
router.delete('/sessions/:sessionId', superAdminController.terminateUserSession);
router.delete('/users/:userId/sessions', superAdminController.terminateAllUserSessions);

module.exports = router;

