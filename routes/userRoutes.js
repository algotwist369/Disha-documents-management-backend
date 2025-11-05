const express = require('express');
const router = express.Router();
const { 
    registerUser, 
    loginUser,
    logoutUser,
    deleteUser,
    approveLoginRequest,
    rejectLoginRequest,
    checkLoginRequestStatus,
    listUsersBasic,
    updateNotificationPreferences,
    getNotifications,
    markNotificationRead,
    deleteNotification,
    deleteAllNotifications,
    getCurrentUser
} = require('../controllers/userController');
const { createRateLimiter } = require('../utils/rateLimiter');
const { protect, requireMinRole } = require('../middleware/authMiddleware');

const loginLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 10 });
const registerLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 5 });

router.post('/register', registerLimiter, registerUser);
router.post('/login', loginLimiter, loginUser);
router.post('/logout', protect, logoutUser); // Protected logout route
router.delete('/:userId', protect, requireMinRole('admin'), deleteUser);

// Basic users list for permissions (auth required)
router.get('/', protect, listUsersBasic);

// Login approval routes
router.post('/login-requests/:requestId/approve', protect, approveLoginRequest);
router.post('/login-requests/:requestId/reject', protect, rejectLoginRequest);
router.get('/login-requests/:requestId/status', checkLoginRequestStatus); // No auth needed for new device to check

// Notification routes
router.put('/notifications/preferences', protect, updateNotificationPreferences);
router.get('/notifications', protect, getNotifications);
router.put('/notifications/:notificationId/read', protect, markNotificationRead);
router.delete('/notifications/:notificationId', protect, deleteNotification);
router.delete('/notifications', protect, deleteAllNotifications);

// User profile routes
router.get('/me', protect, getCurrentUser);

module.exports = router;
