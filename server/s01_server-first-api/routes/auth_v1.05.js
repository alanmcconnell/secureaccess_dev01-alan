const express = require('express');
const router = express.Router();
const {
  login,
  verifyTokenEndpoint,
  passwordResetRequest,
  passwordReset,
  logout,
  refreshToken
} = require('../controllers/authController');
const { 
  authenticateToken, 
  authRateLimit, 
  strictAuthRateLimit, 
  passwordResetRateLimit 
} = require('../middleware/auth');

// Apply general rate limiting to auth routes
router.use(authRateLimit);

// POST /api/auth/login - User login (stricter rate limit)
router.post('/login', strictAuthRateLimit, login);

// GET /api/auth/verify - Verify JWT token
router.get('/verify', authenticateToken, verifyTokenEndpoint);

// POST /api/auth/password-reset-request - Request password reset (strict rate limit)
router.post('/password-reset-request', passwordResetRateLimit, passwordResetRequest);

// POST /api/auth/password-reset - Reset password with security questions (strict rate limit)
router.post('/password-reset', passwordResetRateLimit, passwordReset);

// POST /api/auth/logout - Logout user
router.post('/logout', authenticateToken, logout);

// POST /api/auth/refresh - Refresh JWT token
router.post('/refresh', authenticateToken, refreshToken);

module.exports = router;