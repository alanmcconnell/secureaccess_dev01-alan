const express = require('express');
const router = express.Router();
const { 
  loginUser, 
  logoutUser, 
  passwordResetRequest, 
  passwordReset,
  refreshToken,
  validateToken
} = require('../controllers/authController');
const { authenticateToken, rateLimiter } = require('../middleware/auth');

// Apply stricter rate limiting to auth routes
router.use(rateLimiter(10, 15 * 60 * 1000)); // 10 requests per 15 minutes for auth

// POST /api/auth/login - User login (public)
router.post('/login', loginUser);

// POST /api/auth/logout - User logout (requires authentication)
router.post('/logout', authenticateToken, logoutUser);

// POST /api/auth/refresh - Refresh JWT token (requires valid refresh token)
router.post('/refresh', refreshToken);

// POST /api/auth/validate - Validate current token (requires authentication)
router.post('/validate', authenticateToken, validateToken);

// POST /api/auth/password-reset-request - Request password reset (public)
router.post('/password-reset-request', passwordResetRequest);

// POST /api/auth/password-reset - Reset password using security questions (public)
router.post('/password-reset', passwordReset);

module.exports = router;