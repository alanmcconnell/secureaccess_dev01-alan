const express = require('express');
const router = express.Router();
const { 
  loginUser, 
  logoutUser, 
  passwordResetRequest, 
  passwordReset 
} = require('../controllers/authController');
const { rateLimiter } = require('../middleware/auth');

// Apply rate limiting to auth routes
router.use(rateLimiter(10, 15 * 60 * 1000)); // 10 requests per 15 minutes for auth

// POST /api/auth/login - User login
router.post('/login', loginUser);

// POST /api/auth/logout - User logout
router.post('/logout', logoutUser);

// POST /api/auth/password-reset-request - Request password reset
router.post('/password-reset-request', passwordResetRequest);

// POST /api/auth/password-reset - Reset password
router.post('/password-reset', passwordReset);

module.exports = router;