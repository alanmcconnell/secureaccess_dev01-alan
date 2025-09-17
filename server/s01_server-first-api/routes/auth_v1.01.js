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

// POST /api/auth/login - User login
router.post('/login', login);

// GET /api/auth/verify - Verify JWT token
router.get('/verify', verifyTokenEndpoint);

// POST /api/auth/password-reset-request - Request password reset (get security questions)
router.post('/password-reset-request', passwordResetRequest);

// POST /api/auth/password-reset - Reset password with security questions
router.post('/password-reset', passwordReset);

// POST /api/auth/logout - Logout user
router.post('/logout', logout);

// POST /api/auth/refresh - Refresh JWT token
router.post('/refresh', refreshToken);

module.exports = router;