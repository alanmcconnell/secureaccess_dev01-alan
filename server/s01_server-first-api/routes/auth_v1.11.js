const express = require('express');
const router = express.Router();

// Test importing the auth controller
try {
  const authController = require('../controllers/authController');
  console.log('✅ Auth controller imported successfully');
  console.log('Available functions:', Object.keys(authController));
  
  const {
    login,
    verifyTokenEndpoint,
    passwordResetRequest,
    passwordReset,
    logout,
    refreshToken
  } = authController;
  
  // Check each function individually
  console.log('login:', typeof login, login !== undefined ? '✅' : '❌ UNDEFINED');
  console.log('verifyTokenEndpoint:', typeof verifyTokenEndpoint, verifyTokenEndpoint !== undefined ? '✅' : '❌ UNDEFINED');
  console.log('passwordResetRequest:', typeof passwordResetRequest, passwordResetRequest !== undefined ? '✅' : '❌ UNDEFINED');
  console.log('passwordReset:', typeof passwordReset, passwordReset !== undefined ? '✅' : '❌ UNDEFINED');
  console.log('logout:', typeof logout, logout !== undefined ? '✅' : '❌ UNDEFINED');
  console.log('refreshToken:', typeof refreshToken, refreshToken !== undefined ? '✅' : '❌ UNDEFINED');
  
  // Test importing middleware
  const authMiddleware = require('../middleware/auth');
  const { 
    authenticateToken, 
    authRateLimit, 
    passwordResetRateLimit,
    createRateLimiter
  } = authMiddleware;
  
  const strictAuthRateLimit = createRateLimiter(5, 15 * 60 * 1000, 'Too many login attempts');
  
  // Only add routes for functions that exist
  if (login) {
    router.post('/login', strictAuthRateLimit, login);
    console.log('✅ Login route added');
  } else {
    console.log('❌ Skipping login route - function undefined');
  }
  
  if (verifyTokenEndpoint) {
    router.get('/verify', authenticateToken, verifyTokenEndpoint);
    console.log('✅ Verify route added');
  } else {
    console.log('❌ Skipping verify route - function undefined');
  }
  
  if (passwordResetRequest) {
    router.post('/password-reset-request', passwordResetRateLimit, passwordResetRequest);
    console.log('✅ Password reset request route added');
  } else {
    console.log('❌ Skipping password reset request route - function undefined');
  }
  
  if (passwordReset) {
    router.post('/password-reset', passwordResetRateLimit, passwordReset);
    console.log('✅ Password reset route added');
  } else {
    console.log('❌ Skipping password reset route - function undefined');
  }
  
  if (logout) {
    router.post('/logout', authenticateToken, logout);
    console.log('✅ Logout route added');
  } else {
    console.log('❌ Skipping logout route - function undefined');
  }
  
  if (refreshToken) {
    router.post('/refresh', authenticateToken, refreshToken);
    console.log('✅ Refresh route added');
  } else {
    console.log('❌ Skipping refresh route - function undefined');
  }
  
  // Test route
  router.get('/test', (req, res) => {
    res.json({ message: 'Auth routes working' });
  });
  
} catch (error) {
  console.error('❌ Error:', error.message);
  
  // Fallback test route
  router.get('/test', (req, res) => {
    res.json({ message: 'Auth routes working (fallback)' });
  });
}

module.exports = router;