const express = require('express');
const router = express.Router();

// Test importing the auth controller
try {
  const authController = require('../controllers/authController');
  console.log('✅ Auth controller imported successfully');
  
  const {
    login,
    verifyTokenEndpoint,
    passwordResetRequest,
    passwordReset,
    logout,
    refreshToken
  } = authController;
  
  // Test importing middleware
  console.log('Attempting to import auth middleware...');
  const authMiddleware = require('../middleware/auth');
  console.log('✅ Auth middleware imported successfully');
  console.log('Available middleware:', Object.keys(authMiddleware));
  
  const { 
    authenticateToken, 
    authRateLimit, 
    passwordResetRateLimit,
    createRateLimiter
  } = authMiddleware;
  
  console.log('authenticateToken:', typeof authenticateToken);
  console.log('authRateLimit:', typeof authRateLimit);
  console.log('passwordResetRateLimit:', typeof passwordResetRateLimit);
  console.log('createRateLimiter:', typeof createRateLimiter);
  
  // Create a strict rate limiter for login
  const strictAuthRateLimit = createRateLimiter(5, 15 * 60 * 1000, 'Too many login attempts');
  console.log('strictAuthRateLimit:', typeof strictAuthRateLimit);
  
  // Test a simple route with middleware
  router.get('/test', authRateLimit, (req, res) => {
    res.json({ message: 'Auth routes working with middleware' });
  });
  
  // Add actual auth routes
  router.post('/login', strictAuthRateLimit, login);
  router.get('/verify', authenticateToken, verifyTokenEndpoint);
  router.post('/password-reset-request', passwordResetRateLimit, passwordResetRequest);
  router.post('/password-reset', passwordResetRateLimit, passwordReset);
  router.post('/logout', authenticateToken, logout);
  router.post('/refresh', authenticateToken, refreshToken);
  
  console.log('✅ All auth routes added successfully');
  
} catch (error) {
  console.error('❌ Error:', error.message);
  console.error('Full error:', error);
  
  // Fallback test route
  router.get('/test', (req, res) => {
    res.json({ message: 'Auth routes working (fallback)' });
  });
}

module.exports = router;