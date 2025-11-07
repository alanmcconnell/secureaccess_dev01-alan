const express = require('express');
const router = express.Router();

console.log('Starting auth routes import...');

try {
  const authController = require('../controllers/authController');
  console.log('Auth controller keys:', Object.keys(authController));
  
  const {
    login,
    verifyTokenEndpoint,
    passwordResetRequest,
    passwordReset,
    logout,
    refreshToken
  } = authController;
  
  // Check each function
  console.log('Function checks:');
  console.log('- login:', typeof login);
  console.log('- verifyTokenEndpoint:', typeof verifyTokenEndpoint);
  console.log('- passwordResetRequest:', typeof passwordResetRequest);
  console.log('- passwordReset:', typeof passwordReset);
  console.log('- logout:', typeof logout);
  console.log('- refreshToken:', typeof refreshToken);
  
  const { 
    authenticateToken, 
    authRateLimit, 
    passwordResetRateLimit,
    createRateLimiter
  } = require('../middleware/auth');
  
  // CSRF protection middleware
  const csrfProtection = (req, res, next) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      return next();
    }
    
    const token = req.headers['x-requested-with'];
    if (!token || token !== 'XMLHttpRequest') {
      return res.status(403).json({
        success: false,
        message: 'Invalid request'
      });
    }
    
    next();
  };

  const strictAuthRateLimit = createRateLimiter(5, 15 * 60 * 1000, 'Too many login attempts');

  // Apply general rate limiting to auth routes
  router.use(authRateLimit);

  // Add routes only if functions exist
  if (typeof login === 'function') {
    try {
      router.post('/login', csrfProtection, strictAuthRateLimit, login);
      console.log('✅ Login route added');
    } catch (routeError) {
      const errorMessage = routeError && routeError.message ? routeError.message : 'Unknown error';
      console.error('❌ Error adding login route:', errorMessage);
    }
  } else {
    console.log('❌ Login function is not available');
  }

  if (typeof verifyTokenEndpoint === 'function') {
    try {
      router.get('/verify', authenticateToken, verifyTokenEndpoint);
      console.log('✅ Verify route added');
    } catch (routeError) {
      const errorMessage = routeError && routeError.message ? routeError.message : 'Unknown error';
      console.error('❌ Error adding verify route:', errorMessage);
    }
  } else {
    console.log('❌ VerifyTokenEndpoint function is not available');
  }

  if (typeof passwordResetRequest === 'function') {
    router.post('/password-reset-request', csrfProtection, passwordResetRateLimit, passwordResetRequest);
    console.log('✅ Password reset request route added');
  } else {
    console.log('❌ PasswordResetRequest function is not available');
  }

  if (typeof passwordReset === 'function') {
    router.post('/password-reset', csrfProtection, passwordResetRateLimit, passwordReset);
    console.log('✅ Password reset route added');
  } else {
    console.log('❌ PasswordReset function is not available');
  }

  if (typeof logout === 'function') {
    router.post('/logout', csrfProtection, authenticateToken, logout);
    console.log('✅ Logout route added');
  } else {
    console.log('❌ Logout function is not available');
  }

  if (typeof refreshToken === 'function') {
    router.post('/refresh', csrfProtection, authenticateToken, refreshToken);
    console.log('✅ Refresh route added');
  } else {
    console.log('❌ RefreshToken function is not available');
  }

} catch (error) {
  const errorMessage = error && error.message ? error.message : 'Unknown import error';
  console.error('❌ Error importing auth controller:', errorMessage);
  if (error && error.stack) {
    console.error('Error stack:', error.stack);
  }
}

module.exports = router;