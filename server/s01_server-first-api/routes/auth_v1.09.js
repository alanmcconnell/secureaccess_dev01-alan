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
  
  // Check each function
  console.log('login:', typeof login);
  console.log('verifyTokenEndpoint:', typeof verifyTokenEndpoint);
  console.log('passwordResetRequest:', typeof passwordResetRequest);
  console.log('passwordReset:', typeof passwordReset);
  console.log('logout:', typeof logout);
  console.log('refreshToken:', typeof refreshToken);
  
  // Simple test route
  router.get('/test', (req, res) => {
    res.json({ message: 'Auth routes working' });
  });
  
} catch (error) {
  console.error('❌ Error importing auth controller:', error.message);
  console.error('Full error:', error);
  
  // Fallback test route
  router.get('/test', (req, res) => {
    res.json({ message: 'Auth routes working (fallback)' });
  });
}

module.exports = router;