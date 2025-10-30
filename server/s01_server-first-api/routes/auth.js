const express = require('express');
const crypto = require('crypto');
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
  passwordResetRateLimit,
  createRateLimiter
} = require('../middleware/auth');

// Create a strict rate limiter for login
const strictAuthRateLimit = createRateLimiter(5, 15 * 60 * 1000, 'Too many login attempts');

// Temporary storage for authorization codes (use Redis or database in production)
const authCodes = new Map();

// Clean up expired codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes.entries()) {
    if (now > data.expires_at) {
      authCodes.delete(code);
    }
  }
}, 5 * 60 * 1000);

// Apply general rate limiting to auth routes
router.use(authRateLimit);

// POST /api/auth/login - User login (stricter rate limit)
router.post('/login', strictAuthRateLimit, login);

// GET /api/auth/verify - Verify JWT token
router.get('/verify', authenticateToken, verifyTokenEndpoint);

// POST /api/auth/verify - Verify JWT token (alternative method)
router.post('/verify', authenticateToken, verifyTokenEndpoint);

// POST /api/auth/password-reset-request - Request password reset (strict rate limit)
router.post('/password-reset-request', passwordResetRateLimit, passwordResetRequest);

// POST /api/auth/password-reset - Reset password with security questions (strict rate limit)
router.post('/password-reset', passwordResetRateLimit, passwordReset);

// POST /api/auth/logout - Logout user
router.post('/logout', authenticateToken, logout);

// POST /api/auth/refresh - Refresh JWT token
router.post('/refresh', authenticateToken, refreshToken);

// POST /api/auth/verify-admin - Verify admin access
router.post('/verify-admin', authenticateToken, (req, res) => {
  try {
    // Check if user has admin role
    if (!req.user || req.user.role !== 'Admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required',
        code: 'ADMIN_REQUIRED'
      });
    }
    
    res.json({
      success: true,
      message: 'Admin access verified',
      user: {
        userId: req.user.userId,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Admin verification failed',
      error: error.message
    });
  }
});

// POST /api/auth/authorize - Generate PKCE authorization code
router.post('/authorize', authenticateToken, async (req, res) => {
  try {
    const { 
      user_id, 
      username, 
      email, 
      role, 
      code_challenge, 
      code_challenge_method, 
      state, 
      redirect_uri 
    } = req.body;

    // Validate required PKCE parameters
    if (!code_challenge || code_challenge_method !== 'S256') {
      return res.status(400).json({
        success: false,
        message: 'Invalid PKCE parameters. code_challenge and code_challenge_method=S256 required'
      });
    }

    // Validate that the authenticated user matches the request
    if (req.user.userId !== user_id && req.user.user_id !== user_id) {
      return res.status(403).json({
        success: false,
        message: 'User ID mismatch'
      });
    }

    // Generate secure authorization code
    const authCode = crypto.randomBytes(32).toString('hex');
    
    // Store authorization data with 10-minute expiration
    authCodes.set(authCode, {
      user_id: user_id || req.user.userId || req.user.user_id,
      username: username || req.user.username,
      email: email || req.user.email,
      role: role || req.user.role,
      code_challenge,
      code_challenge_method,
      state,
      redirect_uri,
      created_at: Date.now(),
      expires_at: Date.now() + (10 * 60 * 1000) // 10 minutes
    });

    console.log(`Authorization code generated for user: ${username || req.user.username}`);

    res.json({
      success: true,
      data: {
        code: authCode,
        expires_in: 600 // 10 minutes in seconds
      }
    });

  } catch (error) {
    console.error('Authorization error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate authorization code',
      error: error.message
    });
  }
});

// POST /api/auth/token - Exchange authorization code for user data using PKCE
router.post('/token', async (req, res) => {
  try {
    const { code, code_verifier, state } = req.body;

    // Validate required parameters
    if (!code || !code_verifier) {
      return res.status(400).json({
        success: false,
        message: 'Missing required parameters: code and code_verifier'
      });
    }

    // Retrieve stored authorization data
    const authData = authCodes.get(code);
    
    if (!authData) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired authorization code'
      });
    }

    // Check expiration
    if (Date.now() > authData.expires_at) {
      authCodes.delete(code);
      return res.status(400).json({
        success: false,
        message: 'Authorization code expired'
      });
    }

    // Verify state parameter if provided
    if (state && authData.state !== state) {
      authCodes.delete(code);
      return res.status(400).json({
        success: false,
        message: 'Invalid state parameter'
      });
    }

    // Verify PKCE code challenge
    const hash = crypto.createHash('sha256')
      .update(code_verifier)
      .digest('base64url');
    
    if (hash !== authData.code_challenge) {
      authCodes.delete(code);
      return res.status(400).json({
        success: false,
        message: 'Invalid code_verifier - PKCE verification failed'
      });
    }

    // PKCE verification successful - return user data
    const userData = {
      user_id: authData.user_id,
      username: authData.username,
      email: authData.email,
      role: authData.role
    };

    // Invalidate the authorization code (single use)
    authCodes.delete(code);

    console.log(`Authorization code exchanged successfully for user: ${userData.username}`);

    res.json({
      success: true,
      data: {
        user: userData,
        token_type: 'Bearer',
        scope: 'user_info'
      }
    });

  } catch (error) {
    console.error('Token exchange error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to exchange authorization code',
      error: error.message
    });
  }
});

// GET /api/auth/codes - Debug endpoint to view active authorization codes (remove in production)
router.get('/codes', authenticateToken, (req, res) => {
  // Only allow admin users to view this debug info
  if (req.user.role !== 'Admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }

  const activeCodes = [];
  const now = Date.now();
  
  for (const [code, data] of authCodes.entries()) {
    activeCodes.push({
      code: code.substring(0, 8) + '...', // Partial code for security
      username: data.username,
      created_at: new Date(data.created_at).toISOString(),
      expires_at: new Date(data.expires_at).toISOString(),
      expired: now > data.expires_at
    });
  }

  res.json({
    success: true,
    data: {
      active_codes: activeCodes,
      total_count: authCodes.size
    }
  });
});

module.exports = router;