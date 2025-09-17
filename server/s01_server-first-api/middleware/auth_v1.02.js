const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }
    
    const secret = process.env.JWT_SECRET || 'your-super-secure-secret-key-here';
    
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        console.error('JWT verification error:', err.message);
        
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({
            success: false,
            message: 'Token expired'
          });
        } else if (err.name === 'JsonWebTokenError') {
          return res.status(401).json({
            success: false,
            message: 'Invalid token'
          });
        } else {
          return res.status(401).json({
            success: false,
            message: 'Token verification failed'
          });
        }
      }
      
      // Add user info to request object
      req.user = {
        userId: decoded.userId,
        username: decoded.username,
        email: decoded.email,
        version: decoded.version
      };
      
      next();
    });
    
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return res.status(500).json({
      success: false,
      message: 'Authentication error',
      error: error.message
    });
  }
};

// Rate limiting middleware
const rateLimiter = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  return rateLimit({
    windowMs: windowMs, // time window in milliseconds
    max: maxRequests, // limit each IP to maxRequests requests per windowMs
    message: {
      success: false,
      message: 'Too many requests, please try again later.'
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    // Custom handler for when limit is exceeded
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        message: 'Too many requests, please try again later.',
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

// Optional: Middleware to check if user exists and is active
const checkUserStatus = async (req, res, next) => {
  try {
    const { pool } = require('../database');
    const userId = req.user.userId;
    
    const [users] = await pool.execute(
      'SELECT account_status, jwt_secret_version FROM users WHERE user_id = ?',
      [userId]
    );
    
    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const user = users[0];
    
    if (user.account_status !== 'active') {
      return res.status(401).json({
        success: false,
        message: `Account is ${user.account_status}`
      });
    }
    
    // Check if JWT version matches (for token invalidation on password change)
    if (req.user.version !== user.jwt_secret_version) {
      return res.status(401).json({
        success: false,
        message: 'Token invalidated due to security update'
      });
    }
    
    next();
  } catch (error) {
    console.error('User status check error:', error);
    return res.status(500).json({
      success: false,
      message: 'User verification error',
      error: error.message
    });
  }
};

module.exports = {
  authenticateToken,
  rateLimiter,
  checkUserStatus
};