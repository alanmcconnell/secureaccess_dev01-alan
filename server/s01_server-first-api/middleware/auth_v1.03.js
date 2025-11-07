const { verifyToken } = require('../controllers/authController');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.decode(token);
    
    if (!decoded) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token format'
      });
    }
    
    // Verify token with user's secret
    const verifiedToken = await verifyToken(token, decoded.userId);
    
    // Add user info to request
    req.user = {
      userId: verifiedToken.userId,
      username: verifiedToken.username,
      email: verifiedToken.email,
      version: verifiedToken.version
    };
    
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({
      success: false,
      message: error.message || 'Invalid or expired token'
    });
  }
};

// Optional authentication middleware (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded = jwt.decode(token);
      
      if (decoded) {
        try {
          const verifiedToken = await verifyToken(token, decoded.userId);
          req.user = {
            userId: verifiedToken.userId,
            username: verifiedToken.username,
            email: verifiedToken.email,
            version: verifiedToken.version
          };
        } catch (error) {
          // Token invalid, but continue without user
          console.log('Optional auth failed:', error.message);
        }
      }
    }
    
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};

// Role-based authorization middleware
const authorize = (roles = []) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required'
        });
      }
      
      // In a more complex system, you would check user roles here
      // For now, we'll just ensure the user is authenticated
      next();
    } catch (error) {
      console.error('Authorization error:', error);
      res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
    }
  };
};

// Rate limiting middleware using express-rate-limit
const createRateLimiter = (maxRequests = 100, windowMs = 15 * 60 * 1000, message = 'Too many requests') => {
  return rateLimit({
    windowMs,
    max: maxRequests,
    message: {
      success: false,
      message: `${message}. Please try again later.`,
      retryAfter: Math.ceil(windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        message: `${message}. Please try again later.`,
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

// Pre-configured rate limiters
const generalRateLimit = createRateLimiter(100, 15 * 60 * 1000, 'Too many requests');
const authRateLimit = createRateLimiter(20, 15 * 60 * 1000, 'Too many authentication attempts');
const strictAuthRateLimit = createRateLimiter(5, 15 * 60 * 1000, 'Too many login attempts');
const passwordResetRateLimit = createRateLimiter(3, 15 * 60 * 1000, 'Too many password reset requests');

module.exports = {
  authenticateToken,
  optionalAuth,
  authorize,
  createRateLimiter,
  generalRateLimit,
  authRateLimit,
  strictAuthRateLimit,
  passwordResetRateLimit
};