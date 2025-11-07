const { verifyToken } = require('../controllers/authController');
const jwt = require('jsonwebtoken');

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

// Rate limiting middleware (basic implementation)
const rateLimiter = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  const requestCounts = new Map();
  
  return (req, res, next) => {
    const identifier = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old entries
    for (const [key, data] of requestCounts.entries()) {
      if (data.firstRequest < windowStart) {
        requestCounts.delete(key);
      }
    }
    
    // Check current requests
    const userRequests = requestCounts.get(identifier);
    
    if (!userRequests) {
      requestCounts.set(identifier, {
        count: 1,
        firstRequest: now
      });
      return next();
    }
    
    if (userRequests.firstRequest < windowStart) {
      // Reset counter for new window
      requestCounts.set(identifier, {
        count: 1,
        firstRequest: now
      });
      return next();
    }
    
    if (userRequests.count >= maxRequests) {
      return res.status(429).json({
        success: false,
        message: 'Too many requests. Please try again later.',
        retryAfter: Math.ceil((userRequests.firstRequest + windowMs - now) / 1000)
      });
    }
    
    userRequests.count++;
    next();
  };
};

module.exports = {
  authenticateToken,
  optionalAuth,
  authorize,
  rateLimiter
};