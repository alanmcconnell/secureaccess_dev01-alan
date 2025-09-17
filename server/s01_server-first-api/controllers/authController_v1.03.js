const { pool } = require('../database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const Joi = require('joi');

// Validation schemas
const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required(),
  twoFactorCode: Joi.string().length(6).pattern(/^\d+$/).optional()
});

const passwordResetRequestSchema = Joi.object({
  email: Joi.string().email().required()
});

const passwordResetSchema = Joi.object({
  email: Joi.string().email().required(),
  securityAnswer1: Joi.string().required(),
  securityAnswer2: Joi.string().required(),
  newPassword: Joi.string().min(8).required()
});

// Generate JWT token
const generateToken = (user) => {
  const payload = {
    userId: user.user_id,
    username: user.username,
    email: user.email,
    version: user.jwt_secret_version
  };
  
  // Use user-specific secret (combine app secret with user's salt)
  const secret = process.env.JWT_SECRET + user.salt;
  
  return jwt.sign(payload, secret, {
    expiresIn: `${user.token_expiration_minutes}m`,
    issuer: 'SecureAccess',
    subject: user.user_id.toString()
  });
};

// Verify JWT token
const verifyToken = async (token, userId) => {
  try {
    // Get user's current salt and JWT version
    const [users] = await pool.execute(
      'SELECT salt, jwt_secret_version FROM users WHERE user_id = ?',
      [userId]
    );
    
    if (users.length === 0) {
      throw new Error('User not found');
    }
    
    const user = users[0];
    const secret = process.env.JWT_SECRET + user.salt;
    
    const decoded = jwt.verify(token, secret);
    
    // Check if JWT version matches (for token invalidation)
    if (decoded.version !== user.jwt_secret_version) {
      throw new Error('Token version mismatch - please login again');
    }
    
    return decoded;
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
};

// Login endpoint
const login = async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    const { username, password, twoFactorCode } = value;
    
    // Find user by username or email
    const [users] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email, 
        master_password_hash, salt, account_status, 
        two_factor_enabled, two_factor_secret, jwt_secret_version,
        token_expiration_minutes, last_login_timestamp
      FROM users 
      WHERE username = ? OR email = ?
    `, [username, username]);
    
    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }
    
    const user = users[0];
    
    // Check account status
    if (user.account_status !== 'active') {
      return res.status(401).json({
        success: false,
        message: `Account is ${user.account_status}. Please contact support.`
      });
    }
    
    // Verify password
    const passwordMatch = await bcrypt.compare(password + user.salt, user.master_password_hash);
    
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }
    
    // Check two-factor authentication if enabled
    if (user.two_factor_enabled) {
      if (!twoFactorCode) {
        return res.status(400).json({
          success: false,
          message: 'Two-factor authentication code required',
          requiresTwoFactor: true
        });
      }
      
      const verified = speakeasy.totp.verify({
        secret: user.two_factor_secret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 2 // Allow for time drift
      });
      
      if (!verified) {
        return res.status(401).json({
          success: false,
          message: 'Invalid two-factor authentication code'
        });
      }
    }
    
    // Generate JWT token
    const token = generateToken(user);
    
    // Update last login timestamp
    await pool.execute(
      'UPDATE users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
      [user.user_id]
    );
    
    // Return success response (exclude sensitive data)
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          userId: user.user_id,
          firstName: user.first_name,
          lastName: user.last_name,
          username: user.username,
          email: user.email,
          accountStatus: user.account_status,
          twoFactorEnabled: user.two_factor_enabled,
          tokenExpirationMinutes: user.token_expiration_minutes,
          lastLogin: user.last_login_timestamp
        },
        token,
        expiresIn: user.token_expiration_minutes * 60 // seconds
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login',
      error: error.message
    });
  }
};

// Token verification endpoint
const verifyTokenEndpoint = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
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
    await verifyToken(token, decoded.userId);
    
    // Get current user data
    const [users] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email, 
        account_status, two_factor_enabled, token_expiration_minutes,
        last_login_timestamp, created_at
      FROM users 
      WHERE user_id = ?
    `, [decoded.userId]);
    
    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const user = users[0];
    
    res.json({
      success: true,
      data: {
        userId: user.user_id,
        firstName: user.first_name,
        lastName: user.last_name,
        username: user.username,
        email: user.email,
        accountStatus: user.account_status,
        twoFactorEnabled: user.two_factor_enabled,
        tokenExpirationMinutes: user.token_expiration_minutes,
        lastLogin: user.last_login_timestamp,
        createdAt: user.created_at
      }
    });
    
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({
      success: false,
      message: error.message
    });
  }
};

// Password reset request (get security questions)
const passwordResetRequest = async (req, res) => {
  try {
    const { error, value } = passwordResetRequestSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    const { email } = value;
    
    const [users] = await pool.execute(`
      SELECT 
        user_id, username, email, security_question_1, security_question_2,
        account_status
      FROM users 
      WHERE email = ?
    `, [email]);
    
    if (users.length === 0) {
      // Don't reveal if email exists for security
      return res.json({
        success: true,
        message: 'If the email exists, security questions have been sent'
      });
    }
    
    const user = users[0];
    
    if (user.account_status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Account is not active'
      });
    }
    
    if (!user.security_question_1 || !user.security_question_2) {
      return res.status(400).json({
        success: false,
        message: 'Security questions not set up for this account'
      });
    }
    
    res.json({
      success: true,
      data: {
        email: user.email,
        username: user.username,
        securityQuestion1: user.security_question_1,
        securityQuestion2: user.security_question_2
      }
    });
    
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
};

// Password reset with security questions
const passwordReset = async (req, res) => {
  try {
    const { error, value } = passwordResetSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    const { email, securityAnswer1, securityAnswer2, newPassword } = value;
    
    const [users] = await pool.execute(`
      SELECT 
        user_id, salt, security_answer_1_hash, security_answer_2_hash,
        account_status
      FROM users 
      WHERE email = ?
    `, [email]);
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const user = users[0];
    
    if (user.account_status !== 'active') {
      return res.status(400).json({
        success: false,
        message: 'Account is not active'
      });
    }
    
    // Verify security answers
    const answer1Match = await bcrypt.compare(
      securityAnswer1.toLowerCase().trim() + user.salt, 
      user.security_answer_1_hash
    );
    
    const answer2Match = await bcrypt.compare(
      securityAnswer2.toLowerCase().trim() + user.salt, 
      user.security_answer_2_hash
    );
    
    if (!answer1Match || !answer2Match) {
      return res.status(401).json({
        success: false,
        message: 'Security answers do not match'
      });
    }
    
    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword + user.salt, 12);
    
    // Update password and increment JWT version to invalidate all tokens
    await pool.execute(`
      UPDATE users 
      SET master_password_hash = ?, jwt_secret_version = jwt_secret_version + 1
      WHERE user_id = ?
    `, [newPasswordHash, user.user_id]);
    
    res.json({
      success: true,
      message: 'Password reset successfully. Please login with your new password.'
    });
    
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
};

// Logout endpoint (client-side token deletion, but we can track it)
const logout = async (req, res) => {
  try {
    // In a more sophisticated system, you might want to track logout events
    // or maintain a blacklist of invalidated tokens
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
};

// Refresh token endpoint
const refreshToken = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
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
    
    // Get user data for new token
    const [users] = await pool.execute(`
      SELECT 
        user_id, username, email, salt, jwt_secret_version,
        token_expiration_minutes, account_status
      FROM users 
      WHERE user_id = ?
    `, [decoded.userId]);
    
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
    
    // Verify current token is still valid
    try {
      await verifyToken(token, user.user_id);
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: 'Current token is invalid'
      });
    }
    
    // Generate new token
    const newToken = generateToken(user);
    
    res.json({
      success: true,
      data: {
        token: newToken,
        expiresIn: user.token_expiration_minutes * 60
      }
    });
    
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
};

module.exports = {
  login,
  verifyTokenEndpoint,
  passwordResetRequest,
  passwordReset,
  logout,
  refreshToken,
  verifyToken // Export for middleware use
};