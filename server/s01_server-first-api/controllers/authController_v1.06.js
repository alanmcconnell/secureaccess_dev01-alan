const { pool } = require('../database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const Joi = require('joi');

// Validation schemas
const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required(),
  twoFactorCode: Joi.string().optional()
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

// Helper function to generate JWT token
const generateToken = (user) => {
  const payload = {
    userId: user.user_id,
    username: user.username,
    email: user.email,
    version: user.jwt_secret_version
  };
  
  const secret = process.env.JWT_SECRET || 'your-super-secure-secret-key-here';
  const expiresIn = `${user.token_expiration_minutes}m`;
  
  return jwt.sign(payload, secret, { expiresIn });
};

// Helper function to generate refresh token
const generateRefreshToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// User login
const loginUser = async (req, res) => {
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

    // Get user from database
    const [users] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email, 
        master_password_hash, salt, account_status, two_factor_enabled, 
        two_factor_secret, jwt_secret_version, token_expiration_minutes,
        last_login_timestamp
      FROM users 
      WHERE username = ? OR email = ?
    `, [username, username]);

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const user = users[0];

    // Check account status
    if (user.account_status !== 'active') {
      return res.status(401).json({
        success: false,
        message: `Account is ${user.account_status}`
      });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password + user.salt, user.master_password_hash);
    
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check 2FA if enabled
    if (user.two_factor_enabled) {
      if (!twoFactorCode) {
        return res.status(400).json({
          success: false,
          message: 'Two-factor authentication code required'
        });
      }

      const verified = speakeasy.totp.verify({
        secret: user.two_factor_secret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 2
      });

      if (!verified) {
        return res.status(401).json({
          success: false,
          message: 'Invalid two-factor authentication code'
        });
      }
    }

    // Generate tokens
    const token = generateToken(user);
    const refreshToken = generateRefreshToken();

    // Update last login timestamp
    await pool.execute(
      'UPDATE users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
      [user.user_id]
    );

    // Store refresh token (optional - for refresh token rotation)
    // You might want to create a separate table for refresh tokens

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        refreshToken,
        user: {
          user_id: user.user_id,
          firstName: user.first_name,
          lastName: user.last_name,
          username: user.username,
          email: user.email,
          accountStatus: user.account_status,
          twoFactorEnabled: user.two_factor_enabled,
          lastLogin: new Date().toISOString()
        }
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: error.message
    });
  }
};

// User logout
const logoutUser = async (req, res) => {
  try {
    // In a more sophisticated setup, you'd invalidate the refresh token here
    // and possibly add the JWT to a blacklist until it expires
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed',
      error: error.message
    });
  }
};

// Password reset request
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

    // Get user security questions
    const [users] = await pool.execute(`
      SELECT 
        user_id, email, security_question_1, security_question_2
      FROM users 
      WHERE email = ? AND account_status = 'active'
    `, [email]);

    if (users.length === 0 || !users[0].security_question_1 || !users[0].security_question_2) {
      // Return success for security (don't reveal if email exists or has security questions)
      return res.json({
        success: true,
        message: 'If the email exists and has security questions, they have been sent'
      });
    }

    const user = users[0];

    res.json({
      success: true,
      message: 'Security questions retrieved',
      data: {
        email: user.email,
        securityQuestion1: user.security_question_1,
        securityQuestion2: user.security_question_2
      }
    });

  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({
      success: false,
      message: 'Password reset request failed',
      error: error.message
    });
  }
};

// Password reset
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

    // Get user and security info
    const [users] = await pool.execute(`
      SELECT 
        user_id, salt, security_answer_1_hash, security_answer_2_hash
      FROM users 
      WHERE email = ? AND account_status = 'active'
    `, [email]);

    if (users.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid reset request'
      });
    }

    const user = users[0];

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
      return res.status(400).json({
        success: false,
        message: 'Security answers do not match'
      });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword + user.salt, 12);

    // Update password and increment JWT secret version
    await pool.execute(`
      UPDATE users 
      SET master_password_hash = ?, jwt_secret_version = jwt_secret_version + 1, updated_at = CURRENT_TIMESTAMP
      WHERE user_id = ?
    `, [newPasswordHash, user.user_id]);

    res.json({
      success: true,
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({
      success: false,
      message: 'Password reset failed',
      error: error.message
    });
  }
};

// Refresh token
const refreshToken = async (req, res) => {
  try {
    // Implementation depends on your refresh token strategy
    res.status(501).json({
      success: false,
      message: 'Refresh token functionality not implemented yet'
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({
      success: false,
      message: 'Token refresh failed',
      error: error.message
    });
  }
};

// Validate token
const validateToken = async (req, res) => {
  try {
    // Token is already validated by the authenticateToken middleware
    // If we get here, the token is valid
    res.json({
      success: true,
      message: 'Token is valid',
      data: {
        user: req.user
      }
    });
  } catch (error) {
    console.error('Token validation error:', error);
    res.status(500).json({
      success: false,
      message: 'Token validation failed',
      error: error.message
    });
  }
};

module.exports = {
  loginUser,
  logoutUser,
  passwordResetRequest,
  passwordReset,
  refreshToken,
  validateToken
};