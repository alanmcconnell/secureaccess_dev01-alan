const { pool } = require('../database');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const Joi = require('joi');

// Validation schemas
const createUserSchema = Joi.object({
  first_name: Joi.string().max(100).required(),
  last_name: Joi.string().max(100).required(),
  username: Joi.string().max(255).required(),
  email: Joi.string().email().max(255).required(),
  password: Joi.string().min(8).required(),
  security_question_1: Joi.string().optional(),
  security_answer_1: Joi.string().optional(),
  security_question_2: Joi.string().optional(),
  security_answer_2: Joi.string().optional(),
  two_factor_enabled: Joi.boolean().default(false),
  token_expiration_minutes: Joi.number().integer().min(1).max(1440).default(60)
});

const updateUserSchema = Joi.object({
  first_name: Joi.string().max(100).optional(),
  last_name: Joi.string().max(100).optional(),
  username: Joi.string().max(255).optional(),
  email: Joi.string().email().max(255).optional(),
  password: Joi.string().min(8).optional(),
  account_status: Joi.string().valid('active', 'inactive', 'locked').optional(),
  security_question_1: Joi.string().optional(),
  security_answer_1: Joi.string().optional(),
  security_question_2: Joi.string().optional(),
  security_answer_2: Joi.string().optional(),
  two_factor_enabled: Joi.boolean().optional(),
  token_expiration_minutes: Joi.number().integer().min(1).max(1440).optional()
});

// Helper functions
const generateSalt = () => crypto.randomBytes(32).toString('hex');

const hashPassword = async (password, salt) => {
  return await bcrypt.hash(password + salt, 12);
};

const hashSecurityAnswer = async (answer, salt) => {
  if (!answer) return null;
  return await bcrypt.hash(answer.toLowerCase().trim() + salt, 12);
};

const generateTwoFactorSecret = () => {
  return speakeasy.generateSecret({
    name: 'SecureAccess',
    length: 32
  }).base32;
};

// Get all users
const getAllUsers = async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email, 
        account_creation_date, last_login_timestamp, account_status,
        two_factor_enabled, jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, created_at, updated_at
      FROM users 
      ORDER BY created_at DESC
    `);
    
    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users',
      error: error.message
    });
  }
};

// Get user by ID
const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email,
        account_creation_date, last_login_timestamp, account_status,
        security_question_1, security_question_2, two_factor_enabled,
        jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, created_at, updated_at
      FROM users 
      WHERE user_id = ?
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: rows[0]
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user',
      error: error.message
    });
  }
};

// Create new user
const createUser = async (req, res) => {
  try {
    const { error, value } = createUserSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    const {
      first_name, last_name, username, email, password,
      security_question_1, security_answer_1,
      security_question_2, security_answer_2,
      two_factor_enabled, token_expiration_minutes
    } = value;

    // Generate salt and hash password
    const salt = generateSalt();
    const master_password_hash = await hashPassword(password, salt);
    
    // Hash security answers if provided
    const security_answer_1_hash = await hashSecurityAnswer(security_answer_1, salt);
    const security_answer_2_hash = await hashSecurityAnswer(security_answer_2, salt);
    
    // Generate 2FA secret if enabled
    const two_factor_secret = two_factor_enabled ? generateTwoFactorSecret() : null;

    const [result] = await pool.execute(`
      INSERT INTO users (
        first_name, last_name, username, email, master_password_hash, salt,
        security_question_1, security_answer_1_hash,
        security_question_2, security_answer_2_hash,
        two_factor_enabled, two_factor_secret, token_expiration_minutes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      first_name, last_name, username, email, master_password_hash, salt,
      security_question_1 || null, security_answer_1_hash,
      security_question_2 || null, security_answer_2_hash,
      two_factor_enabled ? 1 : 0, two_factor_secret, token_expiration_minutes
    ]);
    
    // Fetch the created user (without sensitive data)
    const [newUser] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email,
        account_creation_date, account_status, security_question_1,
        security_question_2, two_factor_enabled, jwt_secret_version,
        refresh_token_rotation_enabled, token_expiration_minutes,
        created_at, updated_at
      FROM users 
      WHERE user_id = ?
    `, [result.insertId]);
    
    const response = {
      success: true,
      message: 'User created successfully',
      data: newUser[0]
    };

    // Include 2FA setup info if enabled
    if (two_factor_enabled && two_factor_secret) {
      response.twoFactorSetup = {
        secret: two_factor_secret,
        qrCodeUrl: speakeasy.otpauthURL({
          secret: two_factor_secret,
          label: username,
          name: 'SecureAccess',
          issuer: 'SecureAccess'
        })
      };
    }
    
    res.status(201).json(response);
  } catch (error) {
    console.error('Error creating user:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Username or email already exists'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to create user',
      error: error.message
    });
  }
};

// Update user
const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    
    // Handle profile update authentication
    if (req.body._isProfileUpdate) {
      // For profile updates, we need to authenticate using credentials in the request
      if (!req.body._credentials) {
        return res.status(400).json({
          success: false,
          message: 'Credentials required for profile update'
        });
      }
      
      const { username, password } = req.body._credentials;
      
      // Verify the user credentials
      const [users] = await pool.execute(`
        SELECT 
          user_id, master_password_hash, salt, account_status
        FROM users 
        WHERE (username = ? OR email = ?) AND user_id = ?
      `, [username, username, id]);
      
      if (users.length === 0) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }
      
      const user = users[0];
      
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
      
      // Remove credentials and profile update flag from the request body
      delete req.body._credentials;
      delete req.body._isProfileUpdate;
    }
    
    const { error, value } = updateUserSchema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    // Check if user exists and get current salt
    const [existingUser] = await pool.execute('SELECT salt, two_factor_enabled FROM users WHERE user_id = ?', [id]);
    if (existingUser.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const salt = existingUser[0].salt;
    const currentTwoFactorEnabled = existingUser[0].two_factor_enabled;
    const updates = [];
    const values = [];

    // Handle each field update
    const {
      first_name, last_name, username, email, password, account_status,
      security_question_1, security_answer_1,
      security_question_2, security_answer_2,
      two_factor_enabled, token_expiration_minutes
    } = value;

    if (first_name !== undefined) {
      updates.push('first_name = ?');
      values.push(first_name);
    }
    if (last_name !== undefined) {
      updates.push('last_name = ?');
      values.push(last_name);
    }
    if (username !== undefined) {
      updates.push('username = ?');
      values.push(username);
    }
    if (email !== undefined) {
      updates.push('email = ?');
      values.push(email);
    }
    if (password !== undefined) {
      const master_password_hash = await hashPassword(password, salt);
      updates.push('master_password_hash = ?');
      values.push(master_password_hash);
      // Increment JWT secret version on password change
      updates.push('jwt_secret_version = jwt_secret_version + 1');
    }
    if (account_status !== undefined) {
      updates.push('account_status = ?');
      values.push(account_status);
    }
    if (security_question_1 !== undefined) {
      updates.push('security_question_1 = ?');
      values.push(security_question_1);
    }
    if (security_answer_1 !== undefined) {
      const security_answer_1_hash = await hashSecurityAnswer(security_answer_1, salt);
      updates.push('security_answer_1_hash = ?');
      values.push(security_answer_1_hash);
    }
    if (security_question_2 !== undefined) {
      updates.push('security_question_2 = ?');
      values.push(security_question_2);
    }
    if (security_answer_2 !== undefined) {
      const security_answer_2_hash = await hashSecurityAnswer(security_answer_2, salt);
      updates.push('security_answer_2_hash = ?');
      values.push(security_answer_2_hash);
    }
    if (two_factor_enabled !== undefined) {
      updates.push('two_factor_enabled = ?');
      values.push(two_factor_enabled ? 1 : 0);
      
      // Generate or clear 2FA secret
      if (two_factor_enabled) {
        const two_factor_secret = generateTwoFactorSecret();
        updates.push('two_factor_secret = ?');
        values.push(two_factor_secret);
      } else {
        updates.push('two_factor_secret = NULL');
      }
    }
    if (token_expiration_minutes !== undefined) {
      updates.push('token_expiration_minutes = ?');
      values.push(token_expiration_minutes);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No fields to update'
      });
    }

    values.push(id);
    
    await pool.execute(
      `UPDATE users SET ${updates.join(', ')} WHERE user_id = ?`,
      values
    );
    
    // Fetch updated user
    const [updatedUser] = await pool.execute(`
      SELECT 
        user_id, first_name, last_name, username, email,
        account_creation_date, last_login_timestamp, account_status,
        security_question_1, security_question_2, two_factor_enabled,
        jwt_secret_version, refresh_token_rotation_enabled,
        token_expiration_minutes, created_at, updated_at, two_factor_secret
      FROM users 
      WHERE user_id = ?
    `, [id]);

    const responseData = {
      success: true,
      message: 'User updated successfully',
      data: {
        user_id: updatedUser[0].user_id,
        first_name: updatedUser[0].first_name,
        last_name: updatedUser[0].last_name,
        username: updatedUser[0].username,
        email: updatedUser[0].email,
        account_creation_date: updatedUser[0].account_creation_date,
        last_login_timestamp: updatedUser[0].last_login_timestamp,
        account_status: updatedUser[0].account_status,
        security_question_1: updatedUser[0].security_question_1,
        security_question_2: updatedUser[0].security_question_2,
        two_factor_enabled: updatedUser[0].two_factor_enabled,
        jwt_secret_version: updatedUser[0].jwt_secret_version,
        refresh_token_rotation_enabled: updatedUser[0].refresh_token_rotation_enabled,
        token_expiration_minutes: updatedUser[0].token_expiration_minutes,
        created_at: updatedUser[0].created_at,
        updated_at: updatedUser[0].updated_at
      }
    };

    // If 2FA was enabled during this update, include setup info
    if (two_factor_enabled === true && updatedUser[0].two_factor_secret) {
      responseData.twoFactorSetup = {
        secret: updatedUser[0].two_factor_secret,
        qrCodeUrl: speakeasy.otpauthURL({
          secret: updatedUser[0].two_factor_secret,
          label: updatedUser[0].username,
          name: 'SecureAccess',
          issuer: 'SecureAccess'
        })
      };
    }
    
    res.json(responseData);
  } catch (error) {
    console.error('Error updating user:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Username or email already exists'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to update user',
      error: error.message
    });
  }
};

// Update last login timestamp
const updateLastLogin = async (req, res) => {
  try {
    const { id } = req.params;
    
    const [result] = await pool.execute(
      'UPDATE users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
      [id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Last login timestamp updated successfully'
    });
  } catch (error) {
    console.error('Error updating last login:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update last login timestamp',
      error: error.message
    });
  }
};

// Delete user
const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    
    const [result] = await pool.execute('DELETE FROM users WHERE user_id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete user',
      error: error.message
    });
  }
};

// Get user security info (for password reset, etc.)
const getUserSecurity = async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.execute(`
      SELECT 
        user_id, username, email, security_question_1, security_question_2,
        two_factor_enabled, account_status
      FROM users 
      WHERE user_id = ?
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: rows[0]
    });
  } catch (error) {
    console.error('Error fetching user security info:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user security information',
      error: error.message
    });
  }
};

module.exports = {
  getAllUsers,
  getUserById,
  createUser,
  updateUser,
  updateLastLogin,
  deleteUser,
  getUserSecurity
};