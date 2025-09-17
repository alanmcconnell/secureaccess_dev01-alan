// Improved auth controller with proper response structure
const { pool } = require('../database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Simple login function with proper response structure
const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }
    
    // Query the database for the actual user
    const query = 'SELECT user_id, first_name, last_name, username, email, account_status, two_factor_enabled, last_login_timestamp, master_password_hash, salt, role FROM sa_users WHERE username = ? OR email = ?';
    console.log('========== DEBUG LOGIN START ==========');
    console.log('SQL Query:', query);
    console.log('Query parameters:', [username, username]);
    
    const [rows] = await pool.execute(query, [username, username]);
    console.log('Database result:', rows[0]);
    
    if (rows.length === 0) {
      console.log('No user found');
      console.log('========== DEBUG LOGIN END ==========');
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    // Create user object from database result
    const user = {
        user_id: rows[0].user_id,
        username: rows[0].username,
        email: rows[0].email,
        role: rows[0].role, // Explicitly include role
        master_password_hash: rows[0].master_password_hash,
        salt: rows[0].salt
    };
    
    console.log('Created user object:', user);
    console.log('Role from database:', rows[0].role);
    console.log('Raw database result:', rows[0]);
    console.log('Database columns:', Object.keys(rows[0]));
    console.log('Role field value:', rows[0].role);
    console.log('Role field type:', typeof rows[0].role);
    console.log('========== DEBUG LOGIN END ==========');
    
    // Debug user data
    console.log('User data debug:');
    console.log('Full user object:', user);
    console.log('User ID:', user.user_id);
    console.log('Username:', user.username);
    console.log('Role:', user.role);
    
    // Debug password verification
    console.log('Password verification debug:');
    console.log('Input password:', password);
    console.log('User salt:', user.salt);
    console.log('Stored hash:', user.master_password_hash);
    console.log('Combined for verification:', password + user.salt);
    
    // Verify password (match the format used in user creation)
    const isValidPassword = await bcrypt.compare(password + user.salt, user.master_password_hash);
    console.log('Password valid:', isValidPassword);
    
    if (!isValidPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Return actual user data from database
    const userData = {
      userId: user.user_id,
      firstName: user.first_name,
      lastName: user.last_name,
      username: user.username,
      email: user.email,
      accountStatus: user.account_status,
      twoFactorEnabled: user.two_factor_enabled,
      lastLogin: user.last_login_timestamp,
      role: user.role // Add role to user data
    };
    
    // Get user and role permissions
    console.log('========== DEBUG PERMISSIONS START ==========');
    
    // Ensure role is properly assigned from the database query
    const role = rows[0].role;
    console.log('User role from database:', role);
    
    const [rolePermissions] = await pool.execute(`
        SELECT p.name 
        FROM sa_role_permissions rp 
        JOIN sa_permissions p ON rp.permission_id = p.id 
        WHERE rp.role = ?
    `, [role]);
    
    console.log('Role permissions result:', rolePermissions);

    const [userPermissions] = await pool.execute(`
        SELECT p.name 
        FROM sa_user_permissions up 
        JOIN sa_permissions p ON up.permission_id = p.id 
        WHERE up.user_id = ?
    `, [user.user_id]);
    
    console.log('User permissions result:', userPermissions);
    console.log('========== DEBUG PERMISSIONS END ==========');

    // Combine both sets of permissions
    const allPermissions = [...rolePermissions, ...userPermissions];

    // Debug token data before generation
    console.log('========== DEBUG TOKEN GENERATION START ==========');
    const tokenPayload = {
        userId: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role, // Use the role from user object
        permissions: allPermissions.map(p => p.name)
    };
    console.log('Token payload:', tokenPayload);
    console.log('Role value being added:', role);
    console.log('========== DEBUG TOKEN GENERATION END ==========');

    // Generate real JWT token with permissions
    const token = jwt.sign(
        tokenPayload,
        process.env.JWT_SECRET || 'your-secret-key',
        { expiresIn: '1h' }
    );

    // Debug output
    console.log('User data for token:', {
        userId: user.user_id,
        username: user.username,
        role: user.role
    });
    
    // Set JWT token as HTTP-only cookie
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
    });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: userData,
        expiresIn: 3600
      }
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Login error',
      error: error.message
    });
  }
};

// Simple verify function
const verifyTokenEndpoint = (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      userId: req.user.userId,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role
    }
  });
};

// Simple password reset request
const passwordResetRequest = (req, res) => {
  const { email } = req.body;
  
  res.json({
    success: true,
    message: 'Password reset request received (mock response)',
    data: {
      email: email,
      securityQuestion1: 'What is your favorite color?',
      securityQuestion2: 'What city were you born in?'
    }
  });
};

// Simple password reset
const passwordReset = (req, res) => {
  res.json({
    success: true,
    message: 'Password reset successful (mock response)'
  });
};

// Simple logout
const logout = (req, res) => {
  // Clear the HTTP-only cookie
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  
  res.json({
    success: true,
    message: 'Logout successful'
  });
};

// Refresh token
const refreshToken = async (req, res) => {
  try {
    const user = req.user;
    // Get user and role permissions
    const rolePermissions = await db.query(`
        SELECT p.name 
        FROM sa_role_permissions rp 
        JOIN sa_permissions p ON rp.permission_id = p.id 
        WHERE rp.role = ?
    `, [user.role]);

    const userPermissions = await db.query(`
        SELECT p.name 
        FROM sa_user_permissions up 
        JOIN sa_permissions p ON up.permission_id = p.id 
        WHERE up.user_id = ?
    `, [user.userId]);

    // Combine both sets of permissions
    const allPermissions = [...rolePermissions, ...userPermissions];

    const newToken = jwt.sign(
      {
        userId: user.userId,
        username: user.username,
        email: user.email,
        role: user.role, // Add user's role
        permissions: allPermissions.map(p => p.name) // Add permissions to token
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '1h' }
    );
    
    // Set new JWT token as HTTP-only cookie
    res.cookie('authToken', newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        expiresIn: 3600
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Token refresh failed',
      error: error.message
    });
  }
};

// Verify JWT token function for middleware
const verifyToken = async (token, userId) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    return {
      userId: decoded.userId,
      username: decoded.username,
      email: decoded.email,
      role: decoded.role,
      permissions: decoded.permissions || [],
      version: 1
    };
  } catch (error) {
    throw new Error('Invalid or expired token');
  }
};

module.exports = {
  login,
  verifyTokenEndpoint,
  passwordResetRequest,
  passwordReset,
  logout,
  refreshToken,
  verifyToken
};