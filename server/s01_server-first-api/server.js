const dotenv = require('dotenv')
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const crypto = require('crypto');

             require( "./_config.js" )                                                  // .(51013.03.1 RAM Load process.fvaR)
//    dotenv.config( { path:       `${ __dirname }/.env`) } );                          //#.(51013.03.2 RAM No workie in windows)
      dotenv.config( { path: path.join(__dirname, '.env') } );  
                                                                                        // .(51013.03.2 RAM This works everywhere)
const SECURE_API_URL   = process.fvaRs.SECURE_API_URL                                   // .(51013.04.1 RAM not SECURE_PATH)
      process.env.PORT = SECURE_API_URL.match(   /:([0-9]+)\/?/)?.slice(1,2)[0] ?? ''   // .(51013.04.2 RAM Define them here)
      process.env.HOST = SECURE_API_URL.match(/(.+):[0-9]+\/?/ )?.slice(1,2)[0] ?? ''   // .(51013.04.3)

// Debug environment variables
console.log('🔧 Environment variables loaded:');
console.log('   PORT:',       process.env.PORT);
console.log('   HOST:',       process.env.HOST);
console.log('   DB_HOST:',    process.env.DB_HOST);
console.log('   DB_NAME:',    process.env.DB_NAME);
console.log('   JWT_SECRET:', process.env.JWT_SECRET ? '[SET]' : '[NOT SET]');

// CSRF Token generation
function generateSecureRandomToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Simple CSRF protection using custom header
function csrfCrossOrigin(req, res, next) {
    // Skip CSRF for GET requests
    if (req.method === 'GET') {
        return next();
    }
    
    // Check for custom header (prevents simple form-based attacks)
    const customHeader = req.headers['x-requested-with'];
    if (!customHeader || customHeader !== 'XMLHttpRequest') {
        console.log('❌ CSRF validation failed: Missing X-Requested-With header');
        console.log('📋 Request headers:', req.headers);
        return res.status(403).json({ error: 'Invalid request' });
    }
    
    console.log('✅ CSRF validation passed: X-Requested-With header present');
    next();
}

const app = express();

const PORT     =  process.env.PORT // || 3005;
const NODE_ENV =  process.env.NODE_ENV || 'development';
const HOST     =  NODE_ENV === 'production' ? process.env.PRODUCTION_HOST : process.env.HOST;    // .(51013.03.3 RAM PRODUCTION_HOST is not defined)
//nst BASE_URL = `http${NODE_ENV === 'production' ? 's' : ''}://${HOST}:${PORT}`;                //#.(51013.03.4)
const BASE_URL = `${HOST}:${PORT}`;  
const SECURE_PATH = process.fvaRs.SECURE_PATH                                           // .(51013.03.5 RAM HOST includes http or https)

// JWT Secret - In production, use environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'SecureAccess-JWT-Secret-Key-2024!@#$%';
const JWT_EXPIRES_IN = '24h'; // Token expires in 24 hours

// Middleware
const allowedOrigins = NODE_ENV === 'production' 
    ? [ `${HOST}:${PORT}`, `${HOST}`]
    : [ `${BASE_URL}`, SECURE_PATH ];                                                   // .(51013.04.16 RAM Server: SECURE_API_URL).(51013.03.6 RAM Client: SECURE_PATH)

    allowedOrigins.forEach( aHost => { if (aHost.match( /http:\/\/localhost/ ) ) { allowedOrigins.push( aHost.replace( /\/\/localhost/, "//127.0.0.1" ) ) } } )
//  ? [ `https://${HOST}`, `https://${HOST}:${PORT}`]
//  : [ `http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`,
//      `http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`,
//      'http://localhost:3001', 'http://127.0.0.1:3001',
//      'http://localhost:5500', 'http://127.0.0.1:5500'
//       ];

app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Access'],
    credentials: true
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../../client/c01_client-first-app'))); // Serve client files

// CSRF Protection - configured for cross-origin
const csrfProtection = csrf({ 
    cookie: { 
        httpOnly: false,
        secure: false, 
        sameSite: 'lax'
    },
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});

// Request logging middleware
app.use((req, res, next) => {
    console.log(`🔍 ${new Date().toISOString()} - ${req.method} ${req.path}`);
    if (req.path.includes('/api/')) {
        console.log('🍪 All cookies in request:', req.cookies);
        console.log('📋 Raw cookie header:', req.headers.cookie);
    }
    next();
});

// JWT Token generation function
function generateToken(user) {
    const payload = {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        role: user.role,
        account_status: user.account_status
    };
    
    return jwt.sign(payload, JWT_SECRET, { 
        expiresIn: JWT_EXPIRES_IN,
        issuer: 'SecureAccess',
        audience: 'SecureAccess-Users'
    });
}

// JWT Token verification middleware
function verifyToken(req, res, next) {
    // Check for token in HTTP-only cookie first, then Authorization header
    let token = req.cookies?.authToken;
    
    if (!token) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7);
        }
    }

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required',
            code: 'TOKEN_MISSING'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Check if token is expired
        if (decoded.exp < Date.now() / 1000) {
            return res.status(401).json({
                success: false,
                message: 'Token has expired',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        req.user = decoded;
        next();
    } catch (error) {
        console.error('JWT verification error:', error.message);
        return res.status(401).json({
            success: false,
            message: 'Invalid token',
            code: 'TOKEN_INVALID'
        });
    }
}

// Admin role verification middleware
function requireAdmin(req, res, next) {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Authentication required',
            code: 'AUTH_REQUIRED'
        });
    }
    
    if (req.user.role !== 'Admin') {
        console.log(`🚫 Access denied for user ${req.user.username} (role: ${req.user.role})`);
        return res.status(403).json({
            success: false,
            message: 'Admin access required',
            code: 'ADMIN_REQUIRED'
        });
    }
    
    console.log(`✅ Admin access granted for user ${req.user.username}`);
    next();
}

// Combined middleware for admin operations
const adminAccess = [verifyToken, requireAdmin];

// Database configuration from .env file
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'secureaccess2',
    timezone: 'Z'
};

// Database connection pool
let pool;

async function initDatabase() {
    try {
        pool = mysql.createPool({
            ...dbConfig,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0
        });
        
        // Test connection
        const connection = await pool.getConnection();
        console.log('✅ Connected to MySQL database successfully');
        connection.release();
        
        // Ensure sa_users table exists
        await ensureTableExists();
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        process.exit(1);
    }
}

// Ensure sa_users table exists with proper structure
async function ensureTableExists() {
    try {
        const createTableSQL = `
            CREATE TABLE IF NOT EXISTS sa_users (
                user_id INT AUTO_INCREMENT PRIMARY KEY,
                first_name VARCHAR(50),
                last_name VARCHAR(50),
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                master_password_hash VARCHAR(255) NOT NULL,
                account_status ENUM('active', 'inactive', 'locked') DEFAULT 'active',
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                two_factor_secret VARCHAR(255),
                role ENUM('User', 'Admin') DEFAULT 'User',
                security_question_1 TEXT,
                security_answer_1_hash VARCHAR(255),
                security_question_2 TEXT,
                security_answer_2_hash VARCHAR(255),
                token_expiration_minutes INT DEFAULT 60,
                last_login_timestamp TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `;
        
        await pool.execute(createTableSQL);
        console.log('✅ sa_users table verified/created');
        
    } catch (error) {
        console.error('❌ Error creating sa_users table:', error.message);
    }
}

// Utility function to hash passwords
async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

// Utility function to verify passwords
async function verifyPassword(password, hash) {
    // Handle case where hash is null/undefined/empty
    if (!hash || hash.trim() === '') {
        return false;
    }
    
    try {
        return await bcrypt.compare(password, hash);
    } catch (error) {
        console.error('Password verification error:', error.message);
        return false;
    }
}

// CSRF token endpoint
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Health check endpoint (no CSRF needed)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        database: 'connected'
    });
});

// Config endpoint to provide client configuration
app.get('/config', (req, res) => {
    res.json({
        port: PORT,
        host: HOST,
        environment: NODE_ENV,
        apiBaseUrl: `${BASE_URL}/api`
    });
});

// Debug CSRF endpoint
app.get('/debug/csrf', (req, res) => {
    res.json({ 
        message: 'CSRF debug info',
        cookies: req.cookies,
        headers: req.headers
    });
});

// JWT Token validation endpoint
app.post('/api/auth/verify-token', verifyToken, (req, res) => {
    res.json({
        success: true,
        message: 'Token is valid',
        user: {
            user_id: req.user.user_id,
            username: req.user.username,
            email: req.user.email,
            role: req.user.role,
            account_status: req.user.account_status
        }
    });
});

// Auth verify endpoint for profile page
app.get('/api/auth/verify', (req, res) => {
    console.log('🔍 Auth verify request received');
    console.log('🍪 Request cookies:', req.cookies);
    console.log('📋 Request headers:', req.headers.authorization);
    
    // Check for token in HTTP-only cookie first, then Authorization header
    let token = req.cookies?.authToken;
    
    if (!token) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.substring(7);
        }
    }

    if (!token) {
        console.log('❌ No token found in request');
        return res.status(401).json({
            success: false,
            message: 'Access token required',
            code: 'TOKEN_MISSING'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Check if token is expired
        if (decoded.exp < Date.now() / 1000) {
            console.log('❌ Token expired');
            return res.status(401).json({
                success: false,
                message: 'Token has expired',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        console.log('✅ Token verified for user:', decoded.username);
        res.json({
            success: true,
            message: 'Token is valid',
            data: {
                userId: decoded.user_id,
                username: decoded.username,
                email: decoded.email,
                role: decoded.role
            }
        });
    } catch (error) {
        console.error('❌ JWT verification error:', error.message);
        return res.status(401).json({
            success: false,
            message: 'Invalid token',
            code: 'TOKEN_INVALID'
        });
    }
});

// Auth verify endpoint POST method
app.post('/api/auth/verify', verifyToken, (req, res) => {
    res.json({
        success: true,
        message: 'Token is valid',
        data: {
            userId: req.user.user_id,
            username: req.user.username,
            email: req.user.email,
            role: req.user.role
        }
    });
});

// Admin access verification endpoint
app.post('/api/auth/verify-admin', adminAccess, (req, res) => {
    res.json({
        success: true,
        message: 'Admin access confirmed',
        user: {
            user_id: req.user.user_id,
            username: req.user.username,
            email: req.user.email,
            role: req.user.role
        }
    });
});

// Test bcrypt endpoint
app.get('/api/test-bcrypt', async (req, res) => {
    const testPassword = 'password123';
    const wrongHash = '$2b$12$LQv3c1yqBwcVsvDwxVFOa.hNt/p5j9RLGPLBrkQUTz/p8QFJ1aP.q';
    
    try {
        console.log('🧪 Testing bcrypt with known values...');
        console.log(`   Password: ${testPassword}`);
        console.log(`   Wrong Hash: ${wrongHash}`);
        
        const wrongResult = await bcrypt.compare(testPassword, wrongHash);
        console.log(`   Wrong hash result: ${wrongResult}`);
        
        // Generate correct hash
        console.log('🔧 Generating correct hash...');
        const correctHash = await hashPassword(testPassword);
        console.log(`   Correct Hash: ${correctHash}`);
        
        const correctResult = await bcrypt.compare(testPassword, correctHash);
        console.log(`   Correct hash result: ${correctResult}`);
        
        res.json({
            success: true,
            password: testPassword,
            wrong_hash: wrongHash,
            wrong_result: wrongResult,
            correct_hash: correctHash,
            correct_result: correctResult,
            sql_command: `UPDATE sa_users SET master_password_hash = '${correctHash}' WHERE username = 'officecat';`
        });
    } catch (error) {
        console.error('❌ Bcrypt test error:', error);
        res.json({
            success: false,
            error: error.message
        });
    }
});

// Get all users - PROTECTED WITH JWT
app.get('/api/users', adminAccess, async (req, res) => {
    try {
        console.log('📊 GET /api/users - Loading all users...');
        
        if (!pool) {
            console.error('❌ Database pool not initialized');
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                user_id,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                role,
                token_expiration_minutes,
                last_login_timestamp,
                created_at,
                updated_at
            FROM sa_users 
            ORDER BY first_name, last_name
        `);
        
        console.log(`✅ Found ${rows.length} users`);
        
        res.json({
            success: true,
            data: rows
        });
        
    } catch (error) {
        console.error('❌ Error fetching users:');
        console.error('Error code:', error.code);
        console.error('Error message:', error.message);
        console.error('SQL State:', error.sqlState);
        console.error('Full error:', error);
        
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users',
            error: error.message,
            details: error.code
        });
    }
});

// Get own profile - /me endpoint  
app.get('/api/users/me', verifyToken, async (req, res) => {
    // Allow both Admin and User roles
    if (!req.user || !['Admin', 'User'].includes(req.user.role)) {
        return res.status(403).json({
            success: false,
            message: 'Access denied'
        });
    }
    try {
        const userId = req.user.user_id;
        
        const [rows] = await pool.execute(`
            SELECT 
                user_id, first_name, last_name, username, email,
                account_creation_date, last_login_timestamp, account_status,
                security_question_1, security_answer_1_hash, security_question_2, security_answer_2_hash, 
                two_factor_enabled, token_expiration_minutes, created_at, updated_at
            FROM sa_users 
            WHERE user_id = ?
        `, [userId]);
        
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
        console.error('Error fetching user profile:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user profile',
            error: error.message
        });
    }
});

// Get specific user by ID - PROTECTED WITH JWT
app.get('/api/users/:id', verifyToken, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        if (isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        const [rows] = await pool.execute(`
            SELECT 
                user_id,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                two_factor_secret,
                role,
                security_question_1,
                security_answer_1_hash,
                security_question_2,
                security_answer_2_hash,
                token_expiration_minutes,
                last_login_timestamp,
                created_at,
                updated_at
            FROM sa_users 
            WHERE user_id = ?
        `, [userId]);
        
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
});

// Create new user - PROTECTED WITH JWT
app.post('/api/users', adminAccess, async (req, res) => {
    try {
        const {
            first_name,
            last_name,
            username,
            email,
            password,
            account_status = 'active',
            two_factor_enabled = false,
            role = 'User',
            security_question_1,
            security_answer_1,
            security_question_2,
            security_answer_2,
            token_expiration_minutes = 60
        } = req.body;
        
        // Validation
        if (!first_name || !last_name || !username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: first_name, last_name, username, email, password'
            });
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }
        
        // Validate password strength
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }
        
        // Check if username or email already exists
        const [existingUsers] = await pool.execute(
            'SELECT user_id FROM sa_users WHERE username = ? OR email = ?',
            [username, email]
        );
        
        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Username or email already exists'
            });
        }
        
        // Hash password
        const passwordHash = await hashPassword(password);
        
        // Hash security answers if provided
        let hashedAnswer1 = null;
        let hashedAnswer2 = null;
        
        if (security_answer_1 && security_answer_1.trim() !== '') {
            hashedAnswer1 = await hashPassword(security_answer_1.trim());
            console.log('🔐 Hashed security_answer_1 for new user');
        }
        
        if (security_answer_2 && security_answer_2.trim() !== '') {
            hashedAnswer2 = await hashPassword(security_answer_2.trim());
            console.log('🔐 Hashed security_answer_2 for new user');
        }
        
        // Insert new user
        const [result] = await pool.execute(`
            INSERT INTO sa_users (
                first_name,
                last_name,
                username,
                email,
                master_password_hash,
                account_status,
                two_factor_enabled,
                role,
                security_question_1,
                security_answer_1_hash,
                security_question_2,
                security_answer_2_hash,
                token_expiration_minutes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            first_name,
            last_name,
            username,
            email,
            passwordHash,
            account_status,
            two_factor_enabled,
            role,
            security_question_1 || null,
            hashedAnswer1,
            security_question_2 || null,
            hashedAnswer2,
            token_expiration_minutes
        ]);
        
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: {
                user_id: result.insertId,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                token_expiration_minutes
            }
        });
        
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create user',
            error: error.message
        });
    }
});

// Update own profile - /me endpoint
app.put('/api/users/me', verifyToken, async (req, res) => {
    // Allow both Admin and User roles
    if (!req.user || !['Admin', 'User'].includes(req.user.role)) {
        return res.status(403).json({
            success: false,
            message: 'Access denied'
        });
    }
    
    try {
        const userId = req.user.user_id;
        
        const {
            first_name,
            last_name,
            username,
            email,
            password,
            security_question_1,
            security_answer_1,
            security_question_2,
            security_answer_2
        } = req.body;
        
        console.log('🔄 Profile update request for user ID:', userId);
        
        // Build dynamic update query
        const updates = [];
        const values = [];
        
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
        if (password !== undefined && password.trim() !== '') {
            console.log('🔒 Hashing new password...');
            const passwordHash = await hashPassword(password);
            updates.push('master_password_hash = ?');
            values.push(passwordHash);
        }
        if (security_question_1 !== undefined) {
            updates.push('security_question_1 = ?');
            values.push(security_question_1);
        }
        if (security_answer_1 !== undefined && security_answer_1.trim() !== '') {
            console.log('🔐 Hashing security_answer_1...');
            const hashedAnswer1 = await hashPassword(security_answer_1.trim());
            updates.push('security_answer_1_hash = ?');
            values.push(hashedAnswer1);
        }
        if (security_question_2 !== undefined) {
            updates.push('security_question_2 = ?');
            values.push(security_question_2);
        }
        if (security_answer_2 !== undefined && security_answer_2.trim() !== '') {
            console.log('🔐 Hashing security_answer_2...');
            const hashedAnswer2 = await hashPassword(security_answer_2.trim());
            updates.push('security_answer_2_hash = ?');
            values.push(hashedAnswer2);
        }
        
        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        // Add updated_at timestamp
        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(userId);
        
        const updateSQL = `UPDATE sa_users SET ${updates.join(', ')} WHERE user_id = ?`;
        
        const [updateResult] = await pool.execute(updateSQL, values);
        
        // Fetch updated user data
        const [updatedUser] = await pool.execute(`
            SELECT 
                user_id, first_name, last_name, username, email,
                security_question_1, security_question_2, updated_at
            FROM sa_users 
            WHERE user_id = ?
        `, [userId]);
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: updatedUser[0]
        });
        
    } catch (error) {
        console.error('❌ Error updating profile:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile',
            error: error.message
        });
    }
});

// Update user - PROTECTED WITH JWT
app.put('/api/users/:id', adminAccess, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        if (isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        // Check if user exists
        const [existingUser] = await pool.execute(
            'SELECT user_id FROM sa_users WHERE user_id = ?',
            [userId]
        );
        
        if (existingUser.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const {
            first_name,
            last_name,
            username,
            email,
            password,
            account_status,
            two_factor_enabled,
            role,
            security_question_1,
            security_answer_1,
            security_question_2,
            security_answer_2,
            token_expiration_minutes
        } = req.body;
        
        console.log('🔄 Update request for user ID:', userId);
        console.log('📝 Received data:', {
            first_name,
            last_name,
            username,
            email,
            security_question_1,
            security_answer_1: security_answer_1 ? '[PROVIDED]' : '[NOT PROVIDED]',
            security_question_2,
            security_answer_2: security_answer_2 ? '[PROVIDED]' : '[NOT PROVIDED]'
        });
        
        // Build dynamic update query
        const updates = [];
        const values = [];
        
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
        if (password !== undefined && password.trim() !== '') {
            console.log('🔒 Hashing new password...');
            const passwordHash = await hashPassword(password);
            updates.push('master_password_hash = ?');
            values.push(passwordHash);
        }
        if (account_status !== undefined) {
            updates.push('account_status = ?');
            values.push(account_status);
        }
        if (two_factor_enabled !== undefined) {
            updates.push('two_factor_enabled = ?');
            values.push(two_factor_enabled);
        }
        if (role !== undefined) {
            updates.push('role = ?');
            values.push(role);
        }
        if (security_question_1 !== undefined) {
            console.log('📋 Updating security_question_1:', security_question_1);
            updates.push('security_question_1 = ?');
            values.push(security_question_1);
        }
        
        // FIXED: Security Answer 1 handling
        if (security_answer_1 !== undefined && security_answer_1.trim() !== '') {
            console.log('🔐 Hashing security_answer_1...');
            const hashedAnswer1 = await hashPassword(security_answer_1.trim());
            updates.push('security_answer_1_hash = ?');
            values.push(hashedAnswer1);
            console.log('✅ security_answer_1_hash updated');
        }
        
        if (security_question_2 !== undefined) {
            console.log('📋 Updating security_question_2:', security_question_2);
            updates.push('security_question_2 = ?');
            values.push(security_question_2);
        }
        
        // FIXED: Security Answer 2 handling
        if (security_answer_2 !== undefined && security_answer_2.trim() !== '') {
            console.log('🔐 Hashing security_answer_2...');
            const hashedAnswer2 = await hashPassword(security_answer_2.trim());
            updates.push('security_answer_2_hash = ?');
            values.push(hashedAnswer2);
            console.log('✅ security_answer_2_hash updated');
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
        
        // Add updated_at timestamp
        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(userId);
        
        const updateSQL = `UPDATE sa_users SET ${updates.join(', ')} WHERE user_id = ?`;
        
        console.log('🗃️ Executing SQL:', updateSQL);
        console.log('📊 With values:', values.map((v, i) => 
            values.length - 1 === i ? `userId: ${v}` : 
            updates[i]?.includes('password') || updates[i]?.includes('answer') ? '[HASHED]' : v
        ));
        
        const [updateResult] = await pool.execute(updateSQL, values);
        
        console.log('✅ Update result:', {
            affectedRows: updateResult.affectedRows,
            changedRows: updateResult.changedRows
        });
        
        // Fetch updated user data
        const [updatedUser] = await pool.execute(`
            SELECT 
                user_id,
                first_name,
                last_name,
                username,
                email,
                account_status,
                two_factor_enabled,
                security_question_1,
                security_question_2,
                token_expiration_minutes,
                updated_at
            FROM sa_users 
            WHERE user_id = ?
        `, [userId]);
        
        res.json({
            success: true,
            message: 'User updated successfully',
            data: updatedUser[0]
        });
        
    } catch (error) {
        console.error('❌ Error updating user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user',
            error: error.message
        });
    }
});

// Delete user and related records - PROTECTED WITH JWT
app.delete('/api/users/:id', adminAccess, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        if (isNaN(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID'
            });
        }
        
        // Check if user exists
        const [existingUser] = await pool.execute(
            'SELECT user_id, username FROM sa_users WHERE user_id = ?',
            [userId]
        );
        
        if (existingUser.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        // Start transaction for safe deletion
        const connection = await pool.getConnection();
        await connection.beginTransaction();
        
        try {
            // Delete related records from other tables (add as needed)
            // Example: await connection.execute('DELETE FROM user_sessions WHERE user_id = ?', [userId]);
            // Example: await connection.execute('DELETE FROM user_tokens WHERE user_id = ?', [userId]);
            // Example: await connection.execute('DELETE FROM user_logs WHERE user_id = ?', [userId]);
            
            // Delete the user
            await connection.execute('DELETE FROM sa_users WHERE user_id = ?', [userId]);
            
            await connection.commit();
            connection.release();
            
            res.json({
                success: true,
                message: `User ${existingUser[0].username} deleted successfully`
            });
            
        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user',
            error: error.message
        });
    }
});

// Debug endpoint for security answers - PROTECTED WITH JWT
app.get('/api/debug/user/:id/security', adminAccess, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        
        const [rows] = await pool.execute(`
            SELECT 
                user_id,
                username,
                security_question_1,
                security_answer_1_hash,
                security_question_2,
                security_answer_2_hash,
                LENGTH(security_answer_1_hash) as answer1_hash_length,
                LENGTH(security_answer_2_hash) as answer2_hash_length
            FROM sa_users 
            WHERE user_id = ?
        `, [userId]);
        
        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const user = rows[0];
        
        res.json({
            success: true,
            data: {
                user_id: user.user_id,
                username: user.username,
                security_question_1: user.security_question_1,
                has_security_answer_1: !!user.security_answer_1_hash,
                answer1_hash_length: user.answer1_hash_length,
                security_question_2: user.security_question_2,
                has_security_answer_2: !!user.security_answer_2_hash,
                answer2_hash_length: user.answer2_hash_length
            }
        });
        
    } catch (error) {
        console.error('Error fetching security debug info:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch security info',
            error: error.message
        });
    }
});

// Reset password for a single user - PROTECTED WITH JWT
app.post('/api/admin/reset-single-password', adminAccess, async (req, res) => {
    try {
        const { username, newPassword } = req.body;
        
        if (!username || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Username and newPassword are required'
            });
        }
        
        if (!pool) {
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Hash the new password
        const passwordHash = await hashPassword(newPassword);
        
        // Update the user's password
        const [result] = await pool.execute(
            'UPDATE sa_users SET master_password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?',
            [passwordHash, username]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        console.log(`✅ Password reset for user: ${username}`);
        
        res.json({
            success: true,
            message: `Password reset successfully for user: ${username}`
        });
        
    } catch (error) {
        console.error('❌ Error resetting password:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password',
            error: error.message
        });
    }
});

// Bulk fix passwords for users with NULL password_hash - PROTECTED WITH JWT
app.post('/api/admin/fix-passwords', adminAccess, async (req, res) => {
    try {
        const { defaultPassword = 'password123' } = req.body;
        
        if (!pool) {
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Find all users with NULL or empty master_password_hash
        const [usersWithoutPasswords] = await pool.execute(
            'SELECT user_id, username FROM sa_users WHERE master_password_hash IS NULL OR master_password_hash = ""'
        );
        
        if (usersWithoutPasswords.length === 0) {
            return res.json({
                success: true,
                message: 'All users already have password hashes',
                fixed_count: 0
            });
        }
        
        // Hash the default password
        const passwordHash = await hashPassword(defaultPassword);
        
        // Update all users without password hashes
        const [result] = await pool.execute(
            'UPDATE sa_users SET master_password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE master_password_hash IS NULL OR master_password_hash = ""',
            [passwordHash]
        );
        
        console.log(`✅ Fixed password hashes for ${result.affectedRows} users with default password: ${defaultPassword}`);
        
        res.json({
            success: true,
            message: `Fixed password hashes for ${result.affectedRows} users`,
            fixed_count: result.affectedRows,
            default_password: defaultPassword,
            affected_users: usersWithoutPasswords.map(u => u.username)
        });
        
    } catch (error) {
        console.error('❌ Error fixing passwords:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fix passwords',
            error: error.message
        });
    }
});

// Registration endpoint - PUBLIC ACCESS
app.post('/api/auth/register', async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            username,
            email,
            password,
            securityQuestions,
            twoFactorEnabled = false
        } = req.body;
        
        console.log(`📝 Registration attempt for username: ${username}`);
        
        // Validation
        if (!firstName || !lastName || !username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: firstName, lastName, username, email, password'
            });
        }
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }
        
        // Validate password strength
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }
        
        // Check if username or email already exists
        const [existingUsers] = await pool.execute(
            'SELECT user_id FROM sa_users WHERE username = ? OR email = ?',
            [username, email]
        );
        
        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Username or email already exists'
            });
        }
        
        // Hash password
        const passwordHash = await hashPassword(password);
        
        // Hash security answers if provided
        let hashedAnswer1 = null;
        let hashedAnswer2 = null;
        let securityQuestion1 = null;
        let securityQuestion2 = null;
        
        if (securityQuestions && Array.isArray(securityQuestions) && securityQuestions.length >= 2) {
            if (securityQuestions[0]?.question && securityQuestions[0]?.answer) {
                securityQuestion1 = securityQuestions[0].question;
                hashedAnswer1 = await hashPassword(securityQuestions[0].answer.trim());
                console.log('🔐 Hashed security_answer_1 for registration');
            }
            
            if (securityQuestions[1]?.question && securityQuestions[1]?.answer) {
                securityQuestion2 = securityQuestions[1].question;
                hashedAnswer2 = await hashPassword(securityQuestions[1].answer.trim());
                console.log('🔐 Hashed security_answer_2 for registration');
            }
        }
        
        // Insert new user
        const [result] = await pool.execute(`
            INSERT INTO sa_users (
                first_name,
                last_name,
                username,
                email,
                master_password_hash,
                account_status,
                two_factor_enabled,
                role,
                security_question_1,
                security_answer_1_hash,
                security_question_2,
                security_answer_2_hash,
                token_expiration_minutes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            firstName,
            lastName,
            username,
            email,
            passwordHash,
            'inactive',
            twoFactorEnabled,
            'User',
            securityQuestion1,
            hashedAnswer1,
            securityQuestion2,
            hashedAnswer2,
            60
        ]);
        
        console.log(`✅ User registered successfully: ${username} (ID: ${result.insertId})`);
        
        res.status(201).json({
            success: true,
            message: 'Registration successful',
            data: {
                user_id: result.insertId,
                firstName,
                lastName,
                username,
                email,
                account_status: 'inactive',
                role: 'User'
            }
        });
        
    } catch (error) {
        console.error('❌ Error during registration:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed',
            error: error.message
        });
    }
});

// Login endpoint - UPDATED TO GENERATE JWT TOKENS
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log(`🔍 Login attempt for username: ${username}`);
        
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }
        
        // Find user by username or email
        const [users] = await pool.execute(
            'SELECT * FROM sa_users WHERE username = ? OR email = ?',
            [username, username]
        );
        
        if (users.length === 0) {
            console.log(`❌ User not found: ${username}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        const user = users[0];
        console.log(`✅ User found: ${user.username}`);
        console.log(`   Account status: ${user.account_status}`);
        console.log(`   Role: ${user.role}`);
        console.log(`   Has master_password_hash: ${!!user.master_password_hash}`);
        console.log(`   Hash length: ${user.master_password_hash ? user.master_password_hash.length : 0}`);
        
        // Verify password
        const passwordValid = await verifyPassword(password, user.master_password_hash);
        console.log(`   Password valid: ${passwordValid}`);
        
        if (!passwordValid) {
            console.log(`❌ Invalid password for user: ${username}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        // Check account status (case insensitive)
        if (user.account_status.toLowerCase() !== 'active') {
            console.log(`❌ Account not active: ${user.account_status}`);
            return res.status(403).json({
                success: false,
                message: 'Account is disabled'
            });
        }
        
        // Generate JWT token
        const token = generateToken(user);
        console.log(`🎫 Generated JWT token for user: ${username}`);
        
        // Update last login timestamp
        await pool.execute(
            'UPDATE sa_users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
            [user.user_id]
        );
        
        console.log(`✅ Login successful for user: ${username} (role: ${user.role})`);
        
        // Set JWT token as HTTP-only cookie
        res.cookie('authToken', token, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        console.log('🍪 Cookie set with token for user:', username);
        console.log('🍪 Cookie details:', {
            name: 'authToken',
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000,
            path: '/'
        });
        
        // Return user info (excluding sensitive data)
        const { master_password_hash, security_answer_1_hash, security_answer_2_hash, two_factor_secret, ...userInfo } = user;
        
        res.json({
            success: true,
            message: 'Login successful',
            data: {
                user: userInfo,
                token: token // Temporarily include token in response for debugging
            }
        });
        
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed',
            error: error.message
        });
    }
});

// Logout endpoint
app.post('/api/auth/logout', verifyToken, (req, res) => {
    // Clear the HTTP-only cookie
    res.clearCookie('authToken', {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/'
    });
    
    console.log(`🚪 User ${req.user.username} logged out`);
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: error.message
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

function listRoutes() {                                                                 // .(51007.01.1 RAM Add listRoutes)
    console.log('\n    === Registered Routes ===');
    app._router.stack.forEach((middleware, index) => {
        if (middleware.route) {
            const methods = Object.keys(middleware.route.methods).join(', ').toUpperCase();
            console.log(`    ${methods.padEnd(6)} ${middleware.route.path}`);
        }
    });
    console.log('    ========================\n');
    }                                                                                   // .(51007.01.1 End)
// Start server
async function startServer() {
    try {
        await initDatabase();

              listRoutes()       // .(51007.01.1 RAM Add)

        server = app.listen(PORT, () => {
            console.log(`🚀 Server running on ${BASE_URL}`);
//          console.log(`📊 Admin page:   ${BASE_URL}/admin-page.html`);                 //#.(51013.03.7)
            console.log(`📊 Admin page:   ${SECURE_PATH}/admin-page.html`);              // .(51013.03.7)
            console.log(`📊 Login page:   ${SECURE_PATH}/login_client.html`);            // .(51013.03.8)
            console.log(`🏥 Health check: ${BASE_URL}/health`);
            console.log(`🌍 Environment:  ${NODE_ENV}`);
            console.log(`🔐 JWT Security: ENABLED`);
        });
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
let server;

async function gracefulShutdown(signal) {
    console.log(`\n🛑 Received ${signal}. Shutting down server...`);
    
    if (server) {
        server.close(() => {
            console.log('✅ HTTP server closed');
        });
    }
    
    if (pool) {
        await pool.end();
        console.log('✅ Database connections closed');
    }
    
    process.exit(0);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Windows specific signals
if (process.platform === 'win32') {
    process.on('SIGBREAK', () => gracefulShutdown('SIGBREAK'));
}

// Start the server
startServer();