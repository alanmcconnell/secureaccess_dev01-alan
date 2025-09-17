const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Access']
}));
app.use(express.json());
app.use(express.static('public')); // Serve static files

// Request logging middleware
app.use((req, res, next) => {
    console.log(`🔍 ${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Admin access middleware (simple check for admin operations)
function adminAccess(req, res, next) {
    // For admin page, allow access with admin header
    if (req.headers['x-admin-access'] === 'true') {
        return next();
    }
    
    // For other requests, you could add JWT token validation here
    // For now, allow all requests to proceed
    next();
}

// Database configuration
const dbConfig = {
    host: 'localhost',
    port: 3306,
    user: 'nimdas',
    password: 'FormR!1234',
    database: 'secureaccess2',
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

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        database: 'connected'
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

// Get all users
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

// Get specific user by ID
app.get('/api/users/:id', adminAccess, async (req, res) => {
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

// Create new user
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

// Update user - FIXED VERSION WITH ENHANCED LOGGING
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

// Delete user and related records
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

// Debug endpoint for security answers
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

// Reset password for a single user
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

// Bulk fix passwords for users with NULL password_hash
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

// Login endpoint (for authentication)
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
        
        // Update last login timestamp
        await pool.execute(
            'UPDATE sa_users SET last_login_timestamp = CURRENT_TIMESTAMP WHERE user_id = ?',
            [user.user_id]
        );
        
        console.log(`✅ Login successful for user: ${username}`);
        
        // Return user info (excluding sensitive data)
        const { master_password_hash, ...userInfo } = user;
        
        res.json({
            success: true,
            message: 'Login successful',
            data: {
                user: userInfo,
                token: 'dummy-token-for-demo' // In production, generate proper JWT token
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

// Start server
async function startServer() {
    try {
        await initDatabase();
        
        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
            console.log(`📊 Admin page: http://localhost:${PORT}/admin-page.html`);
            console.log(`🏥 Health check: http://localhost:${PORT}/health`);
        });
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down server...');
    if (pool) {
        await pool.end();
        console.log('✅ Database connections closed');
    }
    process.exit(0);
});

// Start the server
startServer();