const mysql = require('mysql2/promise');
require('dotenv').config();

// Create database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Connected to MySQL database successfully');
    connection.release();
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    process.exit(1);
  }
}

// Initialize database tables
async function initDatabase() {
  try {
    const connection = await pool.getConnection();
    
    // Create users table if it doesn't exist with the exact schema provided
    const createUsersTable = `
      CREATE TABLE IF NOT EXISTS sa_users (
        user_id INT NOT NULL AUTO_INCREMENT,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        master_password_hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        account_creation_date TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        last_login_timestamp TIMESTAMP NULL DEFAULT NULL,
        account_status ENUM('active','inactive','locked') DEFAULT 'active',
        security_question_1 TEXT,
        security_answer_1_hash VARCHAR(255) DEFAULT NULL,
        security_question_2 TEXT,
        security_answer_2_hash VARCHAR(255) DEFAULT NULL,
        two_factor_enabled TINYINT(1) DEFAULT '0',
        two_factor_secret VARCHAR(255) DEFAULT NULL,
        jwt_secret_version INT DEFAULT '1',
        refresh_token_rotation_enabled TINYINT(1) DEFAULT '1',
        token_expiration_minutes INT DEFAULT '60',
        created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id),
        UNIQUE KEY username (username),
        UNIQUE KEY email (email),
        KEY idx_users_email (email),
        KEY idx_users_username (username),
        KEY idx_users_status (account_status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    `;
    
    await connection.execute(createUsersTable);
    console.log('✅ Users table ready with secure schema');
    
    connection.release();
  } catch (error) {
    console.error('❌ Failed to initialize database:', error.message);
    throw error;
  }
}

module.exports = {
  pool,
  testConnection,
  initDatabase
};