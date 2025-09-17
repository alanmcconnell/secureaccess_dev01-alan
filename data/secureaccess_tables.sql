USE secureaccess;

-- Create users table
CREATE TABLE secureaccess.users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    master_password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    account_creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_timestamp TIMESTAMP NULL,
    account_status ENUM('active', 'inactive', 'locked') DEFAULT 'active',
    security_question_1 TEXT,
    security_answer_1_hash VARCHAR(255),
    security_question_2 TEXT,
    security_answer_2_hash VARCHAR(255),
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    jwt_secret_version INT DEFAULT 1,
    refresh_token_rotation_enabled BOOLEAN DEFAULT TRUE,
    token_expiration_minutes INT DEFAULT 60,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create application table
CREATE TABLE application (
    application_id INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL,
    application_name VARCHAR(255) NOT NULL,
    active_status BOOLEAN DEFAULT TRUE,
    access_granted_value VARCHAR(100),
    access_declined_value VARCHAR(100),
    website_url VARCHAR(500),
    date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create encryption_keys table
CREATE TABLE encryption_keys (
    key_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    encrypted_master_key TEXT NOT NULL,
    key_derivation_salt VARCHAR(255) NOT NULL,
    key_derivation_iterations INT DEFAULT 100000,
    creation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    key_version INT DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create stored_accounts table
CREATE TABLE stored_accounts (
    account_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    application_id INT NOT NULL,
    account_username VARCHAR(255) NOT NULL,
    account_email VARCHAR(255),
    encrypted_password TEXT NOT NULL,
    account_category VARCHAR(100),
    account_folder VARCHAR(100),
    notes TEXT,
    date_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    date_last_accessed TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (application_id) REFERENCES application(application_id) ON DELETE RESTRICT
);

-- Create user_sessions table
CREATE TABLE user_sessions (
    session_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(500) NOT NULL,
    ip_address VARCHAR(45),
    device_info TEXT,
    user_agent TEXT,
    login_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expiration_timestamp TIMESTAMP NOT NULL,
    active_status BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_session_token (session_token),
    INDEX idx_user_active (user_id, active_status)
);

-- Create jwt_tokens table
CREATE TABLE jwt_tokens (
    token_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_type ENUM('access', 'refresh') NOT NULL,
    jwt_token_hash VARCHAR(255) NOT NULL,
    jti VARCHAR(255) UNIQUE NOT NULL,
    claims_summary JSON,
    issue_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expiration_timestamp TIMESTAMP NOT NULL,
    revoked_status BOOLEAN DEFAULT FALSE,
    revocation_timestamp TIMESTAMP NULL,
    token_family_id VARCHAR(255),
    device_info TEXT,
    ip_address VARCHAR(45),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_jti (jti),
    INDEX idx_user_type (user_id, token_type),
    INDEX idx_expiration (expiration_timestamp),
    INDEX idx_family (token_family_id)
);

-- Create jwt_blacklist table
CREATE TABLE jwt_blacklist (
    blacklist_id INT AUTO_INCREMENT PRIMARY KEY,
    token_hash VARCHAR(255) NOT NULL,
    jti VARCHAR(255) NOT NULL,
    expiration_timestamp TIMESTAMP NOT NULL,
    reason_for_blacklisting VARCHAR(255),
    timestamp_blacklisted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_jti_blacklist (jti),
    INDEX idx_expiration_blacklist (expiration_timestamp)
);

-- Create audit_log table
CREATE TABLE audit_log (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    jwt_token_id INT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_account_service VARCHAR(255),
    target_resource VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success_status BOOLEAN NOT NULL,
    error_message TEXT,
    additional_data JSON,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (jwt_token_id) REFERENCES jwt_tokens(token_id) ON DELETE SET NULL,
    INDEX idx_user_timestamp (user_id, timestamp),
    INDEX idx_action_type (action_type),
    INDEX idx_timestamp (timestamp)
);

-- Create user_preferences table
CREATE TABLE user_preferences (
    preference_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    password_length INT DEFAULT 12,
    password_include_uppercase BOOLEAN DEFAULT TRUE,
    password_include_lowercase BOOLEAN DEFAULT TRUE,
    password_include_numbers BOOLEAN DEFAULT TRUE,
    password_include_symbols BOOLEAN DEFAULT TRUE,
    password_exclude_ambiguous BOOLEAN DEFAULT TRUE,
    security_timeout_minutes INT DEFAULT 15,
    auto_logout_enabled BOOLEAN DEFAULT TRUE,
    notification_login_enabled BOOLEAN DEFAULT TRUE,
    notification_password_access BOOLEAN DEFAULT FALSE,
    theme_preference VARCHAR(20) DEFAULT 'light',
    language_preference VARCHAR(10) DEFAULT 'en',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_status ON users(account_status);
CREATE INDEX idx_application_active ON application(active_status);
CREATE INDEX idx_stored_accounts_user ON stored_accounts(user_id);
CREATE INDEX idx_stored_accounts_app ON stored_accounts(application_id);
CREATE INDEX idx_encryption_keys_user ON encryption_keys(user_id, is_active);