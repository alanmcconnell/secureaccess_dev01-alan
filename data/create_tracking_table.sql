-- Create sa_tracking_user table for application usage tracking
CREATE TABLE IF NOT EXISTS sa_tracking_user (
    tracking_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    application_id INT NOT NULL,
    access_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES sa_users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (application_id) REFERENCES sa_applications(application_id) ON DELETE CASCADE,
    INDEX idx_user_app (user_id, application_id),
    INDEX idx_timestamp (access_timestamp)
);