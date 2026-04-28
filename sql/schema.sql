CREATE DATABASE IF NOT EXISTS auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE auth_db;

CREATE TABLE users (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    email        VARCHAR(180) NOT NULL UNIQUE,
    password     VARCHAR(255) NOT NULL,
    is_active    TINYINT(1) NOT NULL DEFAULT 1,
    is_verified  TINYINT(1) NOT NULL DEFAULT 0,
    avatar_color VARCHAR(7) DEFAULT '#6c63ff',
    last_login   DATETIME DEFAULT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- OTP codes for email verify + password reset
CREATE TABLE otp_codes (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email      VARCHAR(180) NOT NULL,
    code       VARCHAR(6) NOT NULL,
    type       ENUM('verify_email','reset_password') NOT NULL,
    expires_at DATETIME NOT NULL,
    used       TINYINT(1) NOT NULL DEFAULT 0,
    attempts   TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email_type (email, type),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB;

-- Brute force protection
CREATE TABLE login_attempts (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address   VARCHAR(45) NOT NULL,
    email        VARCHAR(180) DEFAULT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_time (attempted_at)
) ENGINE=InnoDB;

-- Active sessions log
CREATE TABLE sessions (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id    INT UNSIGNED NOT NULL,
    ip_address VARCHAR(45) DEFAULT NULL,
    user_agent VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Default test user (password: Test@1234)
INSERT INTO users (name, email, password, is_active, is_verified, avatar_color) VALUES
('Muhammad Hamza', 'admin@test.com', '$2b$12$lEB47ZdTEXx2OKJVl6dSdO3l8fT0ajxI7z5pNtvYGGfBNOhmQ4GSq', 1, 1, '#6c63ff');
