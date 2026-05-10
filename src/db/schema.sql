-- Production-Scale Database Schema for Cowrie Honeypot
-- Separates entities into normalized tables for better query performance and complex feature engineering.

CREATE DATABASE IF NOT EXISTS cowrie_prod;
USE cowrie_prod;

-- Stores unique attacker IPs and their assigned geolocation/cluster metadata
CREATE TABLE IF NOT EXISTS attackers (
    ip_id INT AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(45) UNIQUE NOT NULL,
    country VARCHAR(100),
    isp VARCHAR(255),
    cluster_group INT DEFAULT -1,
    risk_score DECIMAL(5,2) DEFAULT 0.00,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_src_ip (src_ip)
);

-- Stores individual SSH sessions
CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    ip_id INT,
    start_time DATETIME,
    end_time DATETIME,
    duration_seconds INT,
    FOREIGN KEY (ip_id) REFERENCES attackers(ip_id) ON DELETE CASCADE,
    INDEX idx_start_time (start_time)
);

-- Stores brute-force authentication attempts
CREATE TABLE IF NOT EXISTS auth_attempts (
    attempt_id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64),
    timestamp DATETIME NOT NULL,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_success BOOLEAN NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE KEY uniq_auth_event (session_id, timestamp, username, password, is_success),
    INDEX idx_session (session_id),
    INDEX idx_timestamp (timestamp)
);

-- Stores shell commands executed after a successful login (High-Interaction)
CREATE TABLE IF NOT EXISTS commands (
    cmd_id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(64),
    timestamp DATETIME NOT NULL,
    input TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE KEY uniq_command_event (session_id, timestamp, input(255))
);

-- Stores forecast output used by the API/dashboard layer
CREATE TABLE IF NOT EXISTS predictions (
    prediction_id INT AUTO_INCREMENT PRIMARY KEY,
    forecast_run_id VARCHAR(36),
    horizon_hours INT,
    hour_target DATETIME NOT NULL,
    predicted_volume INT NOT NULL,
    model_name VARCHAR(64),
    confidence_lower INT,
    confidence_upper INT,
    risk_level VARCHAR(20),
    note VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_forecast_run_id (forecast_run_id),
    INDEX idx_created_at (created_at),
    INDEX idx_hour_target (hour_target)
);

-- Stores country/city enrichment for public attacker IPs
CREATE TABLE IF NOT EXISTS attacker_geolocation (
    src_ip VARCHAR(45) PRIMARY KEY,
    country VARCHAR(100),
    country_code VARCHAR(8),
    city VARCHAR(100),
    latitude DECIMAL(10,6),
    longitude DECIMAL(10,6),
    isp VARCHAR(255),
    organization VARCHAR(255),
    asn VARCHAR(255),
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (src_ip) REFERENCES attackers(src_ip) ON DELETE CASCADE
);
