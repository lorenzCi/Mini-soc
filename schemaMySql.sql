CREATE DATABASE IF NOT EXISTS mini_soc;
USE mini_soc;

-- =========================================================
-- TABLE: detection_rules
-- =========================================================

CREATE TABLE detection_rules (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    name VARCHAR(128) NOT NULL UNIQUE,
    description TEXT,

    enabled BOOLEAN DEFAULT TRUE,

    severity ENUM('low','medium','high','critical')
        NOT NULL DEFAULT 'medium',

    rule_type ENUM(
        'signature',
        'threshold',
        'port_scan',
        'brute_force',
        'custom'
    ) NOT NULL,

    conditions JSON NOT NULL,

    mitre_technique VARCHAR(32) NULL,

    created_at DATETIME(3)
        DEFAULT CURRENT_TIMESTAMP(3),

    updated_at DATETIME(3)
        DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),

    INDEX idx_enabled (enabled),
    INDEX idx_rule_type (rule_type)
);

-- =========================================================
-- TABLE: packets
-- =========================================================

CREATE TABLE packets (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    captured_at DATETIME(3) NOT NULL,

    src_ip VARBINARY(16),
    dst_ip VARBINARY(16),

    src_port SMALLINT UNSIGNED,
    dst_port SMALLINT UNSIGNED,

    protocol ENUM('tcp','udp','icmp','other')
        NOT NULL,

    packet_size INT UNSIGNED,

    tcp_flags VARCHAR(16),

    payload_hash CHAR(64),

    payload_preview TEXT NULL,

    created_at DATETIME(3)
        DEFAULT CURRENT_TIMESTAMP(3),

    INDEX idx_captured_at (captured_at),
    INDEX idx_src_time (src_ip, captured_at),
    INDEX idx_dst_time (dst_ip, captured_at),
    INDEX idx_port_time (dst_port, captured_at),
    INDEX idx_protocol_time (protocol, captured_at)
);

-- =========================================================
-- TABLE: users
-- =========================================================

CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,

    password_hash VARCHAR(255) NOT NULL,

    role ENUM('viewer','analyst','admin')
        DEFAULT 'analyst',

    is_active BOOLEAN DEFAULT TRUE,

    created_at DATETIME(3)
        DEFAULT CURRENT_TIMESTAMP(3),

    last_login_at DATETIME(3) NULL
);

-- =========================================================
-- TABLE: alerts
-- =========================================================

CREATE TABLE alerts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    rule_id BIGINT UNSIGNED NOT NULL,

    title VARCHAR(256) NOT NULL,
    description TEXT,

    severity ENUM('low','medium','high','critical')
        NOT NULL,

    status ENUM(
        'new',
        'acknowledged',
        'investigating',
        'closed',
        'false_positive'
    ) DEFAULT 'new',

    assigned_to BIGINT UNSIGNED NULL,

    src_ip VARBINARY(16),
    dst_ip VARBINARY(16),

    src_port SMALLINT UNSIGNED,
    dst_port SMALLINT UNSIGNED,

    protocol ENUM('tcp','udp','icmp','other'),

    event_count INT UNSIGNED DEFAULT 1,

    first_seen_at DATETIME(3) NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,

    evidence JSON NOT NULL,

    created_at DATETIME(3)
        DEFAULT CURRENT_TIMESTAMP(3),

    updated_at DATETIME(3)
        DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),

    CONSTRAINT fk_alert_rule
        FOREIGN KEY (rule_id)
        REFERENCES detection_rules(id),

    CONSTRAINT fk_alert_assigned
        FOREIGN KEY (assigned_to)
        REFERENCES users(id),

    INDEX idx_status_time (status, last_seen_at),
    INDEX idx_severity_time (severity, created_at),
    INDEX idx_rule (rule_id),
    INDEX idx_src_ip_time (src_ip, last_seen_at)
);

-- =========================================================
-- TABLE: alert_packets
-- =========================================================

CREATE TABLE alert_packets (
    alert_id BIGINT UNSIGNED NOT NULL,
    packet_id BIGINT UNSIGNED NOT NULL,

    role ENUM('trigger','related')
        DEFAULT 'trigger',

    PRIMARY KEY (alert_id, packet_id),

    CONSTRAINT fk_alert_packets_alert
        FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_alert_packets_packet
        FOREIGN KEY (packet_id)
        REFERENCES packets(id)
        ON DELETE CASCADE
);

-- =========================================================
-- TABLE: alert_actions
-- =========================================================

CREATE TABLE alert_actions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    alert_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NULL,

    action ENUM(
        'created',
        'acknowledged',
        'commented',
        'escalated',
        'closed'
    ) NOT NULL,

    comment TEXT,

    metadata JSON,

    created_at DATETIME(3)
        DEFAULT CURRENT_TIMESTAMP(3),

    CONSTRAINT fk_alert_actions_alert
        FOREIGN KEY (alert_id)
        REFERENCES alerts(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_alert_actions_user
        FOREIGN KEY (user_id)
        REFERENCES users(id),

    INDEX idx_alert_time (alert_id, created_at)
);

-- =========================================================
-- TABLE: detection_stats_hourly
-- =========================================================

CREATE TABLE detection_stats_hourly (
    bucket_hour DATETIME NOT NULL,

    rule_id BIGINT UNSIGNED NOT NULL,

    alert_count INT UNSIGNED DEFAULT 0,
    packet_count BIGINT UNSIGNED DEFAULT 0,

    PRIMARY KEY (bucket_hour, rule_id),

    CONSTRAINT fk_stats_rule
        FOREIGN KEY (rule_id)
        REFERENCES detection_rules(id),

    INDEX idx_hour (bucket_hour)
);
