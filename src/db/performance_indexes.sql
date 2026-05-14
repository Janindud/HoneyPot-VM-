USE cowrie_prod;

DROP PROCEDURE IF EXISTS add_index_if_missing;

DELIMITER //
CREATE PROCEDURE add_index_if_missing(
    IN table_name_in VARCHAR(64),
    IN index_name_in VARCHAR(64),
    IN index_definition_in VARCHAR(255)
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = table_name_in
          AND INDEX_NAME = index_name_in
    ) THEN
        SET @sql_text = CONCAT(
            'ALTER TABLE `', table_name_in, '` ADD INDEX `',
            index_name_in, '` ', index_definition_in
        );
        PREPARE stmt FROM @sql_text;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END//
DELIMITER ;

CALL add_index_if_missing('sessions', 'idx_sessions_ip_start', '(ip_id, start_time)');
CALL add_index_if_missing('sessions', 'idx_sessions_start_ip', '(start_time, ip_id)');
CALL add_index_if_missing('auth_attempts', 'idx_auth_timestamp_session', '(timestamp, session_id)');
CALL add_index_if_missing('auth_attempts', 'idx_auth_session_timestamp', '(session_id, timestamp)');
CALL add_index_if_missing('auth_attempts', 'idx_auth_success_timestamp', '(is_success, timestamp)');
CALL add_index_if_missing('commands', 'idx_commands_timestamp_session', '(timestamp, session_id)');
CALL add_index_if_missing('commands', 'idx_commands_session_timestamp', '(session_id, timestamp)');
CALL add_index_if_missing('attackers', 'idx_attackers_risk', '(risk_score)');
CALL add_index_if_missing('attackers', 'idx_attackers_cluster_risk', '(cluster_group, risk_score)');
CALL add_index_if_missing('attackers', 'idx_attackers_country_ip', '(country, ip_id)');
CALL add_index_if_missing('predictions', 'idx_predictions_run_created', '(forecast_run_id, created_at, prediction_id)');
CALL add_index_if_missing('predictions', 'idx_predictions_run_hour', '(forecast_run_id, hour_target)');

DROP PROCEDURE IF EXISTS add_index_if_missing;
