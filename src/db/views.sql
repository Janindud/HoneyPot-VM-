USE cowrie_prod;

-- 1. Create a View to simulate the old ATTACK_LOGS table
CREATE OR REPLACE VIEW ATTACK_LOGS AS
SELECT 
    aa.timestamp AS timestamp,
    a.src_ip AS src_ip,
    aa.username AS username,
    aa.password AS password
FROM auth_attempts aa
JOIN sessions s ON aa.session_id = s.session_id
JOIN attackers a ON s.ip_id = a.ip_id;

-- 2. Create a View to simulate the old IP_GEOLOCATION table
CREATE OR REPLACE VIEW IP_GEOLOCATION AS
SELECT 
    a.country AS country,
    NULL AS latitude,
    NULL AS longitude,
    COUNT(s.session_id) AS attack_count,
    a.src_ip AS ip
FROM attackers a
JOIN sessions s ON a.ip_id = s.ip_id
GROUP BY a.src_ip, a.country;
