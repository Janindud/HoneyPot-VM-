import json
from pathlib import Path


DASHBOARD_ROOT = Path("/var/lib/grafana/dashboards")
DEFAULT_DASHBOARD = DASHBOARD_ROOT / "cowrie" / "cowrie-ml-soc-dashboard.json"
LIVE_REFRESH = "10s"
LIVE_TIME_FROM = "now-1h"


STABLE_SQL = {
    "active attacks over time": (
        "SELECT $__timeGroupAlias(s.start_time, '5m'), COUNT(*) AS attacks "
        "FROM sessions s "
        "WHERE $__timeFilter(s.start_time) "
        "GROUP BY 1 "
        "ORDER BY 1"
    ),
    "top high-risk hacking ips": (
        "SELECT "
        "a.src_ip, "
        "ROUND(a.risk_score, 2) AS ml_risk_score, "
        "COUNT(s.session_id) AS attack_count, "
        "a.cluster_group, "
        "COALESCE(a.country, 'Unknown') AS country "
        "FROM attackers a "
        "JOIN sessions s ON a.ip_id = s.ip_id AND $__timeFilter(s.start_time) "
        "GROUP BY a.ip_id, a.src_ip, a.risk_score, a.cluster_group, a.country "
        "ORDER BY a.risk_score DESC, attack_count DESC "
        "LIMIT 10"
    ),
    "top targeted usernames": (
        "SELECT aa.username, COUNT(*) AS attempts "
        "FROM auth_attempts aa "
        "WHERE $__timeFilter(aa.timestamp) "
        "GROUP BY aa.username "
        "ORDER BY attempts DESC "
        "LIMIT 10"
    ),
    "successful logins last 5m": (
        "SELECT COUNT(*) AS successful_logins_last_5m "
        "FROM auth_attempts aa "
        "WHERE aa.is_success = 1 "
        "AND aa.timestamp >= (NOW() - INTERVAL 5 MINUTE)"
    ),
    "countries attacking this vm": (
        "SELECT "
        "COALESCE(a.country, 'Unknown') AS country, "
        "COUNT(DISTINCT a.src_ip) AS attacker_ips, "
        "COUNT(s.session_id) AS attack_sessions, "
        "ROUND(AVG(a.risk_score), 2) AS avg_risk "
        "FROM sessions s "
        "JOIN attackers a ON s.ip_id = a.ip_id "
        "WHERE $__timeFilter(s.start_time) "
        "GROUP BY COALESCE(a.country, 'Unknown') "
        "ORDER BY attack_sessions DESC, attacker_ips DESC "
        "LIMIT 10"
    ),
    "latest cowrie login attempts": (
        "SELECT "
        "aa.timestamp, "
        "a.src_ip, "
        "COALESCE(a.country, 'Unknown') AS country, "
        "aa.username, "
        "aa.password, "
        "CASE WHEN aa.is_success = 1 THEN 'success' ELSE 'failed' END AS result "
        "FROM auth_attempts aa "
        "JOIN sessions s ON aa.session_id = s.session_id "
        "JOIN attackers a ON s.ip_id = a.ip_id "
        "WHERE $__timeFilter(aa.timestamp) "
        "ORDER BY aa.timestamp DESC "
        "LIMIT 20"
    ),
    "commands captured in honeypot": (
        "SELECT "
        "c.timestamp, "
        "a.src_ip, "
        "COALESCE(a.country, 'Unknown') AS country, "
        "c.input AS command "
        "FROM commands c "
        "JOIN sessions s ON c.session_id = s.session_id "
        "JOIN attackers a ON s.ip_id = a.ip_id "
        "WHERE $__timeFilter(c.timestamp) "
        "ORDER BY c.timestamp DESC "
        "LIMIT 30"
    ),
    "risk clusters": (
        "SELECT "
        "CASE "
        "WHEN a.cluster_group = -1 THEN 'New / not clustered' "
        "ELSE CONCAT('Cluster ', a.cluster_group) "
        "END AS cluster, "
        "CASE "
        "WHEN a.cluster_group = -1 THEN 'Unprocessed' "
        "WHEN AVG(a.risk_score) >= 50 THEN 'High' "
        "WHEN AVG(a.risk_score) >= 20 THEN 'Medium' "
        "WHEN AVG(a.risk_score) > 0 THEN 'Low' "
        "ELSE 'Unprocessed' "
        "END AS risk_level, "
        "COUNT(DISTINCT a.src_ip) AS attacker_ips, "
        "COALESCE(SUM(sc.session_count), 0) AS sessions, "
        "ROUND(AVG(a.risk_score), 2) AS avg_risk, "
        "ROUND(MAX(a.risk_score), 2) AS max_risk "
        "FROM attackers a "
        "LEFT JOIN ("
        "  SELECT ip_id, COUNT(*) AS session_count "
        "  FROM sessions "
        "  WHERE $__timeFilter(start_time) "
        "  GROUP BY ip_id"
        ") sc ON sc.ip_id = a.ip_id "
        "WHERE a.cluster_group IS NOT NULL "
        "GROUP BY a.cluster_group "
        "ORDER BY avg_risk DESC, attacker_ips DESC "
        "LIMIT 10"
    ),
    "next hour attack prediction": (
        "SELECT predicted_volume AS predicted_attacks_next_hour "
        "FROM predictions "
        "WHERE forecast_run_id = ("
        "  SELECT forecast_run_id "
        "  FROM predictions "
        "  WHERE forecast_run_id IS NOT NULL "
        "  ORDER BY created_at DESC, prediction_id DESC "
        "  LIMIT 1"
        ") "
        "ORDER BY "
        "CASE WHEN hour_target > NOW() THEN 0 ELSE 1 END, "
        "CASE WHEN hour_target > NOW() THEN hour_target END ASC, "
        "hour_target DESC "
        "LIMIT 1"
    ),
    "future attack prediction": (
        "SELECT "
        "hour_target AS predicted_hour, "
        "horizon_hours, "
        "predicted_volume AS predicted_attacks, "
        "confidence_lower AS low_estimate, "
        "confidence_upper AS high_estimate, "
        "risk_level, "
        "model_name "
        "FROM predictions "
        "WHERE forecast_run_id = ("
        "  SELECT forecast_run_id "
        "  FROM predictions "
        "  WHERE forecast_run_id IS NOT NULL "
        "  ORDER BY created_at DESC, prediction_id DESC "
        "  LIMIT 1"
        ") "
        "AND hour_target > NOW() "
        "ORDER BY hour_target ASC "
        "LIMIT 24"
    ),
}


def normalize_title(title):
    return " ".join(str(title or "").lower().split())


def dashboard_files():
    if DASHBOARD_ROOT.exists():
        files = [
            path
            for path in DASHBOARD_ROOT.rglob("*.json")
            if path.is_file() and "cowrie" in path.read_text(errors="ignore").lower()
        ]
        if files:
            return files
    return [DEFAULT_DASHBOARD]


def unwrap_dashboard(document):
    dashboard = document.get("dashboard") if isinstance(document, dict) else None
    if isinstance(dashboard, dict):
        return dashboard
    return document


def panel_entries(dashboard):
    for panel in dashboard.get("panels", []) or []:
        yield panel.get("title"), panel

    for element in (dashboard.get("elements") or {}).values():
        if not isinstance(element, dict):
            continue
        spec = element.get("spec") or {}
        if element.get("kind") == "Panel" or "title" in spec:
            yield spec.get("title"), element


def legacy_targets(panel):
    for target in panel.get("targets", []) or []:
        if isinstance(target, dict) and "rawSql" in target:
            yield target


def schema_v2_queries(element):
    spec = element.get("spec") or {}
    data = spec.get("data") or {}
    query_group = data.get("spec") or {}
    for query in query_group.get("queries", []) or []:
        q_spec = query.get("spec") or {}
        data_query = q_spec.get("query") or {}
        data_query_spec = data_query.get("spec") or {}
        if "rawSql" in data_query_spec:
            yield data_query_spec


def set_panel_sql(panel, sql):
    changed = 0
    for target in legacy_targets(panel):
        target["rawSql"] = sql
        target["rawQuery"] = True
        changed += 1

    for query_spec in schema_v2_queries(panel):
        query_spec["rawSql"] = sql
        query_spec["rawQuery"] = True
        changed += 1

    return changed


def choose_sql(title):
    normalized = normalize_title(title)
    for key, sql in STABLE_SQL.items():
        if normalized == key or normalized.startswith(key):
            return sql
    return None


def set_dashboard_time(dashboard):
    dashboard["refresh"] = LIVE_REFRESH
    dashboard["time"] = {"from": LIVE_TIME_FROM, "to": "now"}

    time_settings = dashboard.setdefault("timeSettings", {})
    time_settings["autoRefresh"] = LIVE_REFRESH
    time_settings["from"] = LIVE_TIME_FROM
    time_settings["to"] = "now"
    time_settings["timezone"] = time_settings.get("timezone", "browser")


def stabilize(path):
    original_text = path.read_text()
    document = json.loads(original_text)
    dashboard = unwrap_dashboard(document)

    changed = 0
    set_dashboard_time(dashboard)
    changed += 1

    for title, panel in panel_entries(dashboard):
        sql = choose_sql(title)
        if sql:
            changed += set_panel_sql(panel, sql)

    if isinstance(dashboard.get("version"), int):
        dashboard["version"] += 1

    backup = path.with_suffix(path.suffix + ".backup-before-stable")
    if not backup.exists():
        backup.write_text(original_text)

    path.write_text(json.dumps(document, indent=2))
    return changed


def main():
    updated = []
    for path in dashboard_files():
        if not path.exists():
            continue
        changed = stabilize(path)
        updated.append((path, changed))

    if not updated:
        raise SystemExit("No Cowrie Grafana dashboard JSON files found.")

    for path, changed in updated:
        print(f"stabilized {path} ({changed} fields updated)")


if __name__ == "__main__":
    main()
