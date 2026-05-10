import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import mysql.connector
from mysql.connector import pooling
from functools import lru_cache
from datetime import datetime
import uvicorn

# ==========================================
# APP INITIALIZATION
# ==========================================
app = FastAPI(title="Cowrie Threat Intelligence API", version="2.0")

# Enable CORS for dashboards (Streamlit/Grafana)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# DATABASE CONNECTION POOLING
# ==========================================
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "cowrie_user"),
    "password": os.getenv("DB_PASSWORD", "cowrie_pass"),
    "database": os.getenv("DB_NAME", "cowrie_prod"),
    "pool_name": "cowrie_pool",
    "pool_size": 10
}

try:
    # Initialize a connection pool to avoid opening a new connection per request
    db_pool = mysql.connector.pooling.MySQLConnectionPool(**DB_CONFIG)
except Exception as e:
    print(f"CRITICAL: Error initializing database connection pool: {e}")
    db_pool = None

def get_db_connection():
    """Helper function to fetch a connection from the pool."""
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database connection pool unavailable.")
    try:
        return db_pool.get_connection()
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Database connection error: {err}")

# ==========================================
# UTILITY FUNCTIONS
# ==========================================
def serialize_datetime(obj):
    """Recursively converts datetime objects to ISO strings for JSON serialization."""
    if isinstance(obj, list):
        return [serialize_datetime(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in obj.items()}
    return obj

def get_table_columns(conn, table_name: str):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
        """,
        (table_name,),
    )
    columns = {row[0] for row in cursor.fetchall()}
    cursor.close()
    return columns

# ==========================================
# API ENDPOINTS
# ==========================================
@app.get("/")
def read_root():
    return {"status": "success", "message": "Cowrie Threat Intelligence API v2 is running"}

@app.get("/attackers")
def get_attackers(limit: int = Query(50, ge=1, le=1000), offset: int = Query(0, ge=0)):
    """Fetch paginated list of attackers sorted by risk score."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        # Consistently use src_ip aliased as ip_address
        query = """
            SELECT ip_id, src_ip AS ip_address, first_seen, last_seen, country, 
                   cluster_group, risk_score 
            FROM attackers 
            ORDER BY risk_score DESC 
            LIMIT %s OFFSET %s
        """
        cursor.execute(query, (limit, offset))
        results = cursor.fetchall()
        return {"status": "success", "data": serialize_datetime(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.get("/attackers/clusters")
@lru_cache(maxsize=1)
def get_clusters_cached():
    """Calculates cluster demographics. Cached to prevent heavy group-by queries."""
    return fetch_clusters()

def fetch_clusters():
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT cluster_group, COUNT(*) as attacker_count, AVG(risk_score) as avg_risk 
            FROM attackers 
            WHERE cluster_group IS NOT NULL 
            GROUP BY cluster_group
            ORDER BY cluster_group ASC
        """
        cursor.execute(query)
        results = cursor.fetchall()
        return {"status": "success", "data": serialize_datetime(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.get("/threats/active")
def get_active_threats(time_window_minutes: int = Query(60, ge=1, le=1440)):
    """
    Returns attackers active within the specified timeframe.
    Improved to include recent command activity via JOINs, not just session starts.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT DISTINCT a.src_ip AS ip_address, a.country, a.risk_score, a.cluster_group,
                            MAX(s.start_time) as last_session_time,
                            MAX(c.timestamp) as last_command_time
            FROM attackers a
            JOIN sessions s ON a.ip_id = s.ip_id
            LEFT JOIN commands c ON s.session_id = c.session_id
            WHERE s.start_time >= NOW() - INTERVAL %s MINUTE
               OR c.timestamp >= NOW() - INTERVAL %s MINUTE
            GROUP BY a.src_ip, a.country, a.risk_score, a.cluster_group
            ORDER BY a.risk_score DESC
        """
        cursor.execute(query, (time_window_minutes, time_window_minutes))
        results = cursor.fetchall()
        return {"status": "success", "data": serialize_datetime(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.get("/predictions")
def get_predictions(limit: int = Query(24, ge=1, le=168)):
    """Fetch the latest forecast run for the dashboard."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        columns = get_table_columns(conn, "predictions")
        supports_enhanced_forecast = "forecast_run_id" in columns

        if supports_enhanced_forecast:
            cursor.execute(
                """
                SELECT forecast_run_id
                FROM predictions
                WHERE forecast_run_id IS NOT NULL
                ORDER BY created_at DESC, prediction_id DESC
                LIMIT 1
                """
            )
            latest_run = cursor.fetchone()
            if latest_run and latest_run["forecast_run_id"]:
                optional_fields = [
                    "forecast_run_id",
                    "horizon_hours",
                    "model_name",
                    "confidence_lower",
                    "confidence_upper",
                    "risk_level",
                    "note",
                    "created_at",
                ]
                select_fields = [
                    "prediction_id",
                    "hour_target AS target_time",
                    "predicted_volume",
                ]
                select_fields.extend(field for field in optional_fields if field in columns)
                query = f"""
                    SELECT {", ".join(select_fields)}
                    FROM predictions
                    WHERE forecast_run_id = %s
                    ORDER BY COALESCE(horizon_hours, 999999), hour_target ASC
                    LIMIT %s
                """
                cursor.execute(query, (latest_run["forecast_run_id"], limit))
            else:
                cursor.execute(
                    """
                    SELECT prediction_id, hour_target AS target_time, predicted_volume, created_at
                    FROM predictions
                    ORDER BY hour_target DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
        else:
            cursor.execute(
                """
                SELECT prediction_id, hour_target AS target_time, predicted_volume, created_at
                FROM predictions
                ORDER BY hour_target DESC
                LIMIT %s
                """,
                (limit,),
            )
        results = cursor.fetchall()
        return {"status": "success", "data": serialize_datetime(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
