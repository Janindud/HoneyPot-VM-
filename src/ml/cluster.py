import os
import joblib
import pandas as pd
import numpy as np
import mysql.connector
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import silhouette_score
import warnings

# Suppress sklearn warnings for clean cron output
warnings.filterwarnings('ignore', category=FutureWarning)

# ==========================================
# CONFIGURATION
# ==========================================
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'cowrie_user'),
    'password': os.getenv('DB_PASSWORD', 'cowrie_pass'),
    'database': os.getenv('DB_NAME', 'cowrie_prod')
}

MODEL_DIR = os.getenv("MODEL_DIR", os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.getenv("KMEANS_MODEL_PATH", os.path.join(MODEL_DIR, "model.pkl"))
SCALER_PATH = os.getenv("KMEANS_SCALER_PATH", os.path.join(MODEL_DIR, "scaler.pkl"))
MIN_SAMPLES_FOR_SILHOUETTE = 15

# ==========================================
# FEATURE ENGINEERING & DATA LOADING
# ==========================================
def fetch_attacker_features():
    """Extract complex behavioral features for K-Means clustering from normalized DB."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        
        # Improved Attack Frequency: Uses precise hour differences between first and last seen
        query = """
        SELECT 
            a.ip_id, 
            a.src_ip,
            COUNT(DISTINCT s.session_id) AS total_sessions,
            CAST(SUM(CASE WHEN aa.is_success = 1 THEN 1 ELSE 0 END) AS FLOAT) / NULLIF(COUNT(aa.attempt_id), 0) AS success_rate,
            IFNULL(SUM(s.duration_seconds), 0) AS total_duration,
            COUNT(c.cmd_id) AS total_commands,
            
            -- Improved Attack Frequency (sessions per hour)
            COUNT(DISTINCT s.session_id) / 
            NULLIF(TIMESTAMPDIFF(HOUR, MIN(s.start_time), MAX(s.start_time)) + 1, 0) AS attack_frequency,
            
            -- Night Activity Ratio (00:00 to 06:00 UTC)
            CAST(SUM(CASE WHEN HOUR(s.start_time) BETWEEN 0 AND 6 THEN 1 ELSE 0 END) AS FLOAT) / 
            NULLIF(COUNT(s.session_id), 0) AS night_activity_ratio
            
        FROM attackers a
        LEFT JOIN sessions s ON a.ip_id = s.ip_id
        LEFT JOIN auth_attempts aa ON s.session_id = aa.session_id
        LEFT JOIN commands c ON s.session_id = c.session_id
        GROUP BY a.ip_id, a.src_ip
        HAVING total_sessions > 0
        """
        df = pd.read_sql(query, conn)
        conn.close()
        
        # Fill missing numeric values
        df.fillna(0, inplace=True)
        return df
    except Exception as e:
        print(f"Error fetching features: {e}")
        return pd.DataFrame()

# ==========================================
# RISK SCORING
# ==========================================
def calculate_normalized_risk(df):
    """
    Normalizes highly skewed features (sessions, commands) to 0-1 range 
    before applying the weighted risk formula, preventing extreme outliers 
    from dominating the score.
    """
    # 1. Handle Extreme Outliers using Log1p (log(x+1)) to compress huge botnet spikes
    df['log_sessions'] = np.log1p(df['total_sessions'])
    df['log_commands'] = np.log1p(df['total_commands'])

    # 2. MinMax Scale the compressed features to a strict 0.0 - 1.0 range
    minmax = MinMaxScaler()
    scaled_components = minmax.fit_transform(df[['log_sessions', 'log_commands']])
    
    norm_sessions = scaled_components[:, 0]
    norm_commands = scaled_components[:, 1]
    
    # 3. Apply the requested formula (Ensure success_rate is strictly 0-1)
    success_rate = df['success_rate'].clip(lower=0.0, upper=1.0)
    
    # Formula: (sessions * 0.4) + (commands * 0.3) + (success_rate * 0.3)
    # Multiplied by 100 to return an intuitive 0-100 Score
    risk_scores = ((norm_sessions * 0.4) + (norm_commands * 0.3) + (success_rate * 0.3)) * 100
    
    df['risk_score'] = np.round(risk_scores, 2)
    
    # Clean up temporary calculation columns
    df.drop(columns=['log_sessions', 'log_commands'], inplace=True)
    return df

# ==========================================
# MACHINE LEARNING PIPELINE
# ==========================================
def optimize_kmeans(scaled_data):
    """
    Evaluate 3, 4, and 5 clusters using Silhouette Score to dynamically find 
    the best grouping, defaulting to 4 if data is too small.
    """
    if len(scaled_data) < MIN_SAMPLES_FOR_SILHOUETTE:
        cluster_count = min(4, len(scaled_data))
        print(f"Dataset too small for dynamic cluster evaluation. Defaulting to {cluster_count} clusters.")
        return KMeans(n_clusters=cluster_count, random_state=42, n_init=10).fit(scaled_data)

    best_score = -1
    best_model = None
    
    print("Evaluating optimal cluster counts (3-5)...")
    for k in range(3, 6):
        model = KMeans(n_clusters=k, random_state=42, n_init=10)
        labels = model.fit_predict(scaled_data)
        
        # Silhouette Score (-1 to 1) measures how dense and separate the clusters are
        score = silhouette_score(scaled_data, labels)
        print(f"  k={k} -> Silhouette Score: {score:.4f}")
        
        if score > best_score:
            best_score = score
            best_model = model
            
    print(f"Optimal clusters chosen: {best_model.n_clusters}")
    return best_model

def run_ml_pipeline():
    print("Starting K-Means Clustering & Scoring Pipeline...")
    
    # 1. Fetch & Validate Data
    df = fetch_attacker_features()
    if df.empty or len(df) < 2:
        print("Not enough attacker data to run clustering. Exiting.")
        return

    # 2. Risk Scoring (Normalized)
    df = calculate_normalized_risk(df)

    # 3. Model Features & Outlier Clipping (99th percentile) to tame extreme bots
    ml_features = ['total_sessions', 'success_rate', 'total_duration', 'total_commands', 'attack_frequency', 'night_activity_ratio']
    for col in ml_features:
        cap = df[col].quantile(0.99)
        df[col] = df[col].clip(upper=cap)

    # 4. StandardScaler
    print("Scaling Features (StandardScaler)...")
    if os.path.exists(SCALER_PATH):
        scaler = joblib.load(SCALER_PATH)
        scaled_data = scaler.transform(df[ml_features])
    else:
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(df[ml_features])
        joblib.dump(scaler, SCALER_PATH)

    # 5. K-Means Modeling & Optimization
    if os.path.exists(MODEL_PATH):
        print("Loading pre-trained K-Means model...")
        kmeans = joblib.load(MODEL_PATH)
        # Verify cluster count doesn't exceed data length
        if len(df) >= kmeans.n_clusters:
            df['cluster_group'] = kmeans.predict(scaled_data)
        else:
            kmeans = optimize_kmeans(scaled_data)
            df['cluster_group'] = kmeans.labels_
    else:
        print("Training new K-Means model...")
        kmeans = optimize_kmeans(scaled_data)
        df['cluster_group'] = kmeans.labels_
        joblib.dump(kmeans, MODEL_PATH)

    # 6. High-Performance Database Update
    print("Executing batch UPDATE to MySQL...")
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        update_query = """
        UPDATE attackers 
        SET cluster_group = %s, risk_score = %s 
        WHERE ip_id = %s
        """
        
        update_data = [
            (int(row['cluster_group']), float(row['risk_score']), int(row['ip_id'])) 
            for _, row in df.iterrows()
        ]
        
        cursor.executemany(update_query, update_data)
        conn.commit()
        conn.close()
        print(f"Successfully clustered and scored {len(update_data)} attackers.")
        
    except Exception as e:
        print(f"Error updating database: {e}")

if __name__ == "__main__":
    run_ml_pipeline()
