import math
import os
import uuid
from datetime import datetime, timedelta

import mysql.connector
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler


DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "cowrie_user"),
    "password": os.getenv("DB_PASSWORD", "cowrie_pass"),
    "database": os.getenv("DB_NAME", "cowrie_prod"),
}

SEQUENCE_LENGTH = int(os.getenv("LSTM_SEQUENCE_LENGTH", "24"))
LSTM_EPOCHS = int(os.getenv("LSTM_EPOCHS", "10"))
FORECAST_HOURS = int(os.getenv("FORECAST_HOURS", "24"))
MIN_LSTM_POINTS = int(os.getenv("MIN_LSTM_POINTS", str(SEQUENCE_LENGTH * 3)))
MEDIUM_ATTACK_THRESHOLD = int(os.getenv("MEDIUM_ATTACK_THRESHOLD", "20"))
HIGH_ATTACK_THRESHOLD = int(os.getenv("HIGH_ATTACK_THRESHOLD", "50"))


PREDICTION_COLUMNS = {
    "forecast_run_id": "VARCHAR(36) NULL",
    "horizon_hours": "INT NULL",
    "model_name": "VARCHAR(64) NULL",
    "confidence_lower": "INT NULL",
    "confidence_upper": "INT NULL",
    "risk_level": "VARCHAR(20) NULL",
    "note": "VARCHAR(255) NULL",
}


def fetch_hourly_data():
    conn = mysql.connector.connect(**DB_CONFIG)
    query = """
        SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') AS hour,
               COUNT(*) AS attack_volume
        FROM auth_attempts
        GROUP BY hour
        ORDER BY hour ASC
    """
    df = pd.read_sql(query, conn)
    conn.close()
    if df.empty:
        return df

    df["hour"] = pd.to_datetime(df["hour"])
    now_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
    end_hour = max(df["hour"].max().to_pydatetime(), now_hour)
    full_index = pd.date_range(df["hour"].min(), end_hour, freq="h")
    return (
        df.set_index("hour")
        .reindex(full_index, fill_value=0)
        .rename_axis("hour")
        .reset_index()
    )


def ensure_prediction_schema(conn):
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'predictions'
        """
    )
    existing_columns = {row[0] for row in cursor.fetchall()}

    for column, definition in PREDICTION_COLUMNS.items():
        if column not in existing_columns:
            cursor.execute(f"ALTER TABLE predictions ADD COLUMN {column} {definition}")

    cursor.execute(
        """
        SELECT INDEX_NAME
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'predictions'
        """
    )
    existing_indexes = {row[0] for row in cursor.fetchall()}
    if "idx_forecast_run_id" not in existing_indexes:
        cursor.execute("CREATE INDEX idx_forecast_run_id ON predictions (forecast_run_id)")
    if "idx_created_at" not in existing_indexes:
        cursor.execute("CREATE INDEX idx_created_at ON predictions (created_at)")

    conn.commit()
    cursor.close()


def build_sequences(data, sequence_length):
    x_values, y_values = [], []
    for i in range(len(data) - sequence_length):
        x_values.append(data[i : i + sequence_length, 0])
        y_values.append(data[i + sequence_length, 0])
    return np.array(x_values), np.array(y_values)


def forecast_start_hour(df):
    now_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
    if df.empty:
        return now_hour
    return max(df["hour"].max().to_pydatetime(), now_hour)


def target_hours(df, forecast_hours):
    start_hour = forecast_start_hour(df)
    return [start_hour + timedelta(hours=i) for i in range(1, forecast_hours + 1)]


def classify_risk(predicted_volume, recent_average):
    if predicted_volume >= HIGH_ATTACK_THRESHOLD:
        return "High"
    if recent_average > 0 and predicted_volume >= recent_average * 2 and predicted_volume >= MEDIUM_ATTACK_THRESHOLD:
        return "High"
    if predicted_volume >= MEDIUM_ATTACK_THRESHOLD:
        return "Medium"
    if recent_average > 0 and predicted_volume >= recent_average * 1.5 and predicted_volume >= 5:
        return "Medium"
    return "Low"


def confidence_bounds(prediction, error, horizon):
    widening = 1 + (math.sqrt(max(horizon, 1)) * 0.12)
    spread = max(1, int(round(error * widening)))
    lower = max(0, int(prediction) - spread)
    upper = int(prediction) + spread
    return lower, upper


def recent_error_estimate(df):
    if df.empty:
        return 1
    values = df["attack_volume"].astype(float)
    recent = values.tail(min(24, len(values)))
    if len(recent) < 2:
        return max(1, math.sqrt(max(recent.iloc[-1], 1)))
    return max(1, float(recent.std()), math.sqrt(max(float(recent.mean()), 1)))


def weighted_baseline_forecast(df, forecast_hours):
    if df.empty:
        targets = target_hours(df, forecast_hours)
        return [
            {
                "target_time": target,
                "horizon_hours": horizon,
                "predicted_volume": 0,
                "confidence_lower": 0,
                "confidence_upper": 1,
                "risk_level": "Low",
            }
            for horizon, target in enumerate(targets, start=1)
        ]

    values = df["attack_volume"].astype(float)
    recent_window = values.tail(min(6, len(values)))
    previous_window = values.iloc[max(0, len(values) - 12) : max(0, len(values) - 6)]
    recent_average = float(recent_window.mean())
    previous_average = float(previous_window.mean()) if not previous_window.empty else recent_average
    trend = recent_average - previous_average
    global_average = float(values.mean())
    ewma_value = float(values.ewm(span=min(12, max(3, len(values))), adjust=False).mean().iloc[-1])
    error = recent_error_estimate(df)

    forecasts = []
    for horizon, target in enumerate(target_hours(df, forecast_hours), start=1):
        seasonal = df.loc[df["hour"].dt.hour == target.hour, "attack_volume"].astype(float)
        seasonal_average = float(seasonal.mean()) if not seasonal.empty else recent_average
        trend_adjustment = trend / math.sqrt(horizon)
        prediction = (
            recent_average * 0.40
            + ewma_value * 0.25
            + seasonal_average * 0.25
            + global_average * 0.10
            + trend_adjustment
        )
        prediction = max(0, int(round(prediction)))
        lower, upper = confidence_bounds(prediction, error, horizon)
        forecasts.append(
            {
                "target_time": target,
                "horizon_hours": horizon,
                "predicted_volume": prediction,
                "confidence_lower": lower,
                "confidence_upper": upper,
                "risk_level": classify_risk(prediction, recent_average),
            }
        )
    return forecasts


def lstm_forecast(df, forecast_hours):
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    from tensorflow.keras.models import Sequential

    scaler = MinMaxScaler(feature_range=(0, 1))
    scaled_volumes = scaler.fit_transform(df[["attack_volume"]].values)
    x_values, y_values = build_sequences(scaled_volumes, SEQUENCE_LENGTH)
    x_values = np.reshape(x_values, (x_values.shape[0], x_values.shape[1], 1))

    model = Sequential(
        [
            LSTM(units=64, return_sequences=True, input_shape=(x_values.shape[1], 1)),
            Dropout(0.2),
            LSTM(units=32),
            Dropout(0.2),
            Dense(units=1),
        ]
    )
    model.compile(optimizer="adam", loss="mean_squared_error")
    model.fit(x_values, y_values, epochs=LSTM_EPOCHS, batch_size=16, verbose=0)

    train_predictions = model.predict(x_values, verbose=0)
    actual_values = scaler.inverse_transform(y_values.reshape(-1, 1)).ravel()
    predicted_values = scaler.inverse_transform(train_predictions).ravel()
    mae = float(np.mean(np.abs(actual_values - predicted_values))) if len(actual_values) else recent_error_estimate(df)
    error = max(1, mae)

    current_sequence = scaled_volumes[-SEQUENCE_LENGTH:].reshape(1, SEQUENCE_LENGTH, 1)
    future_scaled = []
    for _ in range(forecast_hours):
        next_scaled = float(model.predict(current_sequence, verbose=0)[0][0])
        next_scaled = float(np.clip(next_scaled, 0, 1))
        future_scaled.append(next_scaled)
        current_sequence = np.append(current_sequence[:, 1:, :], [[[next_scaled]]], axis=1)

    predictions = scaler.inverse_transform(np.array(future_scaled).reshape(-1, 1)).ravel()
    recent_average = float(df["attack_volume"].tail(min(6, len(df))).mean())

    forecasts = []
    for horizon, (target, prediction) in enumerate(zip(target_hours(df, forecast_hours), predictions), start=1):
        prediction = max(0, int(round(float(prediction))))
        lower, upper = confidence_bounds(prediction, error, horizon)
        forecasts.append(
            {
                "target_time": target,
                "horizon_hours": horizon,
                "predicted_volume": prediction,
                "confidence_lower": lower,
                "confidence_upper": upper,
                "risk_level": classify_risk(prediction, recent_average),
            }
        )
    return forecasts


def save_forecasts(forecasts, model_name, note):
    forecast_run_id = str(uuid.uuid4())
    created_at = datetime.now().replace(microsecond=0)
    conn = mysql.connector.connect(**DB_CONFIG)
    ensure_prediction_schema(conn)
    cursor = conn.cursor()
    rows = [
        (
            forecast_run_id,
            forecast["horizon_hours"],
            forecast["target_time"].strftime("%Y-%m-%d %H:%M:%S"),
            int(forecast["predicted_volume"]),
            model_name,
            int(forecast["confidence_lower"]),
            int(forecast["confidence_upper"]),
            forecast["risk_level"],
            note[:255],
            created_at.strftime("%Y-%m-%d %H:%M:%S"),
        )
        for forecast in forecasts
    ]
    cursor.executemany(
        """
        INSERT INTO predictions (
            forecast_run_id, horizon_hours, hour_target, predicted_volume,
            model_name, confidence_lower, confidence_upper, risk_level, note, created_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        rows,
    )
    conn.commit()
    cursor.close()
    conn.close()
    return forecast_run_id


def print_summary(forecasts, model_name, forecast_run_id):
    print(f"{model_name.upper()} FORECAST RUN: {forecast_run_id}")
    print("hour_target           horizon  predicted  range       risk")
    for forecast in forecasts:
        print(
            f"{forecast['target_time']:%Y-%m-%d %H:%M:%S}  "
            f"{forecast['horizon_hours']:>3}h      "
            f"{forecast['predicted_volume']:>5}      "
            f"{forecast['confidence_lower']}-{forecast['confidence_upper']:<7} "
            f"{forecast['risk_level']}"
        )


def train_and_forecast_lstm():
    print("Fetching hourly Cowrie attack volume...")
    df = fetch_hourly_data()
    forecast_hours = max(1, FORECAST_HOURS)
    model_name = "weighted_baseline"
    note = "Weighted recent, EWMA, hourly-seasonal, global-average, and trend forecast."

    if len(df) >= max(MIN_LSTM_POINTS, SEQUENCE_LENGTH + 2):
        try:
            forecasts = lstm_forecast(df, forecast_hours)
            model_name = "lstm_recursive"
            note = "Recursive LSTM multi-hour forecast with confidence estimated from training error."
        except ImportError:
            forecasts = weighted_baseline_forecast(df, forecast_hours)
            note = "TensorFlow unavailable; used weighted baseline forecast."
        except Exception as exc:
            forecasts = weighted_baseline_forecast(df, forecast_hours)
            note = f"LSTM failed ({exc}); used weighted baseline forecast."
    else:
        forecasts = weighted_baseline_forecast(df, forecast_hours)
        note = "Small dataset; used weighted baseline forecast."

    forecast_run_id = save_forecasts(forecasts, model_name, note)
    print_summary(forecasts, model_name, forecast_run_id)
    return forecasts[0]["predicted_volume"] if forecasts else 0


if __name__ == "__main__":
    train_and_forecast_lstm()
