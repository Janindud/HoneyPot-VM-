# Cowrie ML SOC Dashboard

Final year project source code for a Cowrie honeypot monitoring pipeline. The system collects Cowrie SSH/Telnet events, stores normalized attack data in MySQL, enriches attacker IPs with country information, applies ML clustering and attack forecasting, exposes results through FastAPI, and visualizes the output in Grafana or Streamlit.

Repository: `git@github.com:Janindud/HoneyPot-VM-.git`

## Main Features

- Cowrie JSON log ingestion into MySQL.
- Attacker, session, authentication attempt, command, geolocation, and prediction tables.
- Country enrichment for attacker IP addresses.
- K-Means based attacker risk clustering.
- Next-hour and next-24-hour attack prediction.
- FastAPI endpoints for dashboard consumption.
- Grafana dashboard JSON export.
- Streamlit dashboard for local testing.

## Project Structure

```text
grafana/
  dashboard.json
src/
  api/server.py
  dashboard/app.py
  db/schema.sql
  db/views.sql
  etl/backfill.py
  etl/geolocate.py
  etl/ingest.py
  ml/cluster.py
  ml/forecast.py
requirements.txt
SUBMISSION_5_DAY_PLAN.md
```

## Environment Variables

The Python services read database settings from environment variables.

```powershell
$env:DB_HOST = "localhost"
$env:DB_USER = "cowrie_user"
$env:DB_PASSWORD = "cowrie_pass"
$env:DB_NAME = "cowrie_prod"
```

## Install Dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Database Setup

```powershell
mysql -u root -p < src\db\schema.sql
mysql -u root -p cowrie_prod < src\db\views.sql
```

## Run Pipeline Components

Run these from the repository root after activating the virtual environment.

```powershell
python src\etl\ingest.py
python src\etl\geolocate.py
python src\ml\cluster.py
python src\ml\forecast.py
uvicorn src.api.server:app --host 0.0.0.0 --port 8000
streamlit run src\dashboard\app.py
```

## Main API Endpoints

- `GET /` - API health check.
- `GET /attackers` - high-risk attackers with country, cluster, and score.
- `GET /attackers/clusters` - cluster summary.
- `GET /threats/active` - attackers active in a selected time window.
- `GET /predictions` - latest next-24-hour forecast run.

## AI and ML Summary

The clustering component groups attacker IPs using K-Means features such as failed login count, successful login count, session volume, command activity, and risk score. The prediction component forecasts attack volume for the next 24 hours using an LSTM model when enough hourly data exists. If the dataset is too small or TensorFlow is unavailable, it automatically uses a weighted baseline model based on recent average, EWMA, hourly seasonality, global average, and trend.

## Authorized Testing Note

Only test this honeypot on infrastructure that you own or have explicit permission to use. The viva demo should target the project Cowrie VM only, for example by generating controlled SSH login attempts against the Cowrie port and then showing the log ingestion, ML analysis, API output, and dashboard update.
