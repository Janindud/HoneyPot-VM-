import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st


API_URL = "http://localhost:8000"

st.set_page_config(page_title="Cowrie Threat Dashboard", layout="wide")
st.title("Cowrie ML Threat Intelligence Dashboard")
st.markdown("Real-time ML-powered monitoring of SSH/Telnet brute-force attacks.")


@st.cache_data(ttl=60)
def fetch_json(endpoint):
    try:
        response = requests.get(f"{API_URL}{endpoint}", timeout=10)
        response.raise_for_status()
        return pd.DataFrame(response.json().get("data", []))
    except requests.RequestException:
        return pd.DataFrame()


active_df = fetch_json("/threats/active?time_window_minutes=60")
cluster_df = fetch_json("/attackers/clusters")
attackers_df = fetch_json("/attackers?limit=100")
forecast_df = fetch_json("/predictions?limit=24")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Active Threats", len(active_df) if not active_df.empty else 0)

with col2:
    avg_risk = round(attackers_df["risk_score"].mean(), 1) if not attackers_df.empty else 0
    st.metric("Average Risk", f"{avg_risk}/100")

with col3:
    total_clusters = len(cluster_df) if not cluster_df.empty else 0
    st.metric("Risk Clusters", total_clusters)

with col4:
    predicted = 0
    if not forecast_df.empty and "predicted_volume" in forecast_df:
        forecast_df["target_time"] = pd.to_datetime(forecast_df["target_time"])
        forecast_df = forecast_df.sort_values("target_time")
        predicted = int(forecast_df.iloc[0]["predicted_volume"])
    st.metric("Next Hour Prediction", predicted)

st.divider()

c1, c2 = st.columns(2)

with c1:
    st.subheader("Attacker Risk Clusters")
    if not cluster_df.empty:
        fig = px.pie(
            cluster_df,
            values="attacker_count",
            names="cluster_group",
            title="K-Means Cluster Distribution",
            hole=0.4,
            hover_data=["avg_risk"],
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No cluster data available. Run the clustering pipeline.")

with c2:
    st.subheader("Highest Risk IPs")
    if not attackers_df.empty:
        top_risk = attackers_df.nlargest(10, "risk_score")
        fig = px.bar(
            top_risk,
            x="ip_address",
            y="risk_score",
            color="cluster_group",
            title="Top 10 IPs by Risk Score",
            labels={"ip_address": "Source IP", "risk_score": "Risk Score"},
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No attacker data available.")

st.divider()

st.subheader("Active Threats Last 60 Minutes")
if not active_df.empty:
    st.dataframe(active_df, use_container_width=True)
else:
    st.success("No active threats detected in the last hour.")

st.subheader("Future Attack Predictions")
if not forecast_df.empty:
    display_columns = [
        column
        for column in [
            "target_time",
            "horizon_hours",
            "predicted_volume",
            "confidence_lower",
            "confidence_upper",
            "risk_level",
            "model_name",
        ]
        if column in forecast_df.columns
    ]
    st.dataframe(forecast_df[display_columns], use_container_width=True)

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=forecast_df["target_time"],
            y=forecast_df["predicted_volume"],
            mode="lines+markers",
            name="Predicted attacks",
        )
    )
    if {"confidence_lower", "confidence_upper"}.issubset(forecast_df.columns):
        fig.add_trace(
            go.Scatter(
                x=forecast_df["target_time"],
                y=forecast_df["confidence_upper"],
                mode="lines",
                line={"width": 0},
                name="Upper estimate",
                showlegend=False,
            )
        )
        fig.add_trace(
            go.Scatter(
                x=forecast_df["target_time"],
                y=forecast_df["confidence_lower"],
                mode="lines",
                line={"width": 0},
                fill="tonexty",
                fillcolor="rgba(31, 78, 121, 0.18)",
                name="Confidence range",
            )
        )
    fig.update_layout(
        title="Next 24 Hours Forecast",
        xaxis_title="Predicted Hour",
        yaxis_title="Attack Attempts",
        hovermode="x unified",
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No predictions available. Run the forecast pipeline.")
