import os
import time
from ipaddress import ip_address

import mysql.connector
import requests

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "cowrie_user"),
    "password": os.getenv("DB_PASSWORD", "cowrie_pass"),
    "database": os.getenv("DB_NAME", "cowrie_prod"),
}

IP_API_URL = os.getenv("IP_API_URL", "http://ip-api.com/batch")
IP_API_BATCH_SIZE = int(os.getenv("IP_API_BATCH_SIZE", "100"))


def is_public_ip(value):
    try:
        parsed = ip_address(value)
    except ValueError:
        return False

    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def fetch_attackers(cursor):
    cursor.execute(
        """
        SELECT src_ip
        FROM attackers
        WHERE src_ip IS NOT NULL
          AND (country IS NULL OR country = '' OR country = 'Unknown')
        ORDER BY last_seen DESC
        """
    )
    return [row[0] for row in cursor.fetchall() if is_public_ip(row[0])]


def fetch_geo_batch(ips):
    fields = "status,message,country,countryCode,city,lat,lon,isp,org,as,query"
    payload = [{"query": ip, "fields": fields} for ip in ips]
    response = requests.post(IP_API_URL, json=payload, timeout=20)
    response.raise_for_status()
    return response.json()


def ensure_schema(cursor):
    cursor.execute(
        """
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
        )
        """
    )


def upsert_geo(cursor, item):
    ip = item.get("query")
    country = item.get("country") or "Unknown"
    if country == "The Netherlands":
        country = "Netherlands"
    country_code = item.get("countryCode") or ""
    city = item.get("city") or "Unknown"
    latitude = item.get("lat")
    longitude = item.get("lon")
    isp = item.get("isp") or "Unknown"
    organization = item.get("org") or "Unknown"
    asn = item.get("as") or "Unknown"

    cursor.execute(
        """
        INSERT INTO attacker_geolocation
            (src_ip, country, country_code, city, latitude, longitude, isp, organization, asn)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            country = VALUES(country),
            country_code = VALUES(country_code),
            city = VALUES(city),
            latitude = VALUES(latitude),
            longitude = VALUES(longitude),
            isp = VALUES(isp),
            organization = VALUES(organization),
            asn = VALUES(asn)
        """,
        (ip, country, country_code, city, latitude, longitude, isp, organization, asn),
    )
    cursor.execute(
        """
        UPDATE attackers
        SET country = %s, isp = %s
        WHERE src_ip = %s
        """,
        (country, isp, ip),
    )


def run_geolocation():
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    ensure_schema(cursor)
    ips = fetch_attackers(cursor)
    if not ips:
        print("No unknown public attacker IPs to geolocate.")
        cursor.close()
        conn.close()
        return

    updated = 0
    for index in range(0, len(ips), IP_API_BATCH_SIZE):
        batch = ips[index : index + IP_API_BATCH_SIZE]
        print(f"Resolving countries for {len(batch)} attacker IPs...")
        for item in fetch_geo_batch(batch):
            if item.get("status") != "success":
                print(f"Skipping {item.get('query')}: {item.get('message', 'lookup failed')}")
                continue
            upsert_geo(cursor, item)
            updated += 1
        conn.commit()
        time.sleep(1)

    cursor.close()
    conn.close()
    print(f"Updated geolocation for {updated} attacker IPs.")


if __name__ == "__main__":
    run_geolocation()
