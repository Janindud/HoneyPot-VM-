import glob
import os

import mysql.connector

from ingest import DB_CONFIG, process_event, tail_f

COWRIE_LOG_GLOB = os.getenv(
    "COWRIE_LOG_GLOB", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json*"
)


def log_sort_key(path):
    # Process rotated files first, then the currently active cowrie.json last.
    base = os.path.basename(path)
    return (base == "cowrie.json", base)


def run_backfill():
    files = sorted(glob.glob(COWRIE_LOG_GLOB), key=log_sort_key)
    if not files:
        print(f"No Cowrie JSON logs matched: {COWRIE_LOG_GLOB}")
        return

    print("Backfilling real Cowrie logs:")
    for file_path in files:
        print(f"  - {file_path}")

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    processed = 0

    try:
        for file_path in files:
            for line in tail_f(file_path, read_from_start=True, follow=False):
                try:
                    import json

                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if process_event(cursor, event, reader=None):
                    processed += 1
                    if processed % 100 == 0:
                        conn.commit()
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    print(f"Backfill complete. Processed {processed} real Cowrie events.")


if __name__ == "__main__":
    run_backfill()
