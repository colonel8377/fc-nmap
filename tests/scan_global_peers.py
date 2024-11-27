import json
import os

import psycopg2
from psycopg2.extras import execute_values
from src.fc_nmap.get_hubs import process_hub_records, process_hub_peers, get_hubs
import signal
import time

from src.fc_nmap.cli.command import update_hub_geo

# Database connection parameters
db_params = {
    'dbname': 'DappResearch',
    'user': 'DappResearch',
    'password': 'FarcasterIndexer',
    'host': '100.81.228.99',
    'port': 6541
}

geo_api_key = '0CFBD2B3B0D534EEA0B8C9DB33DBDF3C'


def timeout_handler(signum, frame):
    """Raise a timeout exception when a function call exceeds its time limit."""
    raise TimeoutError("Operation timed out!")


def upsert_hub_records(cursor, batch_records):
    """Insert or update records in the `hub_info` table."""
    query = """
        INSERT INTO public.hub_info (
            ip, port, peer_id, family, dns_name, hub_version, app_version, 
            last_active_ts, version, is_syncing, nickname, root_hash, fid, 
            num_messages, num_fid_events, num_fname_events, approx_size
        )
        VALUES %s
        ON CONFLICT (ip, port, peer_id)
        DO UPDATE SET
            family = EXCLUDED.family,
            dns_name = EXCLUDED.dns_name,
            hub_version = EXCLUDED.hub_version,
            app_version = EXCLUDED.app_version,
            last_active_ts = EXCLUDED.last_active_ts,
            "version" = EXCLUDED."version",
            is_syncing = EXCLUDED.is_syncing,
            nickname = EXCLUDED.nickname,
            root_hash = EXCLUDED.root_hash,
            fid = EXCLUDED.fid,
            num_messages = EXCLUDED.num_messages,
            num_fid_events = EXCLUDED.num_fid_events,
            num_fname_events = EXCLUDED.num_fname_events,
            approx_size = EXCLUDED.approx_size,
            updated_at = CURRENT_TIMESTAMP;
    """
    try:
        execute_values(
            cursor,
            query,
            batch_records,
            template="(%s, %s, %s, %s, %s, %s, %s, to_timestamp(%s/1000), %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        )
        print(f"{len(batch_records)} records upserted successfully.")
    except Exception as e:
        raise RuntimeError(f"Failed to UPSERT hub records: {str(e)}")

def main_loop():
    conn = None
    try:
        conn = psycopg2.connect(**db_params)
        cursor = conn.cursor()

        while True:
            print("\n=== Starting new scan for peers ===")
            hubs = {}

            try:
                # Fetch a random hub to start
                cursor.execute(
                    "SELECT ip, port, dns_name FROM hub_info WHERE ip != '127.0.0.1' ORDER BY last_active_ts DESC LIMIT 1;"
                )
                random_row = cursor.fetchone()
                if not random_row:
                    print("No hubs available in the database.")
                    continue

                print(f"Scanning peers for {random_row[0]}:{random_row[1]}")

                # Set a timeout for scanning peers
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(600)  # 300-second timeout

                # Process hubs
                get_hubs(hub_address=(random_row[0], random_row[1], random_row[2]), hubs=hubs)
                candidates = process_hub_peers(hubs=hubs, hops=100, max_workers=10)
                hub_infos, disappear_records = process_hub_records(candidates.keys(), 10, int(len(candidates.keys())/10) )

                # Prepare records for insertion
                batch_new_records = []
                for key, base_attr in hubs.items():
                    info = hub_infos.get(key)
                    if info is None:
                        continue

                    batch_new_records.append((
                        base_attr['ip'],
                        base_attr['port'],
                        info.peerId,
                        base_attr['family'],
                        base_attr['dns_name'],
                        base_attr['hubv'],
                        base_attr['appv'],
                        base_attr['last_active_ts'],
                        info.version,
                        info.is_syncing,
                        info.nickname,
                        info.root_hash,
                        info.hub_operator_fid,
                        info.db_stats.num_messages,
                        info.db_stats.num_fid_events,
                        info.db_stats.num_fname_events,
                        info.db_stats.approx_size
                    ))

                # Insert or update records in the database
                if batch_new_records:
                    upsert_hub_records(cursor, batch_new_records)
                    conn.commit()
                    print(f"Successfully committed {len(batch_new_records)} records to the database.")
                update_hub_geo(geo_api_key=geo_api_key, conn=conn)
            except Exception as e:
                conn.rollback()
                print(f"Error during scanning: {str(e)}")
            except TimeoutError:
                print("Scanning operation timed out. Moving to the next iteration.")

            finally:
                signal.alarm(0)  # Disable alarm after the operation

            # Sleep before next scan
            print("Scan completed.")

    except Exception as e:
        print(f"Critical error: {str(e)}")
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")


if __name__ == '__main__':
    main_loop()