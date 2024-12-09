import os
from concurrent.futures import TimeoutError

import psycopg2
from absl import logging
from psycopg2.extras import execute_values

from src.fc_nmap.get_hubs import process_hub_records, process_hub_peers, get_hubs

# Database connection parameters
DB_PARAMS = {
    'dbname': 'DappResearch',
    'user': 'DappResearch',
    'password': 'FarcasterIndexer',
    'host': '100.81.228.99',
    'port': 6541
}

GEO_API_KEY = '0CFBD2B3B0D534EEA0B8C9DB33DBDF3C'

# Logging configuration
logging.set_verbosity(logging.INFO)


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
            version = EXCLUDED.version,
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
        logging.info(f"{len(batch_records)} records upserted successfully.")
    except Exception as e:
        logging.error(f"Failed to UPSERT hub records: {e}")
        raise


def fetch_random_hub(cursor):
    """Fetch a random hub from the database."""
    query = "SELECT ip, port, dns_name FROM hub_info WHERE ip != '127.0.0.1' ORDER BY random() DESC LIMIT 1;"
    cursor.execute(query)
    return cursor.fetchone()


def scan_hubs(cursor, conn, max_workers=os.cpu_count()):
    """Main hub scanning logic."""
    logging.info("\n=== Starting new scan for peers ===")
    hubs = {}

    # Fetch a random hub to start
    random_row = fetch_random_hub(cursor)
    if not random_row:
        logging.info("No hubs available in the database.")
        return

    logging.info(f"Scanning peers for {random_row[0]}:{random_row[1]}")

    try:
        # Process hubs
        hubs = get_hubs(hub_address=(random_row[0], random_row[1], random_row[2]), hubs=hubs)
        logging.info(f"Finding peers of peers with hops {int(len(hubs) / 10)}")
        candidates = process_hub_peers(hubs=hubs, hops=int(len(hubs) / 10), max_workers=max_workers)
        logging.info(f"Fulfilling more info")
        hub_infos, disappear_records = process_hub_records(list(candidates.keys()), timeout=10, max_workers=max_workers)
        logging.info(f"Updating hub records")
        # Prepare records for insertion
        batch_new_records = [
            (
                base_attr['ip'],
                base_attr['port'],
                hub_infos[key].peerId,
                base_attr['family'],
                base_attr['dns_name'],
                base_attr['hubv'],
                base_attr['appv'],
                base_attr['last_active_ts'],
                hub_infos[key].version,
                hub_infos[key].is_syncing,
                hub_infos[key].nickname,
                hub_infos[key].root_hash,
                hub_infos[key].hub_operator_fid,
                hub_infos[key].db_stats.num_messages,
                hub_infos[key].db_stats.num_fid_events,
                hub_infos[key].db_stats.num_fname_events,
                hub_infos[key].db_stats.approx_size
            )
            for key, base_attr in hubs.items() if hub_infos.get(key)
        ]

        # Insert or update records in the database
        if batch_new_records:
            upsert_hub_records(cursor, batch_new_records)
            conn.commit()
            logging.info(f"Successfully committed {len(batch_new_records)} records to the database.")

    except TimeoutError:
        logging.error("Scanning operation timed out. Skipping to the next iteration.")
    except Exception as e:
        conn.rollback()
        logging.error(f"Error during scanning: {e}")


def main_loop():
    """Main loop for scanning hubs."""
    with psycopg2.connect(**DB_PARAMS) as conn:
        with conn.cursor() as cursor:
            while True:
                try:
                    scan_hubs(cursor, conn)
                except Exception as e:
                    logging.error(f"Critical error during main loop: {e}")
                finally:
                    logging.info("Scan iteration completed. Sleeping before next scan.")
                    # time.sleep(60)  # Adjust sleep interval as needed


if __name__ == '__main__':
    main_loop()