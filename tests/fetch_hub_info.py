import datetime
import threading
import psycopg2

from fc_nmap.cli.command import scan, update_hub_info, update_hub_geo, update_full_db, merge_overlapping_downtimes

db_params = {
    'dbname': 'DappResearch',
    'user': 'DappResearch',
    'password': 'FarcasterIndexer',
    'host': 'localhost',  # or your database host
    'port': 6541  # default PostgreSQL port
}

geo_api_key = '0CFBD2B3B0D534EEA0B8C9DB33DBDF3C'


class TimeoutException(Exception):
    pass


def run_with_timeout(func, *args, timeout=300, **kwargs):
    """Run a function with a timeout."""

    result = None
    exception = None
    finished_event = threading.Event()

    def worker():
        nonlocal result, exception
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            exception = e
        finally:
            finished_event.set()  # Signal that the worker has finished

    thread = threading.Thread(target=worker)
    thread.start()

    # Wait for the thread to finish or timeout
    finished = finished_event.wait(timeout)

    if not finished:
        # Timeout occurred
        print(f'Timeout: {func.__name__} took too long!')
        raise TimeoutException(f"{func.__name__} timed out after {timeout} seconds.")

    if exception is not None:
        raise exception


def main(connection):
    i = 0
    while True:
        try:
            print(f'Round {i} begin: {datetime.datetime.now()}')
            print(f'Update Full Database and Mark Down Disappear DB...')
            run_with_timeout(update_full_db, timeout=600, conn=connection)
            db_cursor = connection.cursor()
            db_cursor.execute("SELECT * FROM hub_base_info ORDER BY RANDOM() LIMIT 1;")
            random_row = db_cursor.fetchone()
            ip, port = random_row[0], random_row[1]
            hub = f'{ip}:{port}'
            print(f'Scan Peers for {hub}...')
            # Scan peers with timeout
            run_with_timeout(scan, hub=hub, hops=100, conn=connection)
            print(f'Update Hub Geo...')
            run_with_timeout(update_hub_geo, geo_api_key, conn=connection, timeout=600)
            print(f'Update Hub Extend Info...')
            run_with_timeout(update_hub_info, age_threshold=12 * 60 * 60, grpc_timeout=10, conn=connection)
            print(f'Round {i} end: {datetime.datetime.now()}')
        except Exception as e:
            print(f'Round {i} fail: {e}')
        finally:
            i += 1


if __name__ == '__main__':
    conn = None
    try:
        conn = psycopg2.connect(**db_params)
        main(conn)
    except Exception as e:
        print(f'hubs.db not found. Run "fc-nmap initdb" to create it. Error: {e}')
    finally:
        if conn:
            conn.close()