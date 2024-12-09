import logging
import time

import psycopg2

from src.fc_nmap.cli.command import update_hub_geo

API_ENDPOINT = 'https://api.ip2location.io/'

db_params = {
    'dbname': 'DappResearch',
    'user': 'DappResearch',
    'password': 'FarcasterIndexer',
    'host': '100.81.228.99',
    'port': 6541
}
geo_api_key = 'A76E4269BBA37EE60F0D65606230893B'
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def main_loop():
    conn = None
    try:
        conn = psycopg2.connect(**db_params)
        while True:
            logger.info("=== Starting new scan for peers ===")
            try:
                update_hub_geo(geo_api_key=geo_api_key, conn=conn)
            except Exception as e:
                conn.rollback()
                logger.error(f"Error during scanning: {str(e)}")
            except TimeoutError:
                logger.error("Scanning operation timed out. Moving to the next iteration.")
            # Sleep before next scan
            logger.info("Scan completed. Sleep 60 seconds.")
            time.sleep(60)

    except Exception as e:
        logger.info(f"Critical error: {str(e)}")
    finally:
        if conn:
            conn.close()
            logger.info("Database connection closed.")


if __name__ == '__main__':
    main_loop()