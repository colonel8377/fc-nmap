import os

import click
import sys

import psycopg2

from fc_nmap.__about__ import __version__
from fc_nmap.get_hubs import get_hubs, process_hub_records, process_hub_peers
from fc_nmap import dbexports, dbexports_maps
from fc_nmap.ip2location import resolve_ip


@click.group(context_settings={"help_option_names": ["-h", "--help"]}, invoke_without_command=True)
@click.version_option(version=__version__, prog_name="fc-nmap")
def fc_nmap():
    """Farcaster Network Mapper
    """
    pass


def update_full_db(conn):
    cursor = conn.cursor()
    cursor.execute("""
           SELECT hub_base_info.ip, hub_base_info.port, hub_base_info.dnsname 
           FROM hub_base_info 
       """, )
    records = cursor.fetchall()
    print(f'Update full DB {len(records)} records')
    max_workers = min((int(len(records) / 100) + 1) * os.cpu_count(), 1000)

    disappear_records = records
    active_hubs = {}
    timeout = 20
    i = 0
    while i < 3:
        hub_infos, disappear_records = process_hub_records(disappear_records, timeout, max_workers)
        for info in hub_infos:
            key = (info[0], info[1])
            if key in active_hubs:
                continue
            active_hubs[key] = hub_infos[info]
        i += 1
        timeout *= 2
    print(f'Find {len(disappear_records)} Disappear Records')
    batch_new_records = []
    for key in active_hubs.keys():
        record = key

        info = active_hubs[key]

        # Prepare the record for insertion
        batch_new_records.append(
            (
                (
                    record[0],  # IP
                    record[1],  # Port
                    info.version,
                    info.is_syncing,
                    info.nickname,
                    info.root_hash,
                    info.peerId,
                    info.hub_operator_fid,
                    info.db_stats.num_messages,
                    info.db_stats.num_fid_events,
                    info.db_stats.num_fname_events,
                    info.db_stats.approx_size
                ),
                (
                    record[0],  # IP
                    record[1]
                )
            )
        )

    # Create the SQL command
    sql_command = """
        INSERT INTO hub_ext_info 
        (ip, port, version, is_syncing, nickname, root_hash, peerid, fid, num_messages, num_fid_events, num_fname_events, 
        approx_size, updated_at) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (ip, port) DO UPDATE SET
            version = EXCLUDED.version,
            is_syncing = EXCLUDED.is_syncing,
            nickname = EXCLUDED.nickname,
            root_hash = EXCLUDED.root_hash,
            peerid = EXCLUDED.peerid,
            fid = EXCLUDED.fid,
            num_messages = EXCLUDED.num_messages,
            num_fid_events = EXCLUDED.num_fid_events,
            num_fname_events = EXCLUDED.num_fname_events,
            approx_size = EXCLUDED.approx_size,
            updated_at = NOW();
        """
    # Execute the batch insert
    if batch_new_records and len(batch_new_records) > 0:
        cursor.executemany(sql_command, [record[0] for record in batch_new_records])
        conn.commit()  # Commit the changes

    # Create the SQL command
    sql_command = """
            UPDATE hub_base_info
            SET ofln_ts = NULL
            WHERE ip = %s
            AND port = %s; 
        """
    # Execute the batch insert
    if batch_new_records and len(batch_new_records) > 0:
        cursor.executemany(sql_command, [record[1] for record in batch_new_records])
        conn.commit()  # Commit the change

    batch_update_records = []

    # update fail to fetch hub
    for record in disappear_records:
        batch_update_records.append(
            (
                record[0],
                record[1]
            )
        )

    # update extend info update ts
    sql_command = """
                    INSERT INTO hub_ext_info 
                    (ip, port, updated_at) 
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (ip, port) DO UPDATE SET
                        updated_at = NOW();
                    """
    if batch_update_records and len(batch_update_records) > 0:
        cursor.executemany(sql_command, batch_update_records)
        conn.commit()  # Commit the changes

    # update base info delete ts
    sql_command = """
                    INSERT INTO hub_base_info (ip, port, ofln_ts)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (ip, port) DO UPDATE
                    SET ofln_ts = NOW();  -- Only update if new value is not NULL
        """
    if batch_update_records and len(batch_update_records) > 0:
        cursor.executemany(sql_command, batch_update_records)
        conn.commit()  # Commit the changes


def scan(hub, hops, conn):
    """Scan the network
    """
    db_cursor = conn.cursor()
    hubs = {}

    get_hubs(hub, hubs)
    if not hubs or len(hubs) == 0:
        print(f'Unable to contact {hub}')
        insert_new_hubs(conn, db_cursor, hubs)
        return
    max_workers = min(int(hops / 10) + 1, 100)
    process_hub_peers(hubs, hops, max_workers)
    print(f'Hubs found: {len(hubs)}')
    insert_new_hubs(conn, db_cursor, hubs)


def merge_overlapping_downtimes(conn):
    try:
        with conn.cursor() as cursor:
            print(f'Merge Hub Down Start-End Pair Begin...')
            # Start the transaction
            cursor.execute("BEGIN;")
            # Step 1: Create a temporary table to store merged results
            cursor.execute("""
                -- Step 1: Create or replace the view to encapsulate the merging logic 
                CREATE OR REPLACE VIEW public.merged_downtimes AS 
                WITH merged AS ( 
                    SELECT 
                    ip, 
                    port, 
                    MIN(downtime_start_ts) AS downtime_start_ts, 
                    MAX(downtime_end_ts) AS downtime_end_ts 
                    FROM ( 
                        SELECT 
                        ip, 
                        port, 
                        downtime_start_ts, 
                        downtime_end_ts, 
                        -- Use LEAD and LAG to determine grouping 
                        CASE WHEN LAG(downtime_end_ts) OVER (PARTITION BY ip, port ORDER BY downtime_start_ts) >= downtime_start_ts THEN 1 
                        ELSE 0 
                        END AS grp_flag 
                        FROM public.hub_downtime 
                    ) AS subquery 
                    WHERE grp_flag = 0 -- Filter out rows that belong to existing groups 
                    GROUP BY ip, port, downtime_start_ts 
                ) 
                SELECT ip, port, downtime_start_ts, downtime_end_ts 
                FROM merged; 
                -- Step 2: Delete existing entries for records that will be updated 
                DELETE FROM public.hub_downtime 
                WHERE downtime_end_ts IS NOT NULL; 
                -- Step 3: Insert merged results from the view, updating on conflict 
                INSERT INTO public.hub_downtime (ip, port, downtime_start_ts, downtime_end_ts, create_ts, update_ts) 
                SELECT ip, port, downtime_start_ts, downtime_end_ts, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP 
                FROM public.merged_downtimes 
                ON CONFLICT (ip, port, downtime_start_ts) 
                DO UPDATE SET 
                downtime_end_ts = EXCLUDED.downtime_end_ts, 
                update_ts = CURRENT_TIMESTAMP; -- Update the timestamp on conflict
            """)

            # Commit the transaction

            conn.commit()
            print(f'Merge Hub Down Start-End Pair End...')
    except Exception as e:
        print("Error occurred:", e)
        conn.rollback()


def insert_new_hubs(conn, db_cursor, hubs):
    batch_records = []
    for h in hubs:
        h_ip, h_port = h.split(':')
        h_app_ver = hubs[h]['appv']
        h_proto_ver = hubs[h]['hubv']
        h_dnsname = hubs[h]['dns_name']
        h_last_active_ts = hubs[h]['last_active_ts']
        h_ofln_ts = hubs[h]['ofln_ts']

        batch_records.append((
            h_ip,
            h_port,
            h_dnsname,
            h_proto_ver,
            h_app_ver,
            h_last_active_ts,
            h_ofln_ts
        ))
    # Execute the batch insert if there are records to insert
    if batch_records:
        try:
            db_cursor.executemany("""
                INSERT INTO hub_base_info (ip, port, dnsname, proto_version, app_version, last_active_ts, ofln_ts)
                VALUES (%s, %s, %s, %s, %s, to_timestamp(%s / 1000), to_timestamp(%s / 1000))
                ON CONFLICT (ip, port) DO UPDATE
                SET dnsname = COALESCE(EXCLUDED.dnsname, hub_base_info.dnsname),
                    proto_version = COALESCE(EXCLUDED.proto_version, hub_base_info.proto_version),
                    app_version = COALESCE(EXCLUDED.app_version, hub_base_info.app_version),
                    last_active_ts = COALESCE(EXCLUDED.last_active_ts, hub_base_info.last_active_ts),
                    ofln_ts = EXCLUDED.ofln_ts;  -- This will always update
            """, batch_records)
            conn.commit()  # Commit the changes once after all inserts
        except Exception as e:
            print(f"An error occurred: {e}")
    db_cursor.execute("""INSERT INTO kv (k, v) VALUES ('LAST_SCAN', EXTRACT(EPOCH FROM NOW())::integer)
                         ON CONFLICT (k) DO UPDATE SET v =  EXCLUDED.v;""")
    # db_cursor.execute("""INSERT INTO scan_stats (hubs) VALUES (%s)""", (len(hubs),))
    conn.commit()
    print('Database updated.')


def updatedb(age_threshold, hub_info, hub_location, geo_api_key, timeout, db_params):
    """Collect addtional information about each hub
    """
    if hub_location:
        if not geo_api_key:
            click.echo("You will need to pass --geo-api-location a key from ip2location.io")
            sys.exit(1)
        else:
            update_hub_geo(geo_api_key, db_params)
    if hub_info:
        click.echo("Connecting to each hub to collect more info")
        update_hub_info(age_threshold, timeout, db_params)


def update_hub_info(age_threshold, grpc_timeout, conn):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT hub_base_info.ip, hub_base_info.port, hub_base_info.dnsname 
        FROM hub_base_info 
        LEFT JOIN hub_ext_info ON hub_base_info.ip = hub_ext_info.ip AND hub_base_info.port = hub_ext_info.port 
        WHERE hub_ext_info.updated_at < NOW() - INTERVAL '%s seconds'  -- hub info was not updated in the last N seconds
        OR hub_ext_info.updated_at IS NULL
    """, (age_threshold,))
    records = cursor.fetchall()
    if not records or len(records) == 0:
        return
    max_workers = min((int(len(records) / 100) + 1) * os.cpu_count(), 1000)
    hub_infos, disappear_records = process_hub_records(records, grpc_timeout, max_workers)

    batch_new_records = []
    for key in hub_infos.keys():
        record = key
        info = hub_infos[key]

        # Prepare the record for insertion
        batch_new_records.append(
            (
                (
                    record[0],  # IP
                    record[1],  # Port
                    info.version,
                    info.is_syncing,
                    info.nickname,
                    info.root_hash,
                    info.peerId,
                    info.hub_operator_fid,
                    info.db_stats.num_messages,
                    info.db_stats.num_fid_events,
                    info.db_stats.num_fname_events,
                    info.db_stats.approx_size
                ),
                (
                    record[0],  # IP
                    record[1]
                )
            )
        )

    # Create the SQL command
    sql_command = """
    INSERT INTO hub_ext_info 
    (ip, port, version, is_syncing, nickname, root_hash, peerid, fid, num_messages, num_fid_events, num_fname_events, 
    approx_size, updated_at) 
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
    ON CONFLICT (ip, port) DO UPDATE SET
        version = EXCLUDED.version,
        is_syncing = EXCLUDED.is_syncing,
        nickname = EXCLUDED.nickname,
        root_hash = EXCLUDED.root_hash,
        peerid = EXCLUDED.peerid,
        fid = EXCLUDED.fid,
        num_messages = EXCLUDED.num_messages,
        num_fid_events = EXCLUDED.num_fid_events,
        num_fname_events = EXCLUDED.num_fname_events,
        approx_size = EXCLUDED.approx_size,
        updated_at = NOW();
    """
    # Execute the batch insert
    if batch_new_records and len(batch_new_records) > 0:
        cursor.executemany(sql_command, [record[0] for record in batch_new_records])
        conn.commit()  # Commit the changes

    # Create the SQL command
    sql_command = """
        UPDATE hub_base_info
        SET ofln_ts = NULL
        WHERE ip = %s
        AND port = %s; 
    """
    # Execute the batch insert
    if batch_new_records and len(batch_new_records) > 0:
        cursor.executemany(sql_command, [record[1] for record in batch_new_records])
        conn.commit()  # Commit the change

    batch_update_records = []

    # update fail to fetch hub
    for record in disappear_records:
        batch_update_records.append(
            (
                record[0],
                record[1]
            )
        )

    # update extend info update ts
    sql_command = """
                INSERT INTO hub_ext_info 
                (ip, port, updated_at) 
                VALUES (%s, %s, NOW())
                ON CONFLICT (ip, port) DO UPDATE SET
                    updated_at = NOW();
                """
    if batch_update_records and len(batch_update_records) > 0:
        cursor.executemany(sql_command, batch_update_records)
        conn.commit()  # Commit the changes

    # update base info delete ts
    sql_command = """
                INSERT INTO hub_base_info (ip, port, ofln_ts)
                VALUES (%s, %s, NOW())
                ON CONFLICT (ip, port) DO UPDATE
                SET ofln_ts = NOW();  -- Only update if new value is not NULL
    """
    if batch_update_records and len(batch_update_records) > 0:
        cursor.executemany(sql_command, batch_update_records)
        conn.commit()  # Commit the changes


def update_hub_geo(geo_api_key, conn):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT hub_base_info.ip 
        FROM hub_base_info 
        LEFT JOIN hub_addr ON hub_base_info.ip = hub_addr.ip
        WHERE EXTRACT(EPOCH FROM NOW()) - EXTRACT(EPOCH FROM hub_addr.updated_at) > %s
        OR hub_addr.updated_at IS NULL;
        """, (60 * 60 * 24 * 5,))
    records = cursor.fetchall()
    if not records or len(records) == 0:
        return
    batch_records = []

    for r in records:
        if r[0] == '127.0.0.1':  # Assuming r[0] contains the IP address
            continue
        info = resolve_ip(geo_api_key, r[0])
        if info:
            batch_records.append((
                info['ip'],
                info['country_code'],
                info['country_name'],
                info['region_name'],
                info['city_name'],
                info['latitude'],
                info['longitude'],
                info['zip_code'],
                info['time_zone'],
                info['asn'],
                info['as'],
                info['is_proxy']
            ))

    # Execute the batch insert if there are records to insert
    if batch_records:
        try:
            cursor.executemany("""
                INSERT INTO hub_addr (
                    ip, 
                    country_code, 
                    country_name, 
                    region_name, 
                    city_name, 
                    latitude, 
                    longitude, 
                    zip_code, 
                    time_zone, 
                    as_number, 
                    as_name, 
                    is_proxy, 
                    updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (ip) DO UPDATE SET 
                    country_code = EXCLUDED.country_code,
                    country_name = EXCLUDED.country_name,
                    region_name = EXCLUDED.region_name,
                    city_name = EXCLUDED.city_name,
                    latitude = EXCLUDED.latitude,
                    longitude = EXCLUDED.longitude,
                    zip_code = EXCLUDED.zip_code,
                    time_zone = EXCLUDED.time_zone,
                    as_number = EXCLUDED.as_number,
                    as_name = EXCLUDED.as_name,
                    is_proxy = EXCLUDED.is_proxy,
                    updated_at = NOW();
            """, batch_records)
            conn.commit()  # Commit the changes once after all inserts
        except Exception as e:
            print(f"An error occurred: {e}")


def initdb(conn):
    """Initialize the database"""
    try:
        cursor = conn.cursor()
    except:
        print('hubs.db not found. Run "fc-nmap initdb" to create it.')
        sys.exit(1)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS kv (
            k TEXT NOT NULL PRIMARY KEY,
            v INTEGER
        );
        
        CREATE TABLE IF NOT EXISTS server_downtime (
    ip TEXT,
    port INTEGER,
    downtime_start TIMESTAMP,
    downtime_end TIMESTAMP,
    PRIMARY KEY (ip, port, downtime_start),
    FOREIGN KEY (ip, port) REFERENCES hub_base_info(ip, port)
);
        
        CREATE TABLE IF NOT EXISTS hub_base_info (
            ip TEXT,
            port INTEGER,
            dnsname TEXT,
            proto_version TEXT,
            app_version TEXT,
            last_active_ts TIMESTAMP,  -- Changed from TEXT to TIMESTAMP for better time handling
            ofln_ts TIMESTAMP,
            PRIMARY KEY (ip, port)
        );
        
        CREATE INDEX IF NOT EXISTS idx_hub_info_ip ON hub_base_info(ip);
        
        CREATE TABLE IF NOT EXISTS hub_ext_info (
            ip TEXT,
            port INTEGER,
            version TEXT,
            is_syncing BOOLEAN,
            nickname TEXT,
            root_hash TEXT,
            peerid TEXT,
            fid INTEGER,
            num_messages INTEGER,
            num_fid_events INTEGER,
            num_fname_events INTEGER,
            approx_size INTEGER,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- Changed TEXT to TIMESTAMP
            PRIMARY KEY (ip, port)
        );
        
        CREATE TABLE IF NOT EXISTS hub_addr (
            ip TEXT NOT NULL PRIMARY KEY,
            country_code TEXT,
            country_name TEXT,
            region_name TEXT,
            city_name TEXT,
            latitude REAL,
            longitude REAL,
            zip_code TEXT,
            time_zone TEXT,
            as_number INTEGER,
            as_name TEXT,
            is_proxy BOOLEAN,  -- Changed BOOL to BOOLEAN for PostgreSQL
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP  -- Changed TEXT to TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS scan_stats (
            ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- Changed TEXT to TIMESTAMP
            hubs INTEGER DEFAULT 0
        );

    """)
    conn.commit()


@fc_nmap.command()
@click.option('--out', default='-', help="Output file, leave empty for stdout")
@click.option('--max-age', default=86400,
              help="Only check records that were created/updated in the last INTEGER seconds.", show_default=True)
@click.option('--report',
              type=click.Choice(['all', 'countries', 'fids', 'app', 'asn', 'geoip', 'map'], case_sensitive=False))
def export(out, max_age, report):
    """Create a tab separated dump of the database"""
    if report == 'all':
        dbexports.export_full(dbpath='hubs.db', out=out, max_age=max_age)
    if report == 'countries':
        dbexports.export_countries(dbpath='hubs.db', out=out, max_age=max_age)
    if report == 'fids':
        dbexports.export_fids(dbpath='hubs.db', out=out, max_age=max_age)
    if report == 'app':
        dbexports.export_app_version(dbpath='hubs.db', out=out, max_age=max_age)
    if report == 'asn':
        dbexports.export_asn(dbpath='hubs.db', out=out, max_age=max_age)
    if report == 'geoip':
        dbexports.export_latlong(dbpath='hubs.db', out=out, max_age=max_age)
    if report == 'pam':
        dbexports_maps.map(dbpath='hubs.db', out=out, max_age=max_age)


@fc_nmap.command()
@click.option('--out', default='fc_nmap.html', help="Output file")
@click.option('--max-age', default=86400,
              help="Only check records that were created/updated in the last INTEGER seconds.", show_default=True)
def map(out, max_age):
    dbexports_maps.create_map(dbpath='hubs.db', out=out, max_age=max_age)
