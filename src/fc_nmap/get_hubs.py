import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple

from . GrpcClient import HubService
from grpc import FutureTimeoutError, RpcError, StatusCode
import time, datetime, random

from ipaddress import ip_address 


def _get_peers(hub_address):
	try:
		hub = HubService(hub_address, use_async=False, timeout=5)
		peers = hub.GetCurrentPeers()
		hub.close()
		return peers
	except RpcError as error:
		if error.code() == StatusCode.UNAVAILABLE:
			try:
				hub = HubService(hub_address, use_async=False, timeout=5, use_ssl=True)
				peers = hub.GetCurrentPeers()
				hub.close()
				return peers
			except:
				return None
		return None


def get_hubs(hub_address, hubs):
	if not hub_address:
		print("No hub address. Check .env.sample")
		sys.exit(1)
	peers = _get_peers(hub_address)
	if not peers:
		hubs[hub_address]['ofln_ts'] = int(time.time() * 1000)
		return hubs
	for c in peers.contacts:
		id = f'{c.rpc_address.address}:{c.rpc_address.port}'
		if id not in hubs or hubs[id]['last_active_ts'] < c.timestamp:
			hubs[id] = {
				'family': c.rpc_address.family,
				'dns_name': c.rpc_address.dns_name,
				'hubv': c.hub_version,
				'appv': c.app_version,
				'last_active_ts': c.timestamp,
				'ofln_ts': None
				}
	return hubs


def process_hub_peers(hubs: Dict[str, Any], hops: int, max_workers: int, timeout=20) -> Dict[str, Any]:
	with ThreadPoolExecutor(max_workers=max_workers) as executor:
		# Use random.sample to select unique hubs
		selected_hubs = random.sample(list(hubs.keys()), k=min(hops, len(hubs)))

		# Submit tasks to the executor using a dictionary comprehension
		futures = {executor.submit(get_hubs, hub, hubs): hub for hub in selected_hubs}

		# Process completed futures
		for future in as_completed(futures):
			hub = futures[future]  # Get the hub associated with the future
			try:
				result = future.result(timeout=timeout)  # Retrieve the result with a timeout
			# Process the result if necessary (you can add your processing logic here)
			except TimeoutError:
				print(f"Timeout processing hub {hub}: Task took longer than {timeout} seconds.")
			except Exception as e:
				print(f"Error processing hub {hub}: {e}")

	return hubs


def _get_hub_info(address, port, use_ssl=False, timeout=5):
	try:
		hub = HubService(f'{address}:{port}', use_async=False, timeout=timeout, use_ssl=use_ssl)
		info = hub.GetInfo(db_stats=True, timeout=timeout)
		hub.close()
		return (None, info)
	except RpcError as e:
		return(e, None)


def get_hub_info(address, port, dnsname, timeout=5):
	if not ip_address(address).is_global:
		return None
	(error, info) = _get_hub_info(address, port, use_ssl=False, timeout=timeout)
	if error:
		if error.code() == StatusCode.DEADLINE_EXCEEDED:
			(error, info) = _get_hub_info(address, port, use_ssl=False, timeout=60)
			if not error:
				return info
			else:
				return None
		if error.code() == StatusCode.UNAVAILABLE and dnsname.strip():
			(error,info) = _get_hub_info(dnsname, port, use_ssl=True)
			if not error:
				return info
			else:
				return None
		else:
			return None
	else:
		return info


def process_hub_records(records: List[Tuple[Any, Any, Any]], timeout: int, max_workers: int) -> Tuple[Dict[Tuple[Any, Any, Any], Any], List[Tuple[Any, Any, Any]]]:
    hub_infos = {}
    disappear_records = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks to the executor
        futures = {
            executor.submit(get_hub_info, r[0], r[1], r[2], timeout): r
            for r in records
        }

        for future in as_completed(futures):
            record = futures[future]  # Get the record associated with the future
            try:
                result = future.result(timeout=timeout)  # Set timeout for each task
                if result:  # Only append if result is not None or empty
                    hub_infos[record] = result
                else:
                    disappear_records.append(record)
            except TimeoutError:
                print(f"Timeout processing hub {record[0]}:{record[1]} ({record[2]}): Task took longer than {timeout} seconds.")
                disappear_records.append(record)
            except Exception as e:
                # Log more specific information about the error
                print(f"Error processing hub {record[0]}:{record[1]} ({record[2]}): {e}")
                disappear_records.append(record)

    return hub_infos, disappear_records
