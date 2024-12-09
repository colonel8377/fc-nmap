import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address
from typing import Dict, Any, List, Tuple

from absl import logging
from grpc import RpcError, StatusCode
from tqdm import tqdm

from src.fc_nmap.GrpcClient import HubService
# Logging configuration
logging.set_verbosity(logging.INFO)

def _get_peers_by_ip(hub_address, timeout=10):
    """Retrieve peers by IP."""
    try:
        hub = HubService(hub_address, use_async=False, timeout=timeout)
        peers = hub.GetCurrentPeers()
        hub.close()
        return peers
    except Exception:
        return None


def _get_peers_by_dns(hub_address, timeout=10):
    """Retrieve peers by DNS."""
    try:
        hub = HubService(hub_address, use_async=False, use_ssl=True, timeout=timeout)
        peers = hub.GetCurrentPeers()
        hub.close()
        return peers
    except Exception:
        return None


def get_hubs(hub_address: Tuple[str, int, str], hubs: Dict):
    """Retrieve hubs based on address."""
    if not hub_address:
        raise ValueError("Hub address is missing. Check configuration.")

    addr = f'{hub_address[0]}:{hub_address[1]}'
    peers = _get_peers_by_ip(addr)

    if not peers and hub_address[2]:
        addr = f'{hub_address[2]}:{hub_address[1]}'
        peers = _get_peers_by_dns(addr)

    if not peers:
        return hubs

    for c in peers.contacts:
        hub_key = (c.rpc_address.address, c.rpc_address.port, c.rpc_address.dns_name)
        if hub_key not in hubs:
            hubs[hub_key] = {
                'ip': c.rpc_address.address,
                'port': c.rpc_address.port,
                'family': c.rpc_address.family,
                'dns_name': c.rpc_address.dns_name,
                'hubv': c.hub_version,
                'appv': c.app_version,
                'last_active_ts': c.timestamp
            }
    return hubs

# @timeout_decorator(seconds=15, error_message="Hub peer processing timed out")
def process_hub_peers(hubs: Dict, hops: int, max_workers: int, timeout=10) -> Dict:
    """Process hub peers with threading."""

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Randomly select a limited number of hubs for processing
        selected_hubs = random.sample(list(hubs.keys()), k=min(hops, len(hubs)))

        futures = {executor.submit(get_hubs, hub, hubs): hub for hub in selected_hubs}

        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing hub peers"):
            hub = futures[future]
            try:
                result = future.result(timeout=timeout)
            # Additional processing logic can go here
            except TimeoutError:
                logging.info(f"Timeout while processing hub {hub}.")
            except Exception as e:
                logging.info(f"Error while processing hub {hub}: {e}")
    return hubs


def _get_hub_info(address, port, use_ssl=False, timeout=5):
    """Retrieve hub info with retries."""
    try:
        hub = HubService(f'{address}:{port}', use_async=False, timeout=timeout, use_ssl=use_ssl)
        info = hub.GetInfo(db_stats=True, timeout=timeout)
        hub.close()
        return None, info
    except RpcError as e:
        return e, None


def get_hub_info(address, port, dnsname, timeout=5):
    """Retrieve detailed hub info."""
    if not ip_address(address).is_global:
        return None

    error, info = _get_hub_info(address, port, timeout=timeout)
    if error:
        if error.code() == StatusCode.DEADLINE_EXCEEDED:
            error, info = _get_hub_info(address, port, timeout=60)
        elif error.code() == StatusCode.UNAVAILABLE and dnsname:
            error, info = _get_hub_info(dnsname, port, use_ssl=True)
        return info if not error else None
    return info


def process_hub_records(records: List[Tuple[Any, Any, Any]], timeout: int, max_workers: int):
    """Process hub records concurrently with per-task timeouts."""
    hub_infos = {}
    disappear_records = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(get_hub_info, r[0], r[1], r[2], timeout): r for r in records}

        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing hub records"):
            record = futures[future]
            try:
                # Enforce timeout for individual tasks
                result = future.result(timeout=timeout)
                if result:
                    hub_infos[record] = result
                else:
                    disappear_records.append(record)
            except TimeoutError:
                logging.info(f"Timeout for hub {record[0]}:{record[1]} ({record[2]}).")
                disappear_records.append(record)
            except Exception as e:
                logging.info(f"Error processing hub {record[0]}:{record[1]} ({record[2]}): {e}")
                disappear_records.append(record)

    return hub_infos, disappear_records