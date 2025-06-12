# port_scanner/__init__.py
import concurrent.futures
import os # For os.cpu_count() for default max_workers, though ThreadPoolExecutor handles None.
from collections import defaultdict

# Attempt to import the compiled Cython module components
try:
    # _scan_port_cython is the core C-level port scanning function.
    # _parse_ip_range_py is the Cython helper for parsing IP ranges (Python callable).
    from .scanner.scanner import (
        scan_port as _scan_port_cython,  # This is the Python-callable wrapper in Cython for c_scan_port
        _parse_ip_range_py  # This is the 'def' function in Cython for parsing
    )
    # The following Cython functions that do sequential scanning are no longer directly used by these Python API functions.
    # scan_ports_single_ip as _scan_ports_single_ip_cython,
    # scan_ip_range as _scan_ip_range_cython,
    # scan_ip_list as _scan_ip_list_cython
except ImportError as e:
    raise ImportError(
        "Cython-compiled scanner module or required functions not found. "
        "Please ensure the package is installed correctly and "
        "the Cython modules are compiled. Original error: {}".format(e)
    )

def is_valid_port(port: int) -> bool:
    """Checks if a port number is valid (1-65535)."""
    return 1 <= port <= 65535

def _validate_timeout(timeout_seconds: float):
    """Validates the timeout_seconds parameter."""
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise ValueError("Timeout must be a positive number.")

def _validate_max_workers(max_workers: int = None):
    """Validates the max_workers parameter."""
    if max_workers is not None and (not isinstance(max_workers, int) or max_workers <= 0):
        raise ValueError("max_workers must be None or a positive integer.")

def scan_single_port(ip_address: str, port: int, timeout_seconds: float = 1.0) -> bool:
    """
    Scans a single port on a single IP address.

    Args:
        ip_address: The target IP address (e.g., "192.168.1.1").
        port: The target port number (1-65535).
        timeout_seconds: Connection timeout in seconds for the port scan. Default is 1.0.

    Returns:
        True if the port is open, False otherwise.

    Raises:
        ValueError: If the IP address, port, or timeout is invalid.
    """
    _validate_timeout(timeout_seconds)
    if not isinstance(ip_address, str):
        raise ValueError("IP address must be a string.")
    if not isinstance(port, int) or not is_valid_port(port):
        raise ValueError(f"Invalid port number: {port}. Must be an integer between 1 and 65535.")

    # _scan_port_cython is the Python-callable wrapper in scanner.pyx which calls c_scan_port
    return _scan_port_cython(ip_address.encode('utf-8'), port, timeout_seconds)

def scan_multiple_ports(ip_address: str, ports: list[int], timeout_seconds: float = 1.0, max_workers: int = None) -> list[int]:
    """
    Scans multiple ports on a single IP address in parallel.

    Args:
        ip_address: The target IP address.
        ports: A list of port numbers to scan.
        timeout_seconds: Connection timeout for each port. Default is 1.0.
        max_workers: Maximum number of threads to use. Defaults to ThreadPoolExecutor default.

    Returns:
        A sorted list of open port numbers.
    """
    _validate_timeout(timeout_seconds)
    _validate_max_workers(max_workers)
    if not isinstance(ip_address, str):
        raise ValueError("IP address must be a string.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    open_ports = []
    encoded_ip = ip_address.encode('utf-8')

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_scan_port_cython, encoded_ip, port, timeout_seconds): port
            for port in set(ports) # Use set to avoid scanning the same port multiple times
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                # print(f"Error scanning port {port} on {ip_address}: {e}") # Optional logging
                pass # Port considered closed or scan failed for it
    return sorted(open_ports)

def scan_ip_range_ports(ip_range_str: str, ports: list[int], timeout_seconds: float = 1.0, max_workers: int = None) -> dict[str, list[int]]:
    """
    Scans a range of IP addresses for specified ports in parallel.

    Args:
        ip_range_str: The IP range string (e.g., "192.168.1.1-192.168.1.10" or a single IP).
        ports: A list of port numbers to scan.
        timeout_seconds: Connection timeout for each port. Default is 1.0.
        max_workers: Maximum number of threads to use.

    Returns:
        A dictionary where keys are IP addresses with open ports, and values are sorted lists of those ports.
    """
    _validate_timeout(timeout_seconds)
    _validate_max_workers(max_workers)
    if not isinstance(ip_range_str, str):
        raise ValueError("IP range must be a string.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    ips_to_scan = _parse_ip_range_py(ip_range_str)
    if not ips_to_scan:
        return {}

    # Using defaultdict to simplify appending to lists
    results = defaultdict(list)
    tasks = []
    for ip_str in ips_to_scan:
        for port_num in set(ports): # Use set for unique ports per IP
            tasks.append((ip_str, port_num))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {
            executor.submit(_scan_port_cython, task_ip.encode('utf-8'), task_port, timeout_seconds): (task_ip, task_port)
            for task_ip, task_port in tasks
        }
        for future in concurrent.futures.as_completed(future_to_task):
            task_ip, task_port = future_to_task[future]
            try:
                if future.result():
                    results[task_ip].append(task_port)
            except Exception:
                # print(f"Error scanning port {task_port} on {task_ip}: {e}") # Optional logging
                pass

    # Convert defaultdict to dict and sort port lists
    final_results = {ip: sorted(port_list) for ip, port_list in results.items() if port_list}
    return final_results

def scan_ip_list_ports(ip_list: list[str], ports: list[int], timeout_seconds: float = 1.0, max_workers: int = None) -> dict[str, list[int]]:
    """
    Scans a list of IP addresses and/or IP ranges for specified ports in parallel.

    Args:
        ip_list: A list of IP/IP range strings.
        ports: A list of port numbers to scan.
        timeout_seconds: Connection timeout for each port. Default is 1.0.
        max_workers: Maximum number of threads to use.

    Returns:
        A dictionary where keys are IP addresses with open ports, and values are sorted lists of those ports.
    """
    _validate_timeout(timeout_seconds)
    _validate_max_workers(max_workers)
    if not isinstance(ip_list, list) or not all(isinstance(item, str) for item in ip_list):
        raise ValueError("IP list must be a list of strings.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    all_individual_ips = []
    for item_str in ip_list:
        all_individual_ips.extend(_parse_ip_range_py(item_str))

    unique_ips_to_scan = sorted(list(set(all_individual_ips)))
    if not unique_ips_to_scan:
        return {}

    results = defaultdict(list)
    tasks = []
    for ip_str in unique_ips_to_scan:
        for port_num in set(ports): # Use set for unique ports per IP
            tasks.append((ip_str, port_num))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {
            executor.submit(_scan_port_cython, task_ip.encode('utf-8'), task_port, timeout_seconds): (task_ip, task_port)
            for task_ip, task_port in tasks
        }
        for future in concurrent.futures.as_completed(future_to_task):
            task_ip, task_port = future_to_task[future]
            try:
                if future.result():
                    results[task_ip].append(task_port)
            except Exception:
                # print(f"Error scanning port {task_port} on {task_ip}: {e}") # Optional logging
                pass

    final_results = {ip: sorted(port_list) for ip, port_list in results.items() if port_list}
    return final_results

__all__ = [
    'scan_single_port',
    'scan_multiple_ports',
    'scan_ip_range_ports',
    'scan_ip_list_ports',
    'is_valid_port'
]
