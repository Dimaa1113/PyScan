# port_scanner/__init__.py

try:
    # This is the Python-callable wrapper in scanner.pyx which calls c_scan_port
    from .scanner.scanner import scan_port as _scan_port_cython
    # This is the new Cython function that handles its own ThreadPoolExecutor
    from .scanner.scanner import scan_targets_parallel_cython as _scan_targets_parallel_cython
except ImportError as e:
    # Catching the error and providing a more informative message
    error_message = (
        "Cython-compiled scanner module not found or missing key functions "
        "(e.g., _scan_port_cython, _scan_targets_parallel_cython).\n"
        "Please ensure the package is installed correctly and the Cython modules are compiled.\n"
        "Original error: {}".format(e)
    )
    # Depending on the desired behavior, you might log this, or ensure it's visible.
    # For now, raising a new ImportError with the detailed message.
    raise ImportError(error_message) from e


def is_valid_port(port: int) -> bool:
    """Checks if a port number is valid (1-65535)."""
    return 1 <= port <= 65535

def _validate_timeout(timeout_seconds: float):
    """Validates the timeout_seconds parameter."""
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise ValueError("Timeout must be a positive number.")

def _validate_max_workers(max_workers: int = 0):
    """Validates the max_workers parameter. Default 0 for Cython to interpret as 'use default'."""
    if not isinstance(max_workers, int) or max_workers < 0: # Allow 0 for default in Cython layer
        raise ValueError("max_workers must be a non-negative integer (0 means use Cython's default).")

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

    return _scan_port_cython(ip_address.encode('utf-8'), port, timeout_seconds)

def scan_multiple_ports(ip_address: str, ports: list[int], timeout_seconds: float = 1.0, max_workers: int = 0) -> list[int]:
    """
    Scans multiple ports on a single IP address using the parallel Cython function.

    Args:
        ip_address: The target IP address.
        ports: A list of port numbers to scan.
        timeout_seconds: Connection timeout for each port. Default is 1.0.
        max_workers: Max worker threads for the Cython function.
                     0 means default (CPU core based).

    Returns:
        A sorted list of open port numbers for the given IP.
    """
    _validate_timeout(timeout_seconds)
    _validate_max_workers(max_workers)
    if not isinstance(ip_address, str):
        raise ValueError("IP address must be a string.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    if not ports:
        return []

    # targets_py for _scan_targets_parallel_cython is a list of strings (IPs or ranges)
    results_dict = _scan_targets_parallel_cython([ip_address], ports, timeout_seconds, max_workers)

    # _scan_targets_parallel_cython returns a dict {ip: [open_ports]}, extract the list for the single IP
    return results_dict.get(ip_address, []) # Returns sorted list from Cython


def scan_ip_range_ports(ip_range_str: str, ports: list[int], timeout_seconds: float = 1.0, max_workers: int = 0) -> dict[str, list[int]]:
    """
    Scans a range of IP addresses for specified ports using the parallel Cython function.

    Args:
        ip_range_str: The IP range string (e.g., "192.168.1.1-192.168.1.10" or a single IP).
        ports: A list of port numbers to scan.
        timeout_seconds: Connection timeout for each port. Default is 1.0.
        max_workers: Max worker threads for the Cython function. 0 for default.

    Returns:
        A dictionary where keys are IP addresses with open ports, and values are sorted lists of those ports.
    """
    _validate_timeout(timeout_seconds)
    _validate_max_workers(max_workers)
    if not isinstance(ip_range_str, str):
        raise ValueError("IP range must be a string.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    if not ports: # If no ports to scan, return empty results
        return {}

    # targets_py is a list of strings
    return _scan_targets_parallel_cython([ip_range_str], ports, timeout_seconds, max_workers)


def scan_ip_list_ports(ip_list: list[str], ports: list[int], timeout_seconds: float = 1.0, max_workers: int = 0) -> dict[str, list[int]]:
    """
    Scans a list of IP addresses and/or IP ranges for specified ports using the parallel Cython function.

    Args:
        ip_list: A list of IP/IP range strings.
        ports: A list of port numbers to scan.
        timeout_seconds: Connection timeout for each port. Default is 1.0.
        max_workers: Max worker threads for the Cython function. 0 for default.

    Returns:
        A dictionary where keys are IP addresses with open ports, and values are sorted lists of those ports.
    """
    _validate_timeout(timeout_seconds)
    _validate_max_workers(max_workers) # Validates max_workers is non-negative
    if not isinstance(ip_list, list) or not all(isinstance(item, str) for item in ip_list):
        raise ValueError("IP list must be a list of strings.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    if not ip_list or not ports: # If no IPs or no ports, return empty
        return {}

    # ip_list is already in the correct format for targets_py
    return _scan_targets_parallel_cython(ip_list, ports, timeout_seconds, max_workers)

__all__ = [
    'scan_single_port',
    'scan_multiple_ports',
    'scan_ip_range_ports',
    'scan_ip_list_ports',
    'is_valid_port'
]
