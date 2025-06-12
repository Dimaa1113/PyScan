# port_scanner/__init__.py
# Python wrapper for the Cython scanning functions

# Attempt to import the compiled Cython module
# The actual name of the .so file might vary slightly based on Python version/platform
# but the module name 'scanner' as defined in setup.py for the Cython extension
# should be what we import from port_scanner.scanner.
try:
    from .scanner.scanner import (
        scan_port as _scan_port_cython,
        scan_ports_single_ip as _scan_ports_single_ip_cython,
        scan_ip_range as _scan_ip_range_cython,
        scan_ip_list as _scan_ip_list_cython
    )
except ImportError as e:
    # This error message is helpful for users if the Cython module isn't compiled
    raise ImportError(
        "Cython-compiled scanner module not found. "
        "Please ensure the package is installed correctly and "
        "the Cython modules are compiled. Original error: {}".format(e)
    )

def is_valid_port(port: int) -> bool:
    """Checks if a port number is valid (1-65535)."""
    return 1 <= port <= 65535

def scan_single_port(ip_address: str, port: int) -> bool:
    """
    Scans a single port on a single IP address.

    Args:
        ip_address: The target IP address (e.g., "192.168.1.1").
        port: The target port number (1-65535).

    Returns:
        True if the port is open, False otherwise.

    Raises:
        ValueError: If the IP address or port is invalid.
    """
    if not isinstance(ip_address, str):
        raise ValueError("IP address must be a string.")
    if not isinstance(port, int) or not is_valid_port(port):
        raise ValueError(f"Invalid port number: {port}. Must be an integer between 1 and 65535.")

    # The Cython function expects bytes for the host
    return _scan_port_cython(ip_address.encode('utf-8'), port)

def scan_multiple_ports(ip_address: str, ports: list[int]) -> list[int]:
    """
    Scans multiple ports on a single IP address.

    Args:
        ip_address: The target IP address (e.g., "192.168.1.1").
        ports: A list of port numbers to scan (e.g., [80, 443, 8080]).

    Returns:
        A list of open port numbers.

    Raises:
        ValueError: If the IP address or any port is invalid.
    """
    if not isinstance(ip_address, str):
        raise ValueError("IP address must be a string.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    # The Cython function expects bytes for the host
    return _scan_ports_single_ip_cython(ip_address.encode('utf-8'), ports)

def scan_ip_range_ports(ip_range_str: str, ports: list[int]) -> dict[str, list[int]]:
    """
    Scans a range of IP addresses for specified ports.

    Args:
        ip_range_str: The IP range string (e.g., "192.168.1.1-192.168.1.10" or "10.0.0.5").
        ports: A list of port numbers to scan.

    Returns:
        A dictionary where keys are IP addresses and values are lists of open ports.

    Raises:
        ValueError: If the IP address or any port is invalid.
    """
    if not isinstance(ip_range_str, str):
        raise ValueError("IP range must be a string.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    return _scan_ip_range_cython(ip_range_str, ports)

def scan_ip_list_ports(ip_list: list[str], ports: list[int]) -> dict[str, list[int]]:
    """
    Scans a list of IP addresses and/or IP ranges for specified ports.

    Args:
        ip_list: A list of IP/IP range strings (e.g., ["192.168.1.1", "10.0.0.0/24", "172.16.0.5-172.16.0.10"]).
                 Note: The underlying Cython _parse_ip_range_py currently supports single IPs
                 and hyphenated ranges like "A.B.C.D-E.F.G.H". CIDR notation like "/24" is
                 not yet supported by the Cython parser but could be added to _parse_ip_range_py.
        ports: A list of port numbers to scan.

    Returns:
        A dictionary where keys are IP addresses from the expanded list and values are lists of open ports.

    Raises:
        ValueError: If the IP list or any port is invalid.
    """
    if not isinstance(ip_list, list) or not all(isinstance(item, str) for item in ip_list):
        raise ValueError("IP list must be a list of strings.")
    if not isinstance(ports, list) or not all(isinstance(p, int) and is_valid_port(p) for p in ports):
        raise ValueError("Ports must be a list of integers between 1 and 65535.")

    return _scan_ip_list_cython(ip_list, ports)

# Optional: Add an __all__ to define the public API of the package
__all__ = [
    'scan_single_port',
    'scan_multiple_ports',
    'scan_ip_range_ports',
    'scan_ip_list_ports'
]
