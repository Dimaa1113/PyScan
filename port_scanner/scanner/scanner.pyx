# cython: language_level=3

# cimport socket # This was from the prompt, but standard 'import socket' is used below
import socket # Standard Python import for socket object usage
import ipaddress # Standard Python import for IP address manipulation

# Ensure scan_port and scan_ports_single_ip are present
def scan_port(bytes host, int port):
    """
    (Cython) Scans a single port on a single host.

    Args:
        host: The target host IP address (as bytes, e.g., b"192.168.1.1").
        port: The target port number.

    Returns:
        True if the port is open, False otherwise.
    """
    # s will be a standard Python socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)  # 1 second timeout

    # host is bytes, decode to string for connect_ex
    addr_tuple = (host.decode('utf-8'), port)

    result = -1 # Default to error
    try:
        result = s.connect_ex(addr_tuple)
    finally:
        s.close() # Ensure socket is closed

    if result == 0:
        return True
    else:
        return False

def scan_ports_single_ip(bytes host, list ports_to_scan):
    """
    (Cython) Scans multiple ports on a single host.

    Args:
        host: The target host IP address (as bytes).
        ports_to_scan: A Python list of integer port numbers.

    Returns:
        A Python list of open port numbers found on the host.
    """
    open_ports = [] # Standard Python list
    # cdef int port # Can still use Cython type for loop variable for minor optimization
    for port_num in ports_to_scan: # port_num will be a Python int
        if scan_port(host, port_num):
            open_ports.append(port_num)
    return open_ports
# End of pre-existing functions


# Helper function using standard Python for ipaddress module
def _parse_ip_range_py(ip_range_str_py):
    """
    (Python, called by Cython) Parses an IP range string into a list of IPs.
    Handles single IPs and hyphenated ranges (e.g., "192.168.1.1-192.168.1.5").
    Uses the 'ipaddress' module. Pure Python helper for Cython functions.

    Args:
        ip_range_str_py: The IP range string.

    Returns:
        A list of IP address strings, or an empty list on error/invalid input.
    """
    # This function is pure Python, so use Python types (str, list)
    if not isinstance(ip_range_str_py, str):
        return []

    try:
        if '-' in ip_range_str_py:
            start_ip_str, end_ip_str = ip_range_str_py.split('-', 1)
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())

            if start_ip.version != end_ip.version:
                return [] # IP version mismatch

            result_ips = []
            current_ip_int = int(start_ip)
            end_ip_int = int(end_ip)

            if current_ip_int > end_ip_int:
                return [] # Start IP is greater than end IP

            # Limit the range to avoid excessive memory/time usage for huge ranges
            # For example, limit to a /20 range (4096 addresses) or similar
            if (end_ip_int - current_ip_int + 1) > 4096: # Arbitrary limit
                 # Consider raising an error or logging a warning
                return []


            for ip_int_val in range(current_ip_int, end_ip_int + 1):
                result_ips.append(str(ipaddress.ip_address(ip_int_val)))
            return result_ips
        else:
            # Validate and return as a list containing one IP
            single_ip = ipaddress.ip_address(ip_range_str_py.strip())
            return [str(single_ip)]
    except ValueError:
        return [] # Return empty list on error like invalid IP format

cpdef dict scan_ip_range(str ip_range_str_py, list ports_to_scan_py):
    """
    (Cython) Scans a range of IP addresses for specified ports.

    Args:
        ip_range_str_py: The IP range string (e.g., "192.168.1.1-192.168.1.10").
                         Can also be a single IP address string.
        ports_to_scan_py: A Python list of port numbers to scan.

    Returns:
        A Python dictionary where keys are IP addresses from the range
        and values are lists of open ports for that IP.
    """
    cdef dict results = {}
    # Call the Python helper function
    cdef list ips_to_scan_py = _parse_ip_range_py(ip_range_str_py)
    cdef str ip_address_py_loopvar # Explicitly declare type for loop variable
    cdef list open_ports_py

    for ip_address_py_loopvar in ips_to_scan_py:
        # Ensure ip_address_py_loopvar is actually a string before encoding
        if not isinstance(ip_address_py_loopvar, str):
            # This case should ideally not be reached if _parse_ip_range_py is correct
            continue
        ip_address_bytes = ip_address_py_loopvar.encode('utf-8')
        open_ports_py = scan_ports_single_ip(ip_address_bytes, ports_to_scan_py)
        if open_ports_py:
            results[ip_address_py_loopvar] = open_ports_py
    return results

cpdef dict scan_ip_list(list ip_list_py, list ports_to_scan_py):
    """
    (Cython) Scans a list of IP addresses and/or IP ranges for specified ports.

    Args:
        ip_list_py: A Python list of IP/IP range strings.
                    Each string can be a single IP or a hyphenated range.
        ports_to_scan_py: A Python list of port numbers to scan.

    Returns:
        A Python dictionary where keys are IP addresses from the expanded list
        and values are lists of open ports for that IP.
    """
    cdef dict aggregated_results = {}
    cdef str ip_definition_str_py_loopvar # Explicitly declare type
    cdef dict range_results_py

    for ip_definition_str_py_loopvar in ip_list_py:
        if not isinstance(ip_definition_str_py_loopvar, str):
            # Skip non-string items or handle error
            continue
        range_results_py = scan_ip_range(ip_definition_str_py_loopvar, ports_to_scan_py)
        # Update preserves existing entries if new dict has same keys,
        # which is fine here as IPs from one range call won't overlap with another
        # from a different call to scan_ip_range.
        aggregated_results.update(range_results_py)

    return aggregated_results
