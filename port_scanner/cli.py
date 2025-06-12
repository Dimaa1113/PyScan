# port_scanner/cli.py
import argparse
import sys
import os # Import the os module
from typing import List, Dict, Set

# Attempt to import scanner functions from the main package
try:
    from port_scanner import (
        scan_single_port,
        scan_multiple_ports,
        scan_ip_range_ports,
        scan_ip_list_ports
    )
except ImportError:
    # This allows running cli.py directly for testing if port_scanner is in PYTHONPATH
    # Or if cli.py is moved to the root and paths are adjusted.
    # For proper package structure, the first import should work when installed.
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from port_scanner import (
        scan_single_port,
        scan_multiple_ports,
        scan_ip_range_ports,
        scan_ip_list_ports
    )


def parse_ports(port_string: str) -> List[int]:
    """Parses a port string (e.g., "80", "80,443", "1-100") into a list of integers."""
    ports: Set[int] = set()
    if not port_string:
        raise argparse.ArgumentTypeError("Port string cannot be empty.")

    try:
        parts = port_string.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                raise ValueError("Port segment cannot be empty.")
            if '-' in part:
                start_str, end_str = part.split('-', 1)
                start = int(start_str)
                end = int(end_str)
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    raise ValueError("Invalid port range.")
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError("Invalid port number.")
                ports.add(port)
        if not ports:
            raise ValueError("No valid ports specified.")
        return sorted(list(ports))
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid port specification: '{port_string}'. {e}")


def main():
    parser = argparse.ArgumentParser(description="Fast Cython-based port scanner.")

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--ip", metavar="IP_ADDRESS", help="Scan a single IP address.")
    target_group.add_argument("--ip-range", metavar="IP_RANGE", help="Scan an IP range (e.g., \"192.168.1.1-192.168.1.10\").")
    target_group.add_argument("--ip-list", metavar="IP_LIST", help="Scan a comma-separated list of IPs and/or IP ranges (e.g., \"192.168.1.1,10.0.0.5-10.0.0.10\").")

    parser.add_argument("-p", "--ports", required=True, type=parse_ports,
                        help="Ports to scan. Can be a single port, comma-separated (80,443), or a range (1-1024).")

    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds for each port (default: 1.0). Must be positive.")

    parser.add_argument("-w", "--workers", type=int, default=None,
                        help="Number of worker threads for scanning "
                             "(default: Python's ThreadPoolExecutor default, typically based on CPU cores).")

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("argument -t/--timeout: must be a positive number")

    if args.workers is not None and args.workers <= 0:
        parser.error("argument -w/--workers: must be a positive integer")

    ports_to_scan = args.ports
    timeout_to_use = args.timeout
    workers_to_use = args.workers
    workers_display_str = str(workers_to_use) if workers_to_use is not None else "default"


    results_dict: Dict[str, List[int]] = {}
    single_ip_open_ports: List[int] = []

    try:
        if args.ip:
            print(f"Scanning {args.ip} for ports: {ports_to_scan} (timeout: {timeout_to_use}s, workers: {workers_display_str})...")
            if len(ports_to_scan) == 1:
                # For a single IP and single port, parallelization doesn't offer benefit.
                if scan_single_port(args.ip, ports_to_scan[0], timeout_seconds=timeout_to_use):
                    single_ip_open_ports = [ports_to_scan[0]]
            else:
                single_ip_open_ports = scan_multiple_ports(args.ip, ports_to_scan,
                                                           timeout_seconds=timeout_to_use,
                                                           max_workers=workers_to_use)
            if single_ip_open_ports:
                results_dict[args.ip] = single_ip_open_ports

        elif args.ip_range:
            print(f"Scanning IP range {args.ip_range} for ports: {ports_to_scan} (timeout: {timeout_to_use}s, workers: {workers_display_str})...")
            results_dict = scan_ip_range_ports(args.ip_range, ports_to_scan,
                                               timeout_seconds=timeout_to_use,
                                               max_workers=workers_to_use)

        elif args.ip_list:
            ip_definitions = [item.strip() for item in args.ip_list.split(',')]
            print(f"Scanning IP list {ip_definitions} for ports: {ports_to_scan} (timeout: {timeout_to_use}s, workers: {workers_display_str})...")
            results_dict = scan_ip_list_ports(ip_definitions, ports_to_scan,
                                              timeout_seconds=timeout_to_use,
                                              max_workers=workers_to_use)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    if not single_ip_open_ports and not any(results_dict.values()):
        print("No open ports found for the specified targets and ports.")
        return

    print("\nScan Results:")
    if args.ip:
        if single_ip_open_ports:
            print(f"  Open ports on {args.ip}:")
            for port in single_ip_open_ports:
                print(f"    - {port}")
        else:
            print(f"  No open ports found on {args.ip}.")
        return

    for ip, open_ports in results_dict.items():
        if open_ports:
            print(f"  {ip}:")
            for port in open_ports:
                print(f"    - {port}")
        else:
            print(f"  {ip}: (No open ports found)")

if __name__ == "__main__":
    main()
