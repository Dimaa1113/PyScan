import unittest
import socket
import threading
import time
import subprocess
import sys
import os
import argparse # For ArgumentTypeError
from typing import List, Dict, Any

# Adjust Python path to import from the parent directory (project root)
# This allows running tests/test_scanner.py directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from port_scanner import (
    scan_single_port,
    scan_multiple_ports,
    scan_ip_range_ports,
    scan_ip_list_ports,
    is_valid_port # For direct testing if needed, though it's used by wrappers
)
from port_scanner.cli import parse_ports, main as cli_main
# For testing _parse_ip_range_py directly from Cython module (if needed and accessible)
# from port_scanner.scanner.scanner import _parse_ip_range_py


# --- Test Server Setup ---
TEST_HOST = "127.0.0.1"
TEST_OPEN_PORTS_LIST = [48080, 48081, 48082] # Using a list for ordered access
TEST_CLOSED_PORT = 48083
TEST_ALL_TARGET_PORTS = TEST_OPEN_PORTS_LIST + [TEST_CLOSED_PORT]

def simple_server_worker(host: str, port: int, ready_event: threading.Event, stop_event: threading.Event):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0.5) # Timeout for s.accept() to check stop_event
            s.bind((host, port))
            s.listen(1)
            ready_event.set()
            # print(f"Test server listening on {host}:{port}")
            while not stop_event.is_set():
                try:
                    conn, addr = s.accept()
                    # print(f"Test server accepted connection on {host}:{port}")
                    with conn:
                        conn.recv(1024) # Basic interaction
                except socket.timeout:
                    continue # Loop to check stop_event again
                except Exception:
                    # print(f"Error in server connection handling on {host}:{port}: {e}")
                    break # Exit loop on other connection errors
            # print(f"Test server on {host}:{port} stopping.")
    except OSError:
        # print(f"Server socket error on {host}:{port}: {e}")
        ready_event.set() # Ensure event is set even on error to not hang setup
    except Exception:
        # print(f"General server exception on {host}:{port}: {e}")
        ready_event.set()


class TestWithServerBase(unittest.TestCase):
    server_threads: List[threading.Thread] = []
    stop_events: List[threading.Event] = []

    @classmethod
    def setUpClass(cls):
        cls.server_threads = []
        cls.stop_events = []
        ready_events = []

        for port in TEST_OPEN_PORTS_LIST:
            ready_event = threading.Event()
            stop_event = threading.Event()
            ready_events.append(ready_event)
            cls.stop_events.append(stop_event)

            thread = threading.Thread(
                target=simple_server_worker,
                args=(TEST_HOST, port, ready_event, stop_event),
                daemon=True
            )
            cls.server_threads.append(thread)
            thread.start()

        timeout_seconds = 5
        all_ready = all(event.wait(timeout_seconds / len(ready_events) if ready_events else 1) for event in ready_events)
        if not all_ready:
            # Clean up started threads if not all servers became ready
            for stop_event in cls.stop_events:
                stop_event.set()
            for thread in cls.server_threads:
                thread.join(0.5)
            raise unittest.SkipTest("Could not start all test servers within timeout.")

    @classmethod
    def tearDownClass(cls):
        for stop_event in cls.stop_events:
            stop_event.set()
        for thread in cls.server_threads:
            thread.join(1.0) # Wait a bit for threads to close
        cls.server_threads = []
        cls.stop_events = []


# --- Test Cases ---

class TestPortParsing(unittest.TestCase):
    def test_parse_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_parse_comma_separated_ports(self):
        self.assertEqual(parse_ports("80,443,22"), [22, 80, 443])

    def test_parse_range_ports(self):
        self.assertEqual(parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_parse_mixed_ports(self):
        self.assertEqual(parse_ports("80,1-3,443"), [1, 2, 3, 80, 443])
        self.assertEqual(parse_ports("  80 , 1 - 3 , 443  "), [1, 2, 3, 80, 443])

    def test_parse_duplicate_ports(self):
        self.assertEqual(parse_ports("80,80,1-3,2"), [1, 2, 3, 80])

    def test_invalid_port_string(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("abc")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("1-abc")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("80,abc,443")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("") # Empty
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("1,")

    def test_invalid_port_number(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("0")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("65536")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("80,0,443")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("1-65536")

    def test_invalid_port_range(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_ports("10-1") # Start > End


class TestPythonWrappersAndCore(TestWithServerBase):
    def test_input_validation_scan_single_port(self):
        with self.assertRaisesRegex(ValueError, "IP address must be a string"):
            scan_single_port(123, 80) # type: ignore
        with self.assertRaisesRegex(ValueError, "Invalid port number"):
            scan_single_port(TEST_HOST, 0)
        with self.assertRaisesRegex(ValueError, "Invalid port number"):
            scan_single_port(TEST_HOST, 65536)
        with self.assertRaisesRegex(ValueError, "Invalid port number"):
            scan_single_port(TEST_HOST, "abc") # type: ignore
        # Assuming underlying ipaddress module in Cython handles IP string format,
        # which it does by raising ValueError for bad IP strings.
        # The Python wrapper for scan_single_port does not currently re-validate the IP string format
        # itself, relying on the Cython/ipaddress layer. This could be added.

    def test_input_validation_scan_multiple_ports(self):
        with self.assertRaisesRegex(ValueError, "IP address must be a string"):
            scan_multiple_ports(123, TEST_OPEN_PORTS_LIST) # type: ignore
        with self.assertRaisesRegex(ValueError, "Ports must be a list"):
            scan_multiple_ports(TEST_HOST, "80,443") # type: ignore
        with self.assertRaisesRegex(ValueError, "Ports must be a list of integers"):
            scan_multiple_ports(TEST_HOST, [80, "abc"]) # type: ignore
        with self.assertRaisesRegex(ValueError, "Ports must be a list of integers.*1 and 65535"):
            scan_multiple_ports(TEST_HOST, [80, 0])
        with self.assertRaisesRegex(ValueError, "Ports must be a list of integers.*1 and 65535"):
            scan_multiple_ports(TEST_HOST, [80, 65536])

    def test_input_validation_scan_ip_range_ports(self):
        with self.assertRaisesRegex(ValueError, "IP range must be a string"):
            scan_ip_range_ports(123, TEST_OPEN_PORTS_LIST) # type: ignore
        with self.assertRaisesRegex(ValueError, "Ports must be a list"):
            scan_ip_range_ports(TEST_HOST, "80,443") # type: ignore
        # Further port validation is similar to scan_multiple_ports

    def test_input_validation_scan_ip_list_ports(self):
        with self.assertRaisesRegex(ValueError, "IP list must be a list of strings"):
            scan_ip_list_ports([TEST_HOST, 123], TEST_OPEN_PORTS_LIST) # type: ignore
        with self.assertRaisesRegex(ValueError, "Ports must be a list"):
            scan_ip_list_ports([TEST_HOST], "80,443") # type: ignore
        # Further port validation is similar to scan_multiple_ports

    def test_scan_single_port_open(self):
        self.assertTrue(scan_single_port(TEST_HOST, TEST_OPEN_PORTS_LIST[0]))

    def test_scan_single_port_closed(self):
        self.assertFalse(scan_single_port(TEST_HOST, TEST_CLOSED_PORT))

    def test_scan_multiple_ports_mixed(self):
        open_ports = scan_multiple_ports(TEST_HOST, TEST_ALL_TARGET_PORTS)
        self.assertCountEqual(open_ports, TEST_OPEN_PORTS_LIST) # Order doesn't matter

    def test_scan_ip_range_ports_single_ip(self):
        # Test with a "range" that is actually a single IP
        ip_range_str = f"{TEST_HOST}-{TEST_HOST}"
        results = scan_ip_range_ports(ip_range_str, TEST_ALL_TARGET_PORTS)
        self.assertIn(TEST_HOST, results)
        self.assertCountEqual(results[TEST_HOST], TEST_OPEN_PORTS_LIST)

    def test_scan_ip_range_ports_no_open(self):
        results = scan_ip_range_ports(TEST_HOST, [TEST_CLOSED_PORT])
        if results: # It might return empty dict or dict with empty list
            self.assertNotIn(TEST_CLOSED_PORT, results.get(TEST_HOST, []))

    def test_scan_ip_list_ports(self):
        ip_list = [TEST_HOST, f"{TEST_HOST}-{TEST_HOST}"] # Test with a single IP and a "range" of one IP
        results = scan_ip_list_ports(ip_list, TEST_ALL_TARGET_PORTS)
        self.assertIn(TEST_HOST, results)
        self.assertCountEqual(results[TEST_HOST], TEST_OPEN_PORTS_LIST)
        # Ensure results from "range" don't duplicate or overwrite if keys are same
        self.assertEqual(len(results), 1)

    def test_scan_ip_range_invalid_range_string(self):
        # The _parse_ip_range_py in Cython handles bad ranges by returning empty list.
        # So, scan_ip_range_ports should return an empty dict.
        results = scan_ip_range_ports("invalid-range-string", TEST_OPEN_PORTS_LIST)
        self.assertEqual(results, {})
        results = scan_ip_range_ports("1.1.1.1-2.2.2.2.2", TEST_OPEN_PORTS_LIST) # malformed IP
        self.assertEqual(results, {})
        results = scan_ip_range_ports("127.0.0.1-127.0.0.0", TEST_OPEN_PORTS_LIST) # start > end
        self.assertEqual(results, {})


class TestCLI(TestWithServerBase):
    CLI_EXECUTABLE = [sys.executable, os.path.join(os.path.dirname(__file__), '..', 'port_scanner', 'cli.py')]

    def run_cli_command(self, args: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(self.CLI_EXECUTABLE + args, capture_output=True, text=True, timeout=10)

    def test_cli_help(self):
        result = self.run_cli_command(["--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage: cli.py", result.stdout)
        self.assertIn("--ip IP_ADDRESS", result.stdout)
        self.assertIn("--ports PORTS", result.stdout)

    def test_cli_missing_target(self):
        result = self.run_cli_command(["-p", "80"]) # Missing --ip, --ip-range, or --ip-list
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error: one of the arguments --ip --ip-range --ip-list is required", result.stderr)

    def test_cli_missing_ports(self):
        result = self.run_cli_command(["--ip", TEST_HOST]) # Missing --ports
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error: the following arguments are required: -p/--ports", result.stderr)

    def test_cli_invalid_port_format(self):
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", "abc"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid port specification: 'abc'", result.stderr)

    def test_cli_scan_single_ip_single_open_port(self):
        port_to_scan = TEST_OPEN_PORTS_LIST[0]
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", str(port_to_scan)])
        self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
        self.assertIn(f"Open ports on {TEST_HOST}:", result.stdout)
        self.assertIn(f"- {port_to_scan}", result.stdout)

    def test_cli_scan_single_ip_multiple_ports(self):
        ports_str = ",".join(map(str, TEST_ALL_TARGET_PORTS))
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", ports_str])
        self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
        self.assertIn(f"Open ports on {TEST_HOST}:", result.stdout)
        for port in TEST_OPEN_PORTS_LIST:
            self.assertIn(f"- {port}", result.stdout)
        self.assertNotIn(str(TEST_CLOSED_PORT), result.stdout) # Check that closed port is not listed as open

    def test_cli_scan_ip_range(self):
        ports_str = ",".join(map(str, TEST_OPEN_PORTS_LIST))
        ip_range = f"{TEST_HOST}-{TEST_HOST}" # Range of one IP for simplicity
        result = self.run_cli_command(["--ip-range", ip_range, "-p", ports_str])
        self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
        self.assertIn(f"{TEST_HOST}:", result.stdout)
        for port in TEST_OPEN_PORTS_LIST:
            self.assertIn(f"- {port}", result.stdout)

    def test_cli_scan_ip_list(self):
        ports_str = ",".join(map(str, TEST_OPEN_PORTS_LIST))
        # List containing the same host twice, once as single, once as range of one
        ip_list_str = f"{TEST_HOST},{TEST_HOST}-{TEST_HOST}"
        result = self.run_cli_command(["--ip-list", ip_list_str, "-p", ports_str])
        self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
        # Output should only list the host once due to dict aggregation
        occurrences = result.stdout.count(f"{TEST_HOST}:")
        self.assertEqual(occurrences, 1, "IP address results should be aggregated and appear once")
        for port in TEST_OPEN_PORTS_LIST:
            self.assertIn(f"- {port}", result.stdout)

    def test_cli_scan_no_open_ports_found(self):
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", str(TEST_CLOSED_PORT)])
        self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
        self.assertIn("No open ports found", result.stdout) # Check for the "no open ports" message

if __name__ == "__main__":
    unittest.main(verbosity=2)
