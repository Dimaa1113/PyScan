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
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from port_scanner import (
    scan_single_port,
    scan_multiple_ports,
    scan_ip_range_ports,
    scan_ip_list_ports
)
from port_scanner.cli import parse_ports

# --- Test Server Setup ---
TEST_HOST = "127.0.0.1"
TEST_OPEN_PORTS_LIST = [48080, 48081, 48082]
TEST_CLOSED_PORT = 48083
TEST_ALL_TARGET_PORTS = TEST_OPEN_PORTS_LIST + [TEST_CLOSED_PORT]
TEST_PORT_FOR_TIMEOUT_TEST = TEST_OPEN_PORTS_LIST[0]


def simple_server_worker(host: str, port: int, ready_event: threading.Event, stop_event: threading.Event):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(0.5)
            s.bind((host, port))
            s.listen(5) # Increased backlog
            ready_event.set()
            while not stop_event.is_set():
                try:
                    conn, addr = s.accept()
                    with conn:
                        conn.recv(1024)
                except socket.timeout:
                    continue
                except Exception:
                    break
    except OSError:
        ready_event.set()
    except Exception:
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
            for stop_event in cls.stop_events: stop_event.set()
            for thread in cls.server_threads: thread.join(0.5)
            raise unittest.SkipTest("Could not start all test servers within timeout.")

    @classmethod
    def tearDownClass(cls):
        for stop_event in cls.stop_events: stop_event.set()
        for thread in cls.server_threads: thread.join(1.0)
        cls.server_threads = []
        cls.stop_events = []


class TestPortParsing(unittest.TestCase):
    # ... (Port parsing tests remain unchanged) ...
    def test_parse_single_port(self):
        self.assertEqual(parse_ports("80"), [80])
    def test_parse_comma_separated_ports(self):
        self.assertEqual(parse_ports("80,443,22"), [22, 80, 443])
    def test_parse_range_ports(self):
        self.assertEqual(parse_ports("1-5"), [1, 2, 3, 4, 5])
    def test_parse_mixed_ports(self):
        self.assertEqual(parse_ports("80,1-3,443"), [1, 2, 3, 80, 443])
    def test_parse_duplicate_ports(self):
        self.assertEqual(parse_ports("80,80,1-3,2"), [1, 2, 3, 80])
    def test_parse_ports_invalid_non_numeric(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port specification: 'abc'"):
            parse_ports("abc")
    def test_parse_ports_invalid_range_non_numeric(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port specification: '1-abc'"):
            parse_ports("1-abc")
    def test_parse_ports_invalid_mixed_non_numeric(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port specification: '80,abc,443'"):
            parse_ports("80,abc,443")
    def test_parse_ports_empty_string(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Port string cannot be empty."):
            parse_ports("")
    def test_parse_ports_invalid_trailing_comma(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port specification: '1,'"):
            parse_ports("1,")
    def test_invalid_port_number(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port number"):
            parse_ports("0")
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port number"):
            parse_ports("65536")
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port number"):
            parse_ports("80,0,443")
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port range"):
            parse_ports("1-65536")
    def test_invalid_port_range(self):
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "Invalid port range"):
            parse_ports("10-1")


class TestPythonWrappersAndCore(TestWithServerBase):
    # ... (Basic input validation and timeout validation tests remain unchanged) ...
    def test_input_validation_scan_single_port_basic(self):
        with self.assertRaisesRegex(ValueError, "IP address must be a string"):
            scan_single_port(123, 80) # type: ignore
        with self.assertRaisesRegex(ValueError, "Invalid port number"):
            scan_single_port(TEST_HOST, 0)

    def test_scan_single_port_timeout_validation(self):
        with self.assertRaisesRegex(ValueError, "Timeout must be a positive number"):
            scan_single_port(TEST_HOST, TEST_PORT_FOR_TIMEOUT_TEST, timeout_seconds=0)
        with self.assertRaisesRegex(ValueError, "Timeout must be a positive number"):
            scan_single_port(TEST_HOST, TEST_PORT_FOR_TIMEOUT_TEST, timeout_seconds=-0.5)

    # --- New max_workers validation tests ---
    def test_scan_multiple_ports_workers_validation(self):
        with self.assertRaisesRegex(ValueError, "max_workers must be a non-negative integer"):
            scan_multiple_ports(TEST_HOST, [TEST_PORT_FOR_TIMEOUT_TEST], max_workers=-1)
        # max_workers=0 is now valid (means default)

    def test_scan_ip_range_ports_workers_validation(self):
        with self.assertRaisesRegex(ValueError, "max_workers must be a non-negative integer"):
            scan_ip_range_ports(TEST_HOST, [TEST_PORT_FOR_TIMEOUT_TEST], max_workers=-1)

    def test_scan_ip_list_ports_workers_validation(self):
        with self.assertRaisesRegex(ValueError, "max_workers must be a non-negative integer"):
            scan_ip_list_ports([TEST_HOST], [TEST_PORT_FOR_TIMEOUT_TEST], max_workers=-1)

    # --- Updated scan tests with max_workers parameterization ---
    def test_scan_single_port_with_normal_timeout(self): # No workers for single port scan
        is_open = scan_single_port(TEST_HOST, TEST_PORT_FOR_TIMEOUT_TEST, timeout_seconds=1.0)
        self.assertTrue(is_open, "Port should appear open with normal timeout")

    def test_scan_single_port_open(self): # No workers
        self.assertTrue(scan_single_port(TEST_HOST, TEST_OPEN_PORTS_LIST[0]))

    def test_scan_single_port_closed(self): # No workers
        self.assertFalse(scan_single_port(TEST_HOST, TEST_CLOSED_PORT))

    def test_scan_multiple_ports_mixed(self):
        for workers in [0, 1, 3]: # Test with 0 (default), 1, and 3 workers
            with self.subTest(workers=workers):
                open_ports = scan_multiple_ports(TEST_HOST, TEST_ALL_TARGET_PORTS,
                                                 timeout_seconds=1.0, max_workers=workers)
                self.assertCountEqual(open_ports, TEST_OPEN_PORTS_LIST)

    def test_scan_ip_range_ports_single_ip(self):
        ip_range_str = f"{TEST_HOST}-{TEST_HOST}"
        for workers in [0, 1, 3]: # Test with 0 (default), 1, and 3 workers
            with self.subTest(workers=workers):
                results = scan_ip_range_ports(ip_range_str, TEST_ALL_TARGET_PORTS,
                                              timeout_seconds=1.0, max_workers=workers)
                self.assertIn(TEST_HOST, results)
                self.assertCountEqual(results[TEST_HOST], TEST_OPEN_PORTS_LIST)

    def test_scan_ip_list_ports(self):
        ip_list = [TEST_HOST, f"{TEST_HOST}-{TEST_HOST}"]
        for workers in [0, 1, 3]: # Test with 0 (default), 1, and 3 workers
            with self.subTest(workers=workers):
                results = scan_ip_list_ports(ip_list, TEST_ALL_TARGET_PORTS,
                                             timeout_seconds=1.0, max_workers=workers)
                self.assertIn(TEST_HOST, results)
                self.assertCountEqual(results[TEST_HOST], TEST_OPEN_PORTS_LIST)
                self.assertEqual(len(results), 1)


class TestCLI(TestWithServerBase):
    CLI_EXECUTABLE = [sys.executable, os.path.join(os.path.dirname(__file__), '..', 'port_scanner', 'cli.py')]

    def run_cli_command(self, args: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(self.CLI_EXECUTABLE + args, capture_output=True, text=True, timeout=15)

    def test_cli_help(self):
        result = self.run_cli_command(["--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage: cli.py", result.stdout)
        self.assertIn("--timeout TIMEOUT", result.stdout)
        self.assertIn("--workers WORKERS", result.stdout) # Check for new workers help text

    # ... (Existing timeout validation tests are still relevant) ...
    def test_cli_timeout_validation_zero(self):
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", "80", "--timeout", "0"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argument -t/--timeout: must be a positive number", result.stderr.lower())

    # --- New CLI --workers validation tests ---
    def test_cli_workers_validation_zero(self):
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", "80", "--workers", "0"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argument -w/--workers: must be a positive integer", result.stderr.lower())

    def test_cli_workers_validation_negative(self):
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", "80", "--workers", "-1"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argument -w/--workers: must be a positive integer", result.stderr.lower())

    def test_cli_workers_validation_non_numeric(self):
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", "80", "--workers", "abc"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argument -w/--workers: invalid int value: 'abc'", result.stderr.lower())

    # --- Updated CLI scan tests with --workers parameterization ---
    def test_cli_scan_single_ip_single_open_port(self): # --workers not applicable here
        port_to_scan = TEST_OPEN_PORTS_LIST[0]
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", str(port_to_scan), "--timeout", "1.0"])
        self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
        self.assertIn(f"Open ports on {TEST_HOST}:", result.stdout)
        self.assertIn(f"- {port_to_scan}", result.stdout)

    def test_cli_scan_single_ip_multiple_ports(self):
        ports_str = ",".join(map(str, TEST_ALL_TARGET_PORTS))
        for workers_arg_list in [[], ["--workers", "1"], ["--workers", "3"]]:
            with self.subTest(workers_args=workers_arg_list):
                cmd = ["--ip", TEST_HOST, "-p", ports_str, "--timeout", "1.0"] + workers_arg_list
                result = self.run_cli_command(cmd)
                self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
                self.assertIn(f"Open ports on {TEST_HOST}:", result.stdout)
                for port in TEST_OPEN_PORTS_LIST:
                    self.assertIn(f"- {port}", result.stdout)
                open_port_lines = [line.strip() for line in result.stdout.split('\n') if line.strip().startswith("- ")]
                self.assertNotIn(f"- {TEST_CLOSED_PORT}", open_port_lines)

    def test_cli_scan_ip_range(self):
        ports_str = ",".join(map(str, TEST_OPEN_PORTS_LIST))
        ip_range = f"{TEST_HOST}-{TEST_HOST}"
        for workers_arg_list in [[], ["--workers", "1"], ["--workers", "3"]]:
            with self.subTest(workers_args=workers_arg_list):
                cmd = ["--ip-range", ip_range, "-p", ports_str, "--timeout", "1.0"] + workers_arg_list
                result = self.run_cli_command(cmd)
                self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
                self.assertIn(f"{TEST_HOST}:", result.stdout)
                for port in TEST_OPEN_PORTS_LIST:
                    self.assertIn(f"- {port}", result.stdout)

    def test_cli_scan_ip_list(self):
        ports_str = ",".join(map(str, TEST_OPEN_PORTS_LIST))
        ip_list_str = f"{TEST_HOST},{TEST_HOST}-{TEST_HOST}"
        for workers_arg_list in [[], ["--workers", "1"], ["--workers", "3"]]:
            with self.subTest(workers_args=workers_arg_list):
                cmd = ["--ip-list", ip_list_str, "-p", ports_str, "--timeout", "1.0"] + workers_arg_list
                result = self.run_cli_command(cmd)
                self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
                occurrences = result.stdout.count(f"{TEST_HOST}:")
                self.assertEqual(occurrences, 1)
                for port in TEST_OPEN_PORTS_LIST:
                    self.assertIn(f"- {port}", result.stdout)

    def test_cli_scan_no_open_ports_found(self): # --workers should not affect this outcome
        result = self.run_cli_command(["--ip", TEST_HOST, "-p", str(TEST_CLOSED_PORT), "--timeout", "0.1", "--workers", "2"])
        self.assertEqual(result.returncode, 0, f"CLI Error: {result.stderr}")
        self.assertIn("No open ports found", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
