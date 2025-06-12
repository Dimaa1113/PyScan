# cython: language_level=3
# cython: cdivision=True
# cython: boundscheck=False
# cython: wraparound=False

import ipaddress # Keep for _parse_ip_range_py

# C standard library imports
from libc.stdint cimport uint16_t, uint32_t
from libc.string cimport strerror, memset
# from libc.errno cimport errno

# POSIX Socket API definitions
cdef extern from "<sys/socket.h>" nogil:
    struct c_sockaddr "sockaddr":
        unsigned short sa_family
        char sa_data[14]
    ctypedef unsigned int socklen_t
    int c_socket "socket"(int domain, int type, int protocol)
    int c_connect "connect"(int sockfd, const c_sockaddr *addr, socklen_t addrlen)
    int c_close "close"(int fd)
    int c_setsockopt "setsockopt"(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
    int c_getsockopt "getsockopt"(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
    int C_AF_INET "AF_INET"
    int C_SOCK_STREAM "SOCK_STREAM"
    int C_SOL_SOCKET "SOL_SOCKET"
    int C_SO_REUSEADDR "SO_REUSEADDR"
    int C_SO_ERROR "SO_ERROR"

cdef extern from "<netinet/in.h>" nogil:
    ctypedef uint16_t c_in_port_t "in_port_t"
    ctypedef uint32_t c_in_addr_t_raw
    struct c_in_addr "in_addr":
        c_in_addr_t_raw s_addr
    struct c_sockaddr_in "sockaddr_in":
        unsigned short sin_family
        c_in_port_t sin_port
        c_in_addr sin_addr
    uint16_t htons(uint16_t hostshort)

cdef extern from "<arpa/inet.h>" nogil:
    int inet_pton(int af, const char *src, void *dst)

cdef extern from "<fcntl.h>" nogil:
    int fcntl(int fd, int cmd, ...)
    int C_O_NONBLOCK "O_NONBLOCK"
    int C_F_GETFL "F_GETFL"
    int C_F_SETFL "F_SETFL"

cdef extern from "<sys/select.h>" nogil:
    struct c_timeval "timeval":
        long tv_sec
        long tv_usec
    ctypedef struct c_fd_set "fd_set":
        unsigned char _fds_bits[128]
    void FD_ZERO(c_fd_set *set)
    void FD_SET(int fd, c_fd_set *set)
    void FD_CLR(int fd, c_fd_set *set)
    int FD_ISSET(int fd, c_fd_set *set)
    int c_select "select"(int nfds, c_fd_set *readfds, c_fd_set *writefds, c_fd_set *exceptfds, c_timeval *timeout)

cdef extern from "<errno.h>" nogil:
    int errno
    int C_EINPROGRESS "EINPROGRESS"

cpdef bint c_scan_port(const char* host_ip, uint16_t port_num, double timeout_seconds) except -1:
    cdef int sock_fd = -1
    cdef c_sockaddr_in serv_addr
    cdef int ret
    cdef long arg
    cdef c_timeval tv
    cdef c_fd_set writefds
    cdef int so_error = 0
    cdef socklen_t optlen = sizeof(so_error)
    cdef bint is_open = False

    sock_fd = c_socket(C_AF_INET, C_SOCK_STREAM, 0)
    if sock_fd < 0: return False
    arg = fcntl(sock_fd, C_F_GETFL, 0)
    if arg < 0:
        c_close(sock_fd)
        return False
    ret = fcntl(sock_fd, C_F_SETFL, arg | C_O_NONBLOCK)
    if ret < 0:
        c_close(sock_fd)
        return False
    memset(&serv_addr, 0, sizeof(c_sockaddr_in))
    serv_addr.sin_family = C_AF_INET
    serv_addr.sin_port = htons(port_num)
    if inet_pton(C_AF_INET, host_ip, &serv_addr.sin_addr) <= 0:
        c_close(sock_fd)
        return False
    ret = c_connect(sock_fd, <c_sockaddr*>&serv_addr, sizeof(c_sockaddr_in))
    if ret < 0:
        if errno == C_EINPROGRESS: pass
        else:
            c_close(sock_fd)
            return False
    elif ret == 0:
        c_close(sock_fd)
        return True
    tv.tv_sec = <long>timeout_seconds
    tv.tv_usec = <long>((timeout_seconds - tv.tv_sec) * 1000000)

    if tv.tv_usec < 0:
        tv.tv_usec = 0
    if tv.tv_usec >= 1000000:
        tv.tv_usec = 999999

    # If timeout_seconds was > 0 but calculated tv_sec and tv_usec are both 0,
    # make tv_usec 1 to avoid polling, ensuring a minimal wait.
    if timeout_seconds > 0 and tv.tv_sec == 0 and tv.tv_usec == 0:
        tv.tv_usec = 1

    FD_ZERO(&writefds)
    FD_SET(sock_fd, &writefds)
    with nogil:
        ret = c_select(sock_fd + 1, NULL, &writefds, NULL, &tv)
    if ret > 0:
        if c_getsockopt(sock_fd, C_SOL_SOCKET, C_SO_ERROR, &so_error, &optlen) < 0:
            is_open = False
        elif so_error == 0:
            is_open = True
        else: is_open = False
    elif ret == 0: is_open = False
    else: is_open = False
    c_close(sock_fd)
    return is_open

def scan_port(bytes host, int port, double timeout_seconds=1.0):
    """
    (Cython Python-Wrapper) Scans a single port on a single host using c_scan_port.

    Args:
        host: The target host IP address (as bytes).
        port: The target port number.
        timeout_seconds: Connection timeout in seconds. Default is 1.0.

    Returns:
        True if the port is open, False otherwise.
    """
    if not (1 <= port <= 65535):
        return False
    cdef const char* host_c_str = host
    return c_scan_port(host_c_str, <uint16_t>port, timeout_seconds)

def scan_ports_single_ip(bytes host, list ports_to_scan, double timeout_seconds=1.0):
    """
    (Cython) Scans multiple ports on a single host.

    Args:
        host: The target host IP address (as bytes).
        ports_to_scan: A list of port numbers.
        timeout_seconds: Connection timeout for each port. Default is 1.0.

    Returns:
        A list of open port numbers.
    """
    cdef list open_ports = []
    cdef int port_num
    for port_num in ports_to_scan:
        if scan_port(host, port_num, timeout_seconds): # Pass timeout
            open_ports.append(port_num)
    return open_ports

def _parse_ip_range_py(ip_range_str_py):
    """
    (Python, called by Cython) Parses an IP range string into a list of IPs.
    """
    if not isinstance(ip_range_str_py, str): return []
    try:
        if '-' in ip_range_str_py:
            start_ip_str, end_ip_str = ip_range_str_py.split('-', 1)
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())
            if start_ip.version != end_ip.version: return []
            result_ips = []
            current_ip_int = int(start_ip)
            end_ip_int = int(end_ip)
            if current_ip_int > end_ip_int: return []
            if (end_ip_int - current_ip_int + 1) > 4096: return []
            for ip_int_val in range(current_ip_int, end_ip_int + 1):
                result_ips.append(str(ipaddress.ip_address(ip_int_val)))
            return result_ips
        else:
            single_ip = ipaddress.ip_address(ip_range_str_py.strip())
            return [str(single_ip)]
    except ValueError: return []

cpdef dict scan_ip_range(str ip_range_str_py, list ports_to_scan_py, double timeout_seconds=1.0):
    """
    (Cython) Scans a range of IP addresses for specified ports.

    Args:
        ip_range_str_py: The IP range string (e.g., "192.168.1.1-192.168.1.10").
        ports_to_scan_py: A list of port numbers to scan.
        timeout_seconds: Connection timeout for each port. Default is 1.0.

    Returns:
        A dictionary where keys are IP addresses and values are lists of open ports.
    """
    cdef dict results = {}
    cdef list ips_to_scan_py = _parse_ip_range_py(ip_range_str_py)
    cdef str ip_address_py_loopvar
    cdef list open_ports_py

    for ip_address_py_loopvar in ips_to_scan_py:
        if not isinstance(ip_address_py_loopvar, str): continue
        ip_address_bytes = ip_address_py_loopvar.encode('utf-8')
        open_ports_py = scan_ports_single_ip(ip_address_bytes, ports_to_scan_py, timeout_seconds) # Pass timeout
        if open_ports_py:
            results[ip_address_py_loopvar] = open_ports_py
    return results

cpdef dict scan_ip_list(list ip_list_py, list ports_to_scan_py, double timeout_seconds=1.0):
    """
    (Cython) Scans a list of IP addresses and/or IP ranges for specified ports.

    Args:
        ip_list_py: A list of IP/IP range strings.
        ports_to_scan_py: A list of port numbers to scan.
        timeout_seconds: Connection timeout for each port. Default is 1.0.

    Returns:
        A dictionary where keys are IP addresses and values are lists of open ports.
    """
    cdef dict aggregated_results = {}
    cdef str ip_definition_str_py_loopvar
    cdef dict range_results_py

    for ip_definition_str_py_loopvar in ip_list_py:
        if not isinstance(ip_definition_str_py_loopvar, str): continue
        range_results_py = scan_ip_range(ip_definition_str_py_loopvar, ports_to_scan_py, timeout_seconds) # Pass timeout
        aggregated_results.update(range_results_py)

    return aggregated_results
