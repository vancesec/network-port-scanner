import socket
import termcolor
import threading
from queue import Queue


def scan_port(ip_address, port):
    """Scans a single port on the given IP address."""
    try:
        sock = socket.socket()
        sock.settimeout(1)  # Set a timeout for the connection
        sock.connect((ip_address, port))
        print(termcolor.colored(f"[+] Port {port} is Open on {ip_address}", "green"))
        sock.close()
    except (socket.timeout, ConnectionRefusedError):
        pass  # Ignore closed ports
    except Exception as e:
        print(termcolor.colored(f"[!] Error on {ip_address}:{port} - {e}", "red"))


def scan_target(target, ports):
    """Scans all specified ports on the given target."""
    print(termcolor.colored(f"\n[*] Starting Scan for {target}", "blue"))
    for port in ports:
        scan_port(target, port)


def worker():
    """Thread worker function to scan ports from the queue."""
    while not q.empty():
        ip_address, port = q.get()
        scan_port(ip_address, port)
        q.task_done()


def multi_threaded_scan(target, port_range):
    """Performs a multi-threaded scan on a target."""
    print(termcolor.colored(f"\n[*] Multi-threaded Scan for {target}", "blue"))
    for port in port_range:
        q.put((target, port))

    for _ in range(50):  # Number of threads
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()

    q.join()


def validate_ports(num_ports):
    """Validates the port range input."""
    try:
        num_ports = int(num_ports)
        if 1 <= num_ports <= 65535:
            return num_ports
        else:
            raise ValueError
    except ValueError:
        print(termcolor.colored("[!] Invalid port range! Enter a number between 1 and 65535.", "red"))
        exit()


def validate_targets(targets):
    """Validates and returns the list of target IPs."""
    return [ip.strip() for ip in targets.split(",")]


# Main execution
if __name__ == "__main__":
    targets = input("[*] Enter Targets to Scan (comma-separated): ")
    ports = validate_ports(input("[*] Enter How Many Ports You Want to Scan: "))
    port_range = range(1, ports + 1)

    targets_list = validate_targets(targets)

    q = Queue()  # Queue for threading

    if len(targets_list) > 1:
        print(termcolor.colored("[*] Scanning Multiple Targets", "green"))
        for target in targets_list:
            multi_threaded_scan(target, port_range)
    else:
        single_target = targets_list[0]
        multi_threaded_scan(single_target, port_range)

    print(termcolor.colored("[*] Scanning Completed!", "yellow"))
