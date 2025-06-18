import socket
import sys
import re
import custom_ping
# TODO try to make the script use multiple threads for scanning ports to speed up the process.


GREEN = '\033[0;32m'
RED = '\033[0;31m'
CYAN = '\033[0;36m'
NC = '\033[0m'  

# TODO: Implement a function to discover hosts in a subnet using other methods
# such as Ack requests or other protocols if ICMP is blocked.

def hosts_discovery(hosts , portscan_verify=False):
    print(f"{CYAN}Starting host discovery for {hosts}...{NC}")
    try:
        for target in hosts:
            if custom_ping.ping_icmp(target):
                print(f"{GREEN}{target} is UP (using ICMP){NC}")
                detect_os(target, port_verify=portscan_verify)
            else:
                print(f"{RED}{target} is offline or not responding on ICMP.{NC}")

    except Exception as e:
        print(f"{RED}Error during host discovery: {e}{NC}")

# TODO: i need to try to determine the OS using a different method
def detect_os(host , port_verify=False):
    print(f"{CYAN}Detecting OS for {host}...{NC}")
    if custom_ping.get_ttl(host):
        ttl = custom_ping.get_ttl(host)
        if ttl is not None:
            if ttl <= 1:
                print(f"{GREEN}Target {host} is likely a loopback or heavily filtered firewall.{NC}")
            elif ttl <= 20:
                print(f"{GREEN}Target {host} is likely running HP-UX or an older networking device.{NC}")
            elif ttl <= 30:
                print(f"{GREEN}Target {host} is likely running an older version of Windows.{NC}")
                if (port_verify):
                   port_os_detection(host)
            elif ttl <= 60:
                print(f"{GREEN}Target {host} is likely running macOS (older versions).{NC}")
            elif ttl <= 64:
                print(f"{GREEN}Target {host} is likely running Linux.{NC}")
                if (port_verify):
                   port_os_detection(host)
            elif ttl <= 128:
                print(f"{GREEN}Target {host} is likely running Windows.{NC}")

            elif ttl <= 255:
                print(f"{GREEN}Target {host} is likely running Cisco, Solaris, or AIX.{NC}")
            else:
                print(f"{GREEN}Target {host} has an unknown OS.{NC}")
        else:
            print(f"{RED}Could not determine TTL for {host}.{NC}")

def port_os_detection(host):
    # i need to change the list
    common_ports = [22, 23, 80, 443, 3306, 8080]
    open_ports = []
    tcp_scan(host, common_ports)
    
def print_banner():
    print(CYAN)
    print("  _____           _            ")
    print(" |  __ \         | |           ")
    print(" | |__) |__  _ __| |_ ___ _ __ ")
    print(" |  ___/ _ \| '__| __/ _ \ '__|")
    print(" | |  | (_) | |  | ||  __/ |   ")
    print(" |_|   \___/|_|   \__\___|_|   ")
    print("                               ")
    print("       By Mohammed Aloli       ")
    print(NC)

def host_discovery(host):
    print(f"{CYAN}Checking if {host} is up...{NC}")
    if custom_ping.ping_icmp(host):
        print(f"{GREEN}{host} is UP (using a ICMP){NC}")
        return True


    for port in [80, 443]:
        try:
            with socket.create_connection((host, port), timeout=1):
                print(f"{GREEN}{host} is UP (port {port}){NC}")
                return True
        except:
            continue

    print(f"{RED}{host} is offline or not responding on ICMP, port 80, or port 443.{NC}")
    return False

def tcp_scan(host, ports):
    print(ports)
    open_tcp_ports = []
    print(f"{CYAN}Starting TCP scan on {host} for ports: {ports}{NC}")
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=1):
                print(f"{GREEN}TCP Port {port} is open on {host}{NC}")
                open_tcp_ports.append(port)
        except:
            pass
    return open_tcp_ports
def udp_scan(host, ports):
    print(ports)
    print(f"{CYAN}Starting UDP scan on {host} for ports: {ports}{NC}")
    open_udp_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (host, port))
            sock.recvfrom(1024)
            print(f"{GREEN}UDP Port {port} is open on {host}{NC}")
            open_udp_ports.append(port)
        except socket.timeout:
            print(f"{GREEN}UDP Port {port} is open|filtered on {host} (no response){NC}")
        except:
            pass
        finally:
            sock.close()
    return open_udp_ports

def send_ack_packet(host, port):
    print(f"{CYAN}Sending ACK packet to {host}:{port}...{NC}")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((host, port))
            sock.sendall(b'\x00\x00\x00\x00')  # Placeholder for ACK payload
            response = sock.recv(1024)
            print(f"{GREEN}Received ACK response from {host}:{port}:\n{response}{NC}")

    except Exception as e:
        print(f"{RED}Error sending ACK packet: {e}{NC}")

def banner_grabbing(host, port):
    print(f"{CYAN}Grabbing banner from {host}:{port}...{NC}")
    s = socket.socket()
    # s.settimeout(7)
    s.connect((host, port))
    banner = s.recv(1024).decode(errors='ignore')
    print(f"Banner from {host}:{port}:\n{banner}")
    
def parse_ports(port_input):
    ports = []
    if re.match(r'^\d+-\d+$', port_input):
        start, end = map(int, port_input.split('-'))
        ports = list(range(start, end + 1))
    elif port_input.isdigit():
        ports = [int(port_input)]
    else:
        print(f"{RED}Invalid port format. Use single port (22) or range (20-80).{NC}")
        sys.exit(1)
    return ports
def parse_host_range(host_range , host):
    hosts = []
    if re.match(r'^\d+-\d+$', host_range):
        start, end = map(int, host_range.split('-'))
        base = '.'.join(host.split('.')[:-1])
        hosts = [f"{base}.{i}" for i in range(start, end + 1)]
    elif host_range.isdigit():
        base = '.'.join(host.split('.')[:-1])
        hosts = [f"{base}.{host_range}"]
    else:
        print(f"{RED}Invalid host format. Use single host (22) or range (1-254).{NC}")
        sys.exit(1)
    return hosts
def main():
    print_banner()

    host = input("Enter target host IP: ").strip()
    banner_grabbing(host,443)
    if host.endswith('.0'):
        hosts_range = input("Enter host range (e.g., 1-254): ").strip()
        if input("Do you want to perform a port scan to identify the OS? Enter 'yes' to do or press Enter to ignore: ").strip().lower() == "yes":
            portscan_verify = True
        parsed_hosts_range = parse_host_range(hosts_range , host)
        if (portscan_verify):
            hosts_discovery(parsed_hosts_range ,True)
        else:
            hosts_discovery(parsed_hosts_range)

    else:
        port_input = input("Enter port or port range to scan (e.g., 22 or 20-80): ").strip()
        scan_type = input("Scan type (tcp/udp): ").strip().lower()
        host_discovery(host)
        ports = parse_ports(port_input)

        if host_discovery(host):
            if scan_type == "udp":
                udp_scan(host, ports)
            else:
                tcp_scan(host, ports)
            print(f"{GREEN}Port scan completed.{NC}")
        else:
            print(f"{RED}Exiting... {host} is not reachable.{NC}")
            sys.exit(1)

if __name__ == "__main__":
    main()