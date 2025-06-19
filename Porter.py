import socket
import sys
import re
import custom_ping


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
            # elif send_ack_packet(target , 80):
            #      print(f"{GREEN}{target} is UP (using ACK){NC}")
            else:
                print(f"{RED}{target} is offline or not responding on ICMP.{NC}")
                print(f"{CYAN}Performing port scan on {target} to verify...{NC}")
                if portscan_verify:
                    port_os_detection(target)

    except Exception as e:
        print(f"{RED}Error during host discovery: {e}{NC}")

def detect_os(host , port_verify=False):
    print(f"{CYAN}Detecting OS for {host}...{NC}")
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
        print(f"{CYAN}Performing port scan on {host} to identify OS...{NC}")
        port_os_detection(host)
        

def port_os_detection(host):
    print(f"{CYAN}Performing port scan on {host} to identify OS...{NC}")
    os_ports = [
        22,    # SSH (Linux/Unix/macOS) need to check banner to be sure
        80,    # HTTP (common on all OS)
        135,   # MS RPC (Windows)
        139,   # NetBIOS (Windows)
        443,   # HTTPS (common on all OS)
        445,   # SMB (Windows, also used by Samba on Linux try banner grabbing to make sure 100%)
        3389,  # RDP (Windows)
        3306,  # MySQL (Linux/Windows)
        5432,  # PostgreSQL (Linux/Unix)
        6379,  # Redis (Linux/Unix)
        27017, # MongoDB (Linux/Unix)
    ]

    open_ports = tcp_scan(host, os_ports)
    if open_ports:
        if 3389 in open_ports or 445 in open_ports or 135 in open_ports or 139 in open_ports:
            print(f"{GREEN}Windows-specific ports detected on {host}. Likely a Windows machine!{NC}") 
            if 445 in open_ports:
                banner = banner_grabbing(host, 445)
                if banner and "samba" in banner.lower():
                    print(f"{GREEN}SMB (Samba) detected on {host}. Likely a Linux system!{NC}")
                else:
                    print(f"{GREEN}SMB detected on {host}. Likely a Windows system!{NC}")
                
        elif 22 in open_ports or 5432 in open_ports:
            print(f"{GREEN}Linux/Unix-specific ports detected on {host}. Likely a Linux/Unix system!{NC}")
        elif 5900 in open_ports:
            print(f"{GREEN}VNC detected on {host}. Could be Linux, macOS, or Windows with VNC!{NC}")
        elif 80 in open_ports or 443 in open_ports:
            print(f"{GREEN}HTTP/HTTPS detected on {host}. Could be any OS with a web server!{NC}")
            if 80 in open_ports:
                banner = send_get_request(host, 80)
                if banner:
                    banner_lower = banner.lower()
                    if "windows" in banner_lower:
                        print(f"{GREEN}HTTP banner indicates Windows OS on {host}!{NC}")
                    elif "ubuntu" in banner_lower:
                        print(f"{GREEN}HTTP banner indicates Ubuntu/linux OS on {host}!{NC}")
            if 443 in open_ports:
                banner = send_get_request(host, 443)
                if banner:
                    banner_lower = banner.lower()
                    if "windows" in banner_lower:
                        print(f"{GREEN}HTTPS banner indicates Windows OS on {host}!{NC}")
                    elif "ubuntu" in banner_lower:
                        print(f"{GREEN}HTTPS banner indicates Ubuntu OS on {host}!{NC}")
        else:
            print(f"{GREEN}Open ports on {host}: {open_ports}{NC}")
    else:
        print(f"{RED}No common OS-specific ports open on {host}.{NC}")
    
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

def single_host_discovery(host):
    print(f"{CYAN}Checking if {host} is up...{NC}")
    if custom_ping.ping_icmp(host):
        print(f"{GREEN}{host} is UP (using a ICMP){NC}")
        return True

    for port in [22,23,21,25,53,80,443,3306,5432]:
        common_banner_ports = [21,22, 23, 25,110, 143, 3306, 3389, 5900, 8080, 6379, 5432, 27017]
        try:
            with socket.create_connection((host, port), timeout=1):
                print(f"{GREEN}{host} is UP (port {port}){NC}")
                if port in common_banner_ports:
                    banner_grabbing(host, port)
                elif port == 80 or port == 443:
                    send_get_request(host, port)
                return True
        except:
            continue

    print(f"{RED}{host} is offline or not responding on ICMP, port 80, or port 443.{NC}")
    return False

def tcp_scan(host, ports):
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

# current ACK logic doesn't construct a real TCP ACK. TCP requires a raw socket for custom flags like ACK.
# i need to use libraries like scapy or raw sockets to send a real ACK packet.
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
def send_get_request(host, port):
    print(f"{CYAN}Sending GET request to {host}:{port}...{NC}")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((host, port))
            
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

           
            if b"HTTP/1.1" not in response and b"HTTP/2" not in response:
                request = f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode())
                response = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break

            headers = response.decode(errors='ignore').split('\r\n')
            server_header = None
            powered_by = None
            for header in headers:
                if header.lower().startswith('server:'):
                    server_header = header
                elif header.lower().startswith('x-powered-by:'):
                    powered_by = header
            if server_header:
                print(f"{GREEN}{server_header}{NC}")
            if powered_by:
                print(f"{GREEN}{powered_by}{NC}")
            if not server_header and not powered_by:
                print(f"{GREEN}Received response from {host}:{port} but no Server or X-Powered-By headers found.{NC}")

    except Exception as e: 
        print(f"{RED}Error sending GET request: {e}{NC}")

def banner_grabbing(host, port):
    print(f"{CYAN}Grabbing banner from {host}:{port}...{NC}")
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors='ignore')
        print(f"Banner from {host}:{port}:\n{banner}")
        s.close()
    except Exception as e:
        print(f"{RED}Failed to grab banner from {host}:{port}: {e}{NC}")
    
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
    if host.endswith('.0'):
        hosts_range = input("Enter host range (e.g., 1-254): ").strip()
        portscan_verify = False
        if input("Do you want to perform a port scan to identify the OS? Enter 'yes' to do or press Enter to ignore: ").strip().lower() == "yes":
            portscan_verify = True
        parsed_hosts_range = parse_host_range(hosts_range , host)
        if (portscan_verify):
            hosts_discovery(parsed_hosts_range ,True)
        else:
            hosts_discovery(parsed_hosts_range)
    elif input('Do you want to perform a OS detection scan? Enter "yes" to do or press Enter to ignore: ').strip().lower() == "yes":
        if single_host_discovery(host):
            detect_os(host, port_verify=True)
            print(f"{GREEN}OS detection completed.{NC}")
        else:
            print(f"{RED}Exiting... {host} is not reachable.{NC}")
            sys.exit(1)
    else:
        
        port_input = input("Enter port or port range to scan (e.g., 22 or 20-80): ").strip()
        scan_type = input("Scan type (tcp/udp): ").strip().lower()
        # host_discovery(host)
        ports = parse_ports(port_input)

        if single_host_discovery(host):
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