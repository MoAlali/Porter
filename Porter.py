import socket
import sys
import re
import custom_ping_icmp
# TODO try to make the script use multiple threads for scanning ports to speed up the process.


GREEN = '\033[0;32m'
RED = '\033[0;31m'
CYAN = '\033[0;36m'
NC = '\033[0m'  

# TODO: Implement a function to discover hosts in a subnet using other methods
# such as ARP requests or other protocols if ICMP is blocked.
def hosts_discovery(host):
    print(f"{CYAN}Starting host discovery for {host}...{NC}")
    try:
        for i in range(1, 255):
            target = f"{host[:-1]}{i}"
            if custom_ping_icmp.custom_ping_icmp(target):
                print(f"{GREEN}{target} is UP (using ICMP){NC}")
                
            else:
                print(f"{RED}{target} is DOWN{NC}")
    except Exception as e:
        print(f"{RED}Error during host discovery: {e}{NC}")


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
    if custom_ping_icmp.custom_ping_icmp(host):
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
    print(f"{CYAN}Starting TCP scan on {host} for ports: {ports}{NC}")
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=1):
                print(f"{GREEN}TCP Port {port} is open on {host}{NC}")
        except:
            pass

def udp_scan(host, ports):
    print(f"{CYAN}Starting UDP scan on {host} for ports: {ports}{NC}")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (host, port))
            sock.recvfrom(1024)
            print(f"{GREEN}UDP Port {port} is open on {host}{NC}")
        except socket.timeout:
            print(f"{GREEN}UDP Port {port} is open|filtered on {host} (no response){NC}")
        except:
            pass
        finally:
            sock.close()

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

def main():
    print_banner()
    host = input("Enter target host IP: ").strip()

    
    if host.endswith('.0'):
        hosts_discovery(host)
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