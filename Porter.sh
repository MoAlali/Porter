#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Host Discovery
host_discovery() {
    target_host=$1
    echo -e "${CYAN}Checking if $target_host is up...${NC}"

    ping -c 1 -W 1 "$target_host" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}$target_host is UP (using ICMP ping)${NC}"
        return 0
    fi

    (echo > /dev/tcp/$target_host/80) >/dev/null 2>&1 && { echo -e "${GREEN}$target_host is UP (port 80)${NC}"; return 0; }
    (echo > /dev/tcp/$target_host/443) >/dev/null 2>&1 && { echo -e "${GREEN}$target_host is UP (port 443)${NC}"; return 0; }

    echo -e "${RED}$target_host is offline or not responding.${NC}"
    return 1
}

# TCP Scan
tcp_scan() {
    ports=()

    if [[ "$port_input" =~ ^[0-9]+-[0-9]+$ ]]; then
        IFS='-' read start_port end_port <<< "$port_input"
        for ((port=start_port; port<=end_port; port++)); do
            ports+=("$port")
        done
    else
        ports+=("$port_input")
    fi

    echo -e "${CYAN}Starting TCP scan on $target_host for ports: $port_input${NC}"
    for port in "${ports[@]}"; do
        (echo > /dev/tcp/$target_host/$port) >/dev/null 2>&1 && echo -e "${GREEN}TCP Port $port is open on $target_host${NC}"
    done
}

# UDP Scan (best-effort in Bash)
udp_scan() {
    echo -e "${RED}Note: UDP scanning via Bash is unreliable. For accurate results, use tools like nmap.${NC}"

    ports=()
    if [[ "$port_input" =~ ^[0-9]+-[0-9]+$ ]]; then
        IFS='-' read start_port end_port <<< "$port_input"
        for ((port=start_port; port<=end_port; port++)); do
            ports+=("$port")
        done
    else
        ports+=("$port_input")
    fi

    echo -e "${CYAN}Starting UDP scan on $target_host for ports: $port_input${NC}"
    for port in "${ports[@]}"; do
        (echo > /dev/udp/$target_host/$port) >/dev/null 2>&1 && echo -e "${GREEN}UDP Port $port is open (unconfirmed) on $target_host${NC}"
    done
}

# Port Scan Selector
port_scan() {
    if [[ "$scan_type" == "tcp" ]]; then
        tcp_scan
    elif [[ "$scan_type" == "udp" ]]; then
        udp_scan
    elif [[ -z "$scan_type" ]]; then
        echo -e "${CYAN}No scan type provided. Defaulting to TCP scan.${NC}"
        tcp_scan
    else
        echo -e "${RED}Invalid scan type. Defaulting to TCP scan.${NC}"
        tcp_scan
    fi
}

# Banner
echo -e "${CYAN}"
echo "  _____           _            "
echo " |  __ \         | |           "
echo " | |__) |__  _ __| |_ ___ _ __ "
echo " |  ___/ _ \| '__| __/ _ \ '__|"
echo " | |  | (_) | |  | ||  __/ |   "
echo " |_|   \___/|_|   \__\___|_|   "
echo "                               "
echo "         By Mohammed Aloli     "
echo -e "${NC}"
echo

# User Input
read -p "Enter target host IP: " target_host
host_discovery "$target_host"

if [[ $? -eq 0 ]]; then
    read -p "Enter port or port range to scan (e.g., 22 or 20-80): " port_input
    read -p "Scan type (tcp/udp): " scan_type
    port_scan
else
    echo -e "${RED}Exiting...$target_host is not reachable.${NC}"
    exit 1
fi
