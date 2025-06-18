import socket
import struct
import os
import time

def checksum(source_string):
    sum = 0
    countTo = (len(source_string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = source_string[count + 1] * 256 + source_string[count]
        sum += thisVal
        sum = sum & 0xffffffff
        count += 2

    if countTo < len(source_string):
        sum += source_string[-1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    return answer

def ping_icmp(host, timeout=1):
    try:
        icmp = socket.getprotobyname('icmp')
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as sock:
            sock.settimeout(timeout)

            packet_id = os.getpid() & 0xFFFF
            sequence = 1
            header = struct.pack('bbHHh', 8, 0, 0, packet_id, sequence)
            data = 192 * b'Q'

            my_checksum = checksum(header + data)
            header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), packet_id, sequence)
            packet = header + data

            sock.sendto(packet, (host, 1))
            start_time = time.time()

            while True:
                try:
                    recv_packet, addr = sock.recvfrom(1024)
                    icmp_header = recv_packet[20:28]
                    r_type, r_code, r_checksum, r_id, r_seq = struct.unpack('bbHHh', icmp_header)

                    if r_id == packet_id:
                        return True
                except socket.timeout:
                    return False
                if time.time() - start_time > timeout:
                    return False
    except Exception:
        return False

def get_ttl(host):
    try:
        icmp = socket.getprotobyname('icmp')
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as sock:
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
            packet_id = os.getpid() & 0xFFFF
            sequence = 1
            header = struct.pack('bbHHh', 8, 0, 0, packet_id, sequence)
            data = 192 * b'Q'

            my_checksum = checksum(header + data)
            header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), packet_id, sequence)
            packet = header + data

            sock.sendto(packet, (host, 1))
            start_time = time.time()

            while True:
                try:
                    recv_packet, addr = sock.recvfrom(1024)
                    icmp_header = recv_packet[20:28]
                    r_type, r_code, r_checksum, r_id, r_seq = struct.unpack('bbHHh', icmp_header)

                    if r_id == packet_id:
                        ttl = recv_packet[8]  # TTL is in the IP header at offset 8
                        return ttl
                except socket.timeout:
                    return None
                if time.time() - start_time > 1:
                    return None
    except Exception:
        return None