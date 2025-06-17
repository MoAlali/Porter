#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>


unsigned short checksum(char *buf, int len) {
    unsigned int sum = 0;
    int i;

    for (i = 0; i < len - 1; i += 2) {
        unsigned short word = (buf[i] << 8) + (unsigned char)buf[i + 1];
        sum += word;
    }
    if (len % 2 == 1) {
        unsigned short word = (buf[len - 1] << 8);
        sum += word;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <IP>\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(argv[1]);

    char packet[64] = {0};
    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = 1;
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, sizeof(struct icmphdr));

    sendto(sock, packet, sizeof(struct icmphdr), 0, (struct sockaddr *)&addr, sizeof(addr));
    printf("ICMP Echo sent to %s\n", argv[1]);
    close(sock);
    return 0;
}
