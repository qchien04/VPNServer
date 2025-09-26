#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define MAX_PACKET_SIZE 2000

int tun_alloc(const char *devname) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    return fd;
}

// Tính checksum cho ICMP
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short*)b;
    unsigned int sum=0;
    unsigned short result;
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    int tun_fd = tun_alloc("tun0");
    if (tun_fd < 0) return 1;

    std::cout << "TUN interface tun0 created, now run:\n";
    std::cout << "  sudo ip addr add 10.0.0.1/24 dev tun0\n";
    std::cout << "  sudo ip link set tun0 up\n";
    std::cout << "  sudo ip route add 192.168.50.0/24 dev tun0\n";
    std::cout << "Then ping 192.168.50.2\n";

    uint8_t buffer[MAX_PACKET_SIZE];
    while (true) {
        ssize_t nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("read");
            break;
        }
        struct iphdr *ip = (struct iphdr*)buffer;
        if (ip->protocol != IPPROTO_ICMP) continue;

        struct icmphdr *icmp = (struct icmphdr*)(buffer + ip->ihl*4);
        if (icmp->type == ICMP_ECHO) {
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

            std::cout << "Got ICMP Echo Request: "
                      << src_ip << " -> " << dst_ip << std::endl;

            // Đổi type thành Echo Reply
            icmp->type = ICMP_ECHOREPLY;
            icmp->checksum = 0;
            icmp->checksum = checksum((unsigned short*)icmp, nread - ip->ihl*4);

            // Đổi src/dst IP
            in_addr src, dst;
            src.s_addr = ip->saddr;
            dst.s_addr = ip->daddr;
            ip->saddr = dst.s_addr;
            ip->daddr = src.s_addr;

            // Ghi gói ICMP Echo Reply vào tun0
            write(tun_fd, buffer, nread);

            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));
            std::cout << "Sent ICMP Echo Reply: "
                      << src_ip << " -> " << dst_ip << std::endl;
        }
    }

    close(tun_fd);
    return 0;
}
