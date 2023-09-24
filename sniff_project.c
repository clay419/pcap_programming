#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    struct ip *ip_packet = (struct ip *) (packet + ETHER_HDR_LEN);

    if (ip_packet->ip_p != IPPROTO_TCP) {
        return; 
    }

    struct tcphdr *tcp_header = (struct tcphdr *) (packet + ETHER_HDR_LEN + (ip_packet->ip_hl << 2));

    printf("Ethernet Header:\n");
    printf("  src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("  dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    printf("IP Header:\n");
    printf("  src ip: %s\n", inet_ntoa(ip_packet->ip_src));
    printf("  dst ip: %s\n", inet_ntoa(ip_packet->ip_dst));

    printf("TCP Header:\n");
    printf("  src port: %d\n", ntohs(tcp_header->th_sport));
    printf("  dst port: %d\n", ntohs(tcp_header->th_dport));

    const unsigned char *data = packet + ETHER_HDR_LEN + (ip_packet->ip_hl << 2) + (tcp_header->th_off << 2);
    int data_length = pkthdr->len - (ETHER_HDR_LEN + (ip_packet->ip_hl << 2) + (tcp_header->th_off << 2));
    if (data_length > 0) {
        printf("Message (Data):\n");
        for (int i = 0; i < data_length; i++) {
            printf("%02x ", data[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
    }
    printf("\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "ens33";

    printf("Capturing on device: %s\n", dev);

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}
