#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

// 이더넷 헤더 구조체
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];    /* destination eth addr */
    u_int8_t  ether_shost[6];    /* source ether addr    */
    u_int16_t ether_type;        /* packet type ID field */
};

// IP 헤더 구조체
struct libnet_ipv4_hdr
{
    u_int8_t ip_vhl;             /* version << 4 | header length >> 2 */
    u_int8_t ip_tos;             /* type of service */
    u_int16_t ip_len;            /* total length */
    u_int16_t ip_id;             /* identification */
    u_int16_t ip_off;            /* fragment offset field */
    u_int8_t ip_ttl;             /* time to live */
    u_int8_t ip_p;               /* protocol */
    u_int16_t ip_sum;            /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

// TCP 헤더 구조체
struct libnet_tcp_hdr
{
    u_int16_t th_sport;          /* source port */
    u_int16_t th_dport;          /* destination port */
    u_int32_t th_seq;            /* sequence number */
    u_int32_t th_ack;            /* acknowledgement number */
    u_int8_t th_x2:4,           /* unused */
    th_off:4;                   /* data offset */
    u_int8_t  th_flags;          /* control flags */
    u_int16_t th_win;            /* window */
    u_int16_t th_sum;            /* checksum */
    u_int16_t th_urp;            /* urgent pointer */
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(u_int8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const u_char* data, int length) {
    int print_len = length > 20 ? 20 : length;
    printf("Payload: ");
    for(int i = 0; i < print_len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void analyze_packet(const u_char* packet, int caplen) {
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;

     printf("Packet captured! Length: %d\n", caplen);  // 디버깅 메시지

    // IP 패킷인지 확인
    if (ntohs(eth_hdr->ether_type) != 0x0800)
        return;

    // 이더넷 헤더 출력
    printf("\n[Ethernet Header]\n");
    printf("Source MAC: ");
    print_mac(eth_hdr->ether_shost);
    printf("\nDestination MAC: ");
    print_mac(eth_hdr->ether_dhost);
    printf("\n");

    // IP 헤더
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

    // TCP 패킷인지 확인
    if (ip_hdr->ip_p != IPPROTO_TCP)
        return;

    // IP 헤더 출력
    printf("\n[IP Header]\n");
    printf("Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

    // TCP 헤더
    int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;
    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header_len);

    // TCP 헤더 출력
    printf("\n[TCP Header]\n");
    printf("Source Port: %d\n", ntohs(tcp_hdr->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_hdr->th_dport));

    // 페이로드 계산 및 출력
    int tcp_header_len = tcp_hdr->th_off * 4;
    int total_headers_len = sizeof(struct libnet_ethernet_hdr) + ip_header_len + tcp_header_len;
    int payload_len = caplen - total_headers_len;

    if (payload_len > 0) {
        const u_char* payload = packet + total_headers_len;
        printf("\n[Payload]\n");
        print_payload(payload, payload_len);
    }

    printf("\n----------------------------------------\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        analyze_packet(packet, header->caplen);
    }

    pcap_close(pcap);
    return 0;
}
