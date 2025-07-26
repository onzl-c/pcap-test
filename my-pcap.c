#include "my-pcap.h"

bool packet_handler(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ethernet_hdr *eth = (struct ethernet_hdr *)packet;
    const struct ipv4_hdr *ip;
    const struct tcp_hdr *tcp;

    if (ntohs(eth->ether_type) == 0x0800) { // IPv4
        ip = (struct ipv4_hdr*)(packet + sizeof(struct ethernet_hdr));
        int ip_header_size = ip->ip_hl * 4;
        if (ip->ip_p == 0x06) { // TCP
            tcp = (struct tcp_hdr*)((u_char*)ip + ip_header_size);
            int tcp_header_size = tcp->th_off * 4;
            const u_char* payload = (const u_char*)tcp + tcp_header_size;
            int payload_size = ntohs(ip->ip_len) - ip_header_size - tcp_header_size;

            for (int i=0; i<6; i++) {
                printf("%02x", eth->ether_shost[i]);
                if (i != 5) printf(":");
            }
            printf(" -> ");
            for (int i = 0; i < 6; i++) {
                printf("%02x", eth->ether_dhost[i]);
                if (i != 5) printf(":");
            }
            printf(", ");
            printf("%s", inet_ntoa(ip->ip_src));
            printf(" -> ");
            printf("%s", inet_ntoa(ip->ip_dst));
            printf(", ");
            printf("%d", ntohs(tcp->th_sport));
            printf(" -> ");
            printf("%d", ntohs(tcp->th_dport));
            printf(", \n");

            if (payload_size > 0) {
                int print_len = payload_size > 20 ? 20 : payload_size;

                for (int i = 0; i < print_len; i++) {
                    printf("%02x", payload[i]); 
                    if (i != print_len - 1) printf("|");
                }
            }
            else printf("-");
            printf("\n");
        }
        else return false;
    }
    else return false;
    return true;
}

void packet_capture(pcap_t* pcap) {
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        bool is_tcp = packet_handler(header, packet);
        if (is_tcp) printf("============================================\n");
	}
}