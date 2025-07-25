#include "struct.h"
#include "parse.h"
#include "my-pcap.h"

int main(int argc, char* argv[]) {
    // #0. parsing
	if (!parse(&param, argc, argv))
		return -1;

    // #1. pcap open live_device
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    // #2. packet capture
    packet_capture(pcap);

	pcap_close(pcap);
    return 0;
}
