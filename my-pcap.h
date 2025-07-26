#pragma once

#include "struct.h"

bool packet_handler(const struct pcap_pkthdr *pkthdr, const u_char *packet);

void packet_capture(pcap_t* pcap);