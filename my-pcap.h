#pragma once

#include "struct.h"

bool packet_handler(const struct pcap_pkthdr *pkthdr, const u_char *packet);
git pull origin main --rebase
void packet_capture(pcap_t* pcap);