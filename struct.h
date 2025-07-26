#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>

struct ethernet_hdr
{
    u_int8_t  ether_dhost[6];   // destination ethernet address
    u_int8_t  ether_shost[6];   // source ethernet address
    u_int16_t ether_type;       // protocol: IPv4(0x0800)
};

struct ipv4_hdr
{
    u_int8_t ip_hl:4,               // header length = ip_hl * 4
           ip_v:4;                  // version 

    u_int8_t ip_tos;                // type of service 
    u_int16_t ip_len;               // total length 
    u_int16_t ip_id;                // identification 
    u_int16_t ip_off;               // flags 3 + fragment offset 13
    u_int8_t ip_ttl;                // time to live 
    u_int8_t ip_p;                  // protocol: TCP(0x06)
    u_int16_t ip_sum;               // checksum 
    struct in_addr ip_src, ip_dst;  // source and dest address
};

struct tcp_hdr
{
    u_int16_t th_sport;         // source port
    u_int16_t th_dport;         // destination port
    u_int32_t th_seq;           // sequence number
    u_int32_t th_ack;           // acknowledgement number
    u_int8_t th_x2:4,           // reserved 
           th_off:4;            // data offset: header length = th_off * 4
    u_int8_t  th_flags;         // control flags
    u_int16_t th_win;           // window
    u_int16_t th_sum;           // checksum
    u_int16_t th_urp;           // urgent pointer
};