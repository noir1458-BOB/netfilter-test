#pragma once
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#pragma pack(push, 1) 
struct Ipv4 {
    enum IPV4_PROTOCOL : uint8_t {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    ENCAP = 41,
    OSPF = 89,
    SCTP = 132
    };

    uint8_t v_h_len;
    uint8_t DSCP_ESN;
    uint16_t tot_len;
    uint16_t id;
    uint16_t flags_fragmentoffset;
    uint8_t ttl;
    IPV4_PROTOCOL protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;

    void Print_src();
    void Print_dst();

    uint8_t Get_v();
    uint8_t Get_hlen();
    uint16_t Get_id();
    uint8_t Get_protocol();
    uint32_t Get_src();
    uint32_t Get_dst();
};
#pragma pack(pop)



