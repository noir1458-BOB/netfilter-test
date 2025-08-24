#pragma once
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#pragma pack(push, 1) 
struct Arp {
    enum ARP_HWTYPE : uint16_t {
    ETHERNET = 1
    };

    enum ARP_PROTOCOL : uint16_t {
        IPV4 = 0x0800
    };

    enum ARP_OPERATION : uint16_t {
        REQUEST = 1,
        REPLY = 2
    };
    static const int HEADER_LEN = 28;

    uint16_t hwtype;
    uint16_t protocol;
    uint8_t hw_len;
    uint8_t protocol_len;
    uint16_t operation;

    uint8_t src_mac[6]; 
    uint32_t src_ip;
    uint8_t dst_mac[6];
    uint32_t dst_ip;

    uint16_t Get_hwtype();
    uint16_t Get_protocol();
    uint16_t Get_operation();

    void Print_src_mac();
    void Print_dst_mac();
    void Print_src_ip();
    void Print_dst_ip();
};
#pragma pack(pop)