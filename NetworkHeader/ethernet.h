#pragma once
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#pragma pack(push, 1) 
struct Ethernet {
    enum Eth_type : uint16_t {
    IPV4 = 0x0800,
    ARP = 0x0806,
    IPV6 = 0x86DD,
    };
    static const int HEADER_LEN = 14;

    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    Eth_type eth_type;

    void Print_src();
    void Print_dst();
    void Print_type();

    uint8_t* Get_src();
    uint8_t* Get_dst();
    Eth_type Get_type();
};
#pragma pack(pop)

