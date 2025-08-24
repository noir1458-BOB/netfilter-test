#pragma once
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

#pragma pack(push, 1) 
struct Tcp {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t dOffset_Rsrvd;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;

    void Print_src();
    void Print_dst();

    uint16_t Get_src();
    uint16_t Get_dst();
    uint8_t Get_hlen();
};
#pragma pack(pop)