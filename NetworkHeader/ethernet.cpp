#include "ethernet.h"

void Ethernet::Print_src(){
    for(int i=0;i<6;i++){
        printf("%02x",src_mac[i]);
        if(i!=5) printf(":");
    }
    printf("\n");
}

void Ethernet::Print_dst(){
    for(int i=0;i<6;i++){
        printf("%02x",dst_mac[i]);
        if(i!=5) printf(":");
    }
    printf("\n");
}

void Ethernet::Print_type(){
    if (ntohs(eth_type) == 0x0800)
    printf("IPv4\n");
    else if (ntohs(eth_type) == 0x0806)
    printf("ARP\n");
    else if (ntohs(eth_type) == 0x86DD)
    printf("IPv6\n");
    else printf("ERROR\n");
    
}

uint8_t* Ethernet::Get_src(){
    return src_mac;
}
uint8_t* Ethernet::Get_dst(){
    return dst_mac;
}
Ethernet::Eth_type Ethernet::Get_type(){
    return eth_type;
}