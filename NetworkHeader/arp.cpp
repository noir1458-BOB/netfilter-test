#include "arp.h"

uint16_t Arp::Get_hwtype(){
    return ntohs(hwtype);
}
uint16_t Arp::Get_protocol(){
    return ntohs(protocol);
}
uint16_t Arp::Get_operation(){
    return ntohs(operation);
}

void Arp::Print_src_mac(){
    for(int i=0;i<6;i++){
        printf("%02x",src_mac[i]);
        if(i!=5) printf(":");
    }
    printf("\n");
}
void Arp::Print_dst_mac(){
    for(int i=0;i<6;i++){
        printf("%02x",dst_mac[i]);
        if(i!=5) printf(":");
    }
    printf("\n");
}
void Arp::Print_src_ip(){
    uint32_t tmp = src_ip;
    for(int i=0;i<4;i++){
        printf("%d",(tmp&0x000000FF));
        tmp = tmp >> 8;
        if(i!=3) printf(".");
    }
    printf("\n");
}
void Arp::Print_dst_ip(){
    uint32_t tmp = dst_ip;
    for(int i=0;i<4;i++){
        printf("%d",(tmp&0x000000FF));
        tmp = tmp >> 8;
        if(i!=3) printf(".");
    }
    printf("\n");
}