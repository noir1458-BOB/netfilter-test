#include "ipv4.h"

void Ipv4::Print_src(){
    uint32_t tmp = src_ip;
    for(int i=0;i<4;i++){
        printf("%d",(tmp&0x000000FF));
        tmp = tmp >> 8;
        if(i!=3) printf(".");
    }
    printf("\n");
}
void Ipv4::Print_dst(){
    uint32_t tmp = dst_ip;
    for(int i=0;i<4;i++){
        printf("%d",(tmp&0x000000FF));
        tmp = tmp >> 8;
        if(i!=3) printf(".");
    }
    printf("\n");
}

uint8_t Ipv4::Get_v(){
    return (v_h_len >> 4);
}
uint8_t Ipv4::Get_hlen(){
    return (v_h_len & 0x0F) * 4;
}
uint16_t Ipv4::Get_id(){
    return id;
}
uint8_t Ipv4::Get_protocol(){
    return protocol;
}
uint32_t Ipv4::Get_src(){
    return ntohl(src_ip);
}
uint32_t Ipv4::Get_dst(){
    return ntohl(dst_ip);
}