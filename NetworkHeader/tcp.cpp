#include "tcp.h"

void Tcp::Print_src(){
    printf("%d\n",ntohs(src_port));
}
    
void Tcp::Print_dst(){
    printf("%d\n",ntohs(dst_port));
}

uint16_t Tcp::Get_src(){
    return ntohs(src_port);
}

uint16_t Tcp::Get_dst(){
    return ntohs(dst_port);
}

uint8_t Tcp::Get_hlen(){
    return ((dOffset_Rsrvd & 0xF0) >> 4) * 4;
}
