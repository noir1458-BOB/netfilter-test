#include "addr_cast.h"

void mac_str_to_byte(std::string& mac_str, uint8_t* mac_bytes) {
    int byte_idx = 0;
    for(size_t i=0;i<mac_str.length();i+=3){ 
        char c1 = tolower(mac_str[i]);  
        char c2 = tolower(mac_str[i+1]);  
        uint8_t high = (c1 >= '0' && c1 <= '9') ? c1 - '0' : c1 - 'a' + 10;
        uint8_t low = (c2 >= '0' && c2 <= '9') ? c2 - '0' : c2 - 'a' + 10;
        mac_bytes[byte_idx++] = (high << 4) | low;
    }
}

std::string mac_byte_to_str(uint8_t* mac_bytes) {
    std::string tmp = "";
    for(int i=0;i<6;i++){
        char hex_str[3];
        sprintf(hex_str, "%02x", mac_bytes[i]);
        tmp += hex_str;
        if (i!=5) tmp += ':';
    }
    return tmp;
}

uint32_t ip_str_to_uint32(std::string& ip_str) {
    uint32_t tmp = 0;
    int shift = 24;
    int start = 0;
    std::string add_tmp;
    for(size_t i=0;i<ip_str.length();i++){
        if(ip_str[i]=='.'){
            add_tmp = ip_str.substr(start, i - start);
            tmp += atoi(add_tmp.c_str()) << shift;
            shift -= 8;
            start = i + 1;
        }
    }
    add_tmp = ip_str.substr(start);
    tmp += atoi(add_tmp.c_str()) << shift;  // shift 추가
    return tmp;
}

