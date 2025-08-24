#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <cctype>

void mac_str_to_byte(std::string& mac_str, uint8_t* mac_bytes);
std::string mac_byte_to_str(uint8_t* mac_bytes);
uint32_t ip_str_to_uint32(std::string& ip_str);