#pragma once
#include <stdint.h>
#include "protocol/all.h"

void printMACAddress(mac_addr);
void printIPAddress(ip_addr);
void printTCPPort(uint16_t);

void packetParse(eth_header*, const u_char *, int *);

void printPacket(const unsigned char *, uint32_t);

void _printPacket(const unsigned char *, uint32_t);

bool equalIPAddr(ip_addr, ip_addr);
bool equalMACAddr(mac_addr, mac_addr);