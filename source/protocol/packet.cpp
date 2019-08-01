#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include "../../header/protocol/all.h"

#define MAX_MTU 1500

void printMACAddress(mac_addr mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void printIPAddress(ip_addr ipAddr)
{
    printf("%d.%d.%d.%d", ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}

void printTCPPort(uint16_t port)
{
    printf("%d", port);
}

void printPacket(const unsigned char *p, uint32_t size)
{
    int len = 0;
    while (len < size)
    {
        if(!(len % 16)) {
            printf("%04X  ", len);
        }
        printf("%02X ", *(p+len));
        if (!((len+1) % 8)){
            printf("   ");
        }
        len++;
        if (!((len) % 16) || (size - len) == 0)
        {
            int length = (size - len) == 0 ? size % 16 : 16; 
            if(length < 16) {
                for(int i=0;i<16-length;i++) {
                    printf("   ");
                    if (!((i+1) % 8)){
                        printf("   ");
                    }
                }
                printf("   ");
            }
            for(int i = 0; i<length; i++) {
                uint8_t nowChar = *(p+(len-(length-i)));
                if(nowChar >= 33 && nowChar <= 126) {
                    printf("%c ", nowChar);
                }
                else {
                    printf(". ");
                }
                if(!((i+1) % 8)) {
                    printf("   ");
                }
            }
            printf("\n");
        }
    }
}

bool equalIPAddr(ip_addr x, ip_addr y)
{
    return memcmp(&x, &y, sizeof(ip_addr))==0;
    //return x.a == y.a && x.b == y.b && x.c == y.c && x.d == y.d;
}
bool equalMACAddr(mac_addr x, mac_addr y)
{
    return memcmp(&x, &y, sizeof(mac_addr))==0;
    //return x.nic[0] == y.nic[0] && x.nic[1] == y.nic[1] && x.nic[2] == y.nic[2] && x.oui[0] == y.oui[0] && x.oui[1] == y.oui[1] && x.oui[2] == y.oui[2];
}