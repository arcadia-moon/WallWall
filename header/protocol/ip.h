#pragma once
#include <stdint.h>
/*
#define IPPROTO_IP 0
#define IPPROTO_ICMP 1
#define IPPROTO_IGMP 2
#define IPPROTO_IPIP 4
#define IPPROTO_TCP	6
#define IPPROTO_EGP	8
#define IPPROTO_PUP	12
#define IPPROTO_UDP	17
#define IPPROTO_IDP	22
#define IPPROTO_TP 29
#define IPPROTO_DCCP 33
#define IPPROTO_IPV6 41
#define IPPROTO_RSVP 46	
#define IPPROTO_GRE	47
#define IPPROTO_ESP	50
#define IPPROTO_AH 51
#define IPPROTO_MTP	92
#define IPPROTO_BEETPH 94
#define IPPROTO_ENCAP 98
#define IPPROTO_PIM 103
#define IPPROTO_COMP 108
#define IPPROTO_SCTP 132
#define IPPROTO_UDPLITE 136
#define IPPROTO_MPLS 137
#define IPPROTO_RAW	255
*/

struct ip_addr
{
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
};

struct ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl : 4; /* header length */
    unsigned int ip_v : 4;  /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v : 4;  /* version */
    unsigned int ip_hl : 4; /* header length */
#endif
    uint8_t ip_tos;         /* type of service */
    uint16_t ip_len;          /* total length */
    uint16_t ip_id;           /* identification */
    uint16_t ip_off;          /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    uint8_t ip_ttl;         /* time to live */
    uint8_t ip_p;           /* protocol */
    uint16_t ip_sum;          /* checksum */
    ip_addr ip_src;
    ip_addr ip_dst; /* source and dest address */
};
