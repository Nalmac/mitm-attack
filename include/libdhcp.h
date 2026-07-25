#ifndef LIBDHCP_H
#define LIBDHCP_H

#include <netinet/in.h>
#include <sys/types.h>
#define DHCP_RESPONSE_BUF_SIZE 576

#define DHCP_MAX_OPTIONS_SIZE 256
#define BROADCAST_STRADDR "255.255.255.255"
#define DHCP_MAGIC_COOKIE 0x63538263
#define END_MARKER 0xFF

/*
 *  A DHCP Header as specified in the RFC 2131 :
 *
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+
 * */
struct dhcp_msg {
  u_int8_t op;
  u_int8_t htype;
  u_int8_t hlen;
  u_int8_t hops;
  u_int32_t xid;
  u_int16_t secs;
  u_int16_t flags;
  u_int32_t ciaddr;
  u_int32_t yiaddr;
  u_int32_t siaddr;
  u_int32_t giaddr;
  u_int8_t chaddr[16];
  u_int8_t sname[64];
  u_int8_t file[128];
  u_int32_t magic_cookie;
  u_int8_t options[DHCP_MAX_OPTIONS_SIZE];
};

/*Struct to make TLV easier*/
struct tlv_value {
  u_int8_t type;
  u_int8_t length;
  u_int8_t value[256];
};

/*
 *  Enumeration for the DHCP message types, following the RFC 2132
 * */

enum dhcp_msg_type {
  DHCPDISCOVER = 1,
  DHCPOFFER = 2,
  DHCPREQUEST = 3,
  DHCPDECLINE = 4,
  DHCPACK = 5,
  DHCPNAK = 6,
  DHCPRELEASE = 7,
  DHCPINFORM = 8
};

/*
 *  Enumeration for the DHCP options
 * */
enum dhcp_options { BOOTREQUEST = 1, BOOTREPLY = 2 };

/*
 *  Enumeration for harware addresses type
 * */
enum hardware_address_type { ETHERNET = 1, ETHERNET_LEN = 6 };

#endif // !LIBDHCP_H
