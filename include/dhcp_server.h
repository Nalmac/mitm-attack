#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

#include "inaddr_db.h"
#include "libdhcp.h"
#include <sys/types.h>
struct server_config {
  u_int32_t dns_server_addr;
  u_int32_t subnet_mask;
  u_int32_t server_ip;
  u_int32_t default_gateway;
  u_int32_t broadcast;
  u_int32_t renewal;
  u_int32_t rebind;
  int lease_time;
};

struct communication_config {
  u_int32_t xid;
  u_int8_t chaddr[16];
};

struct fake_server_args {
  struct inaddr_db *db;
  struct server_config config;
};

int create_socket();

void write_tlv(struct tlv_value option, void **options_ptr,
               int *remaining_space);

void write_option(u_int8_t type, u_int8_t length, u_int32_t value,
                  void **options_ptr, int *remaining_space);

int send_dhcp_offer(int sfd, struct server_config config, u_int32_t in_addr,
                    struct communication_config comm);

int send_dhcp_ack(int sfd, struct server_config config, u_int32_t in_addr,
                  struct communication_config comm);

void *fake_server(void *raw_args);

#endif // !DHCP_SERVER_H
