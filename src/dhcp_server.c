#include "dhcp_server.h"
#include "inaddr_db.h"
#include "libdhcp.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int create_socket() {
  // Opening socket
  int sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sfd == -1) {
    fprintf(stderr, "[!] Failed to create socket : %s\n", strerror(errno));
    return -1;
  }

  // Binding to port 67
  struct sockaddr_in bind_addr = {0};
  bind_addr.sin_port = htons(67);
  bind_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "0.0.0.0", &bind_addr.sin_addr.s_addr);

  // Setting a few options
  // Setup broadcast
  int broadcast = 1;
  if (setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                 sizeof(broadcast)) == -1) {
    fprintf(stderr, "[!] Failed to enable broadcast: %s\n", strerror(errno));
    close(sfd);
    return -1;
  }

  // Binding to specific interface
  const char *iface = "ceth-lab-att";
  if (setsockopt(sfd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) ==
      -1) {
    fprintf(stderr, "[!] Failed to bind to interface: %s\n", strerror(errno));
    close(sfd);
    return -1;
  }
  if (bind(sfd, (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) ==
      -1) {
    fprintf(stderr, "[!] Failed to bind socket while opening server : %s\n",
            strerror(errno));
    return -1;
  }

  return sfd;
}

void write_tlv(struct tlv_value option, void **options_ptr,
               int *remaining_space) {

  *remaining_space -= option.length + 2;
  if (*remaining_space < 0) {
    fprintf(stderr, "[!] Too many options already, could not write\n");
    return;
  }
  memcpy(*options_ptr, &option.type, sizeof(u_int8_t));
  *options_ptr += sizeof(u_int8_t);
  memcpy(*options_ptr, &option.length, sizeof(u_int8_t));
  *options_ptr += sizeof(u_int8_t);
  memcpy(*options_ptr, &option.value, option.length);
  *options_ptr += option.length;
  memset(*options_ptr, END_MARKER, 1);
}

void write_option(u_int8_t type, u_int8_t length, u_int32_t value,
                  void **options_ptr, int *remaining_space) {
  struct tlv_value option = {0};
  option.type = type;
  option.length = length;
  memcpy(&option.value, &value, length);
  write_tlv(option, options_ptr, remaining_space);
}

int send_dhcp_message(int sfd, struct server_config config, u_int32_t in_addr,
                      struct communication_config comm, u_int8_t message_type) {

  struct sockaddr_in bdcast = {0};
  bdcast.sin_port = htons(68);
  bdcast.sin_family = AF_INET;
  inet_pton(AF_INET, BROADCAST_STRADDR, &bdcast.sin_addr.s_addr);

  struct dhcp_msg message = {0};
  message.yiaddr = in_addr;
  message.siaddr = config.server_ip;
  message.xid = comm.xid;
  message.htype = ETHERNET;
  message.hlen = ETHERNET_LEN;
  printf("%s\n", comm.chaddr);
  memcpy(&message.chaddr, &comm.chaddr, sizeof(u_int8_t) * message.hlen);
  message.flags = htons(0x8000);
  message.magic_cookie = DHCP_MAGIC_COOKIE;
  message.op = 2;

  // Setting up the options
  int empty_options = DHCP_MAX_OPTIONS_SIZE;
  u_int8_t *options_ptr = &(message.options[0]);

  // Type of message
  write_option(53, 1, message_type, (void **)&options_ptr, &empty_options);

  // Server IP
  write_option(54, 4, config.server_ip, (void **)&options_ptr, &empty_options);

  // Lease time
  write_option(51, 4, config.lease_time, (void **)&options_ptr, &empty_options);

  // Renewal
  write_option(58, 4, config.renewal, (void **)&options_ptr, &empty_options);

  // Rebinding
  write_option(59, 4, config.rebind, (void **)&options_ptr, &empty_options);

  // Subnet mask
  write_option(1, 4, config.subnet_mask, (void **)&options_ptr, &empty_options);

  // Broadcast
  write_option(28, 4, config.broadcast, (void **)&options_ptr, &empty_options);

  // DNS
  write_option(6, 4, config.dns_server_addr, (void **)&options_ptr,
               &empty_options);

  // Gateway
  write_option(3, 4, config.default_gateway, (void **)&options_ptr,
               &empty_options);

  if (sendto(sfd, &message, sizeof(struct dhcp_msg), 0,
             (struct sockaddr *)&bdcast, sizeof(struct sockaddr_in)) <= 0) {
    fprintf(stderr, "[!] Failed to send OFFER message : %s\n", strerror(errno));
    return -1;
  }
  printf("[+] Sent DHCP message !\n");
  return 0;
}

u_int8_t get_dhcp_message_type(struct dhcp_msg msg) {
  int i = 0;
  for (; i < DHCP_MAX_OPTIONS_SIZE && msg.options[i] != 53; i++) {
  }

  if (msg.options[i] != 53) {
    fprintf(stderr, "[!] DHCP message contained no type field ! That's a "
                    "malformed packet if I've ever seen one...\n");
    return -1;
  }
  // Expected message type stands on one byte so we will only read one byte. If
  // the client sends weird packets then we drop them.
  return msg.options[i + 2];
}

int answer_to_packet(int sfd, struct dhcp_msg msg, struct server_config config,
                     struct inaddr_db db) {
  u_int8_t msg_type = get_dhcp_message_type(msg);
  u_int32_t in_addr = 0;
  int i = 0;
  struct communication_config comm = {0};

  switch (msg_type) {
  case DHCPDISCOVER:
    if (pop(&db, &in_addr) == -1) {
      fprintf(stderr, "[!] Unable to accomodate client, IP pool is empty\n");
      return -1;
    }
    memcpy(&comm.chaddr, &msg.chaddr, sizeof(u_int8_t) * 16);
    comm.xid = msg.xid;
    if (send_dhcp_message(sfd, config, in_addr, comm, DHCPOFFER) == -1) {
      fprintf(stderr, "[!] Failed to send DHCP OFFER\n");
      push(in_addr, &db);
      return -1;
    }
    printf("[+] Sent DHCP OFFER successfully !\n");
    break;
  case DHCPREQUEST:
    for (; i < DHCP_MAX_OPTIONS_SIZE && msg.options[i] != 50; i++)
      ;
    if (msg.options[i] != 50) {
      fprintf(stderr, "[!] Client requested nothing !\n");
      return -1;
    }
    memcpy(&in_addr, &msg.options[i + 2], sizeof(u_int32_t));
    memcpy(&comm.chaddr, &msg.chaddr, sizeof(u_int8_t) * 16);
    comm.xid = msg.xid;
    if (send_dhcp_message(sfd, config, in_addr, comm, DHCPACK) == -1) {
      fprintf(stderr, "[!] Failed to send DHCP ACK\n");
      push(in_addr, &db);
      return -1;
    }
    printf("[+] Sent DHCP ACK successfully !\n");
    break;
  default:
    fprintf(stderr, "[!] Unsupported message type, dropping packet...\n");
  }

  return 0;
}

void *fake_server(void *raw_args) {
  struct fake_server_args *args = (struct fake_server_args *)raw_args;
  struct server_config config = args->config;
  struct inaddr_db db = *args->db;
  int sfd = create_socket();
  struct dhcp_msg msg_buf = {0};
  printf("[+] Listening for DHCP requests\n");
  while (recv(sfd, &msg_buf, sizeof(struct dhcp_msg), 0)) {
    if (answer_to_packet(sfd, msg_buf, config, db) == -1) {
      fprintf(stderr, "[!] Error while answering packet !\n");
    }
  }
  close(sfd);
  return NULL;
}
