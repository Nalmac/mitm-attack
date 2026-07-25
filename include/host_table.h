#ifndef HOST_TABLE_H
#define HOST_TABLE_H

#define WATCHLIST_LEN 1

#include "dns_parser.h"
#include <netinet/in.h>
struct host {
  char ip[INET_ADDRSTRLEN];
  char host[DOMAIN_MAX_LENGTH];
};

int get_host(const struct host *watchlist, char *hostname, struct host *host);

#endif // !HOST_TABLE_H
