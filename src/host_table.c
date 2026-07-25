#include "host_table.h"
#include "dns_parser.h"
#include <netinet/in.h>
#include <string.h>

/*
 *  Makes some serious assumptions on watchlist. It has to be a properly
 * populated array of struct host
 * */
int get_host(const struct host *watchlist, char *hostname, struct host *host) {
  for (int i = 0; i < WATCHLIST_LEN; i++) {
    if (strcmp(watchlist[i].host, hostname) == 0) {
      strncpy(host->ip, watchlist[i].ip, INET_ADDRSTRLEN);
      return 0;
    }
  }
  return -1;
}
