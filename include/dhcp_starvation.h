#ifndef DHCP_STARVATION_H
#define DHCP_STARVATION_H

#include "inaddr_db.h"
#include <netinet/in.h>
#include <sys/types.h>

#define MAX_OFFER_ITER 150

/*================================ Functions ===========================*/

int starvation(struct inaddr_db *db);

#endif
