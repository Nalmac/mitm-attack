#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <sys/types.h>
#define DNS_BUFFER_SIZE 512
#define DNS_SERVER_IP "129.104.30.41"

void *run_dns_proxy(void *raw_args);
#endif // !DNS_SERVER_H
