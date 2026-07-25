#ifndef INADDR_DB_H
#define INADDR_DB_H
#include <stddef.h>
#include <sys/types.h>

/*
 *  We will be using a simple queue to store the IP addresses stolen from the
 * legitimate DHCP server
 * */

struct inaddr_db {
  size_t capacity;
  size_t size;
  u_int32_t *data;
  int first;
  int last;
};

int init_inaddr_db(struct inaddr_db *db, size_t capacity);
int push(u_int32_t ip, struct inaddr_db *db);
int pop(struct inaddr_db *db, u_int32_t *ip);
int is_empty(struct inaddr_db db);
int is_full(struct inaddr_db);
void free_db(struct inaddr_db *db);

#endif // INADDR_DB_H
