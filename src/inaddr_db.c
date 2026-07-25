#include "inaddr_db.h"
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int init_inaddr_db(struct inaddr_db *db, size_t capacity) {
  db->capacity = capacity;
  db->data = malloc(db->capacity * sizeof(u_int32_t));
  if (!db->data) {
    return -1;
  }
  return 0;
}

int is_empty(struct inaddr_db db) {
  if (db.size == 0) {
    return 1;
  } else {
    return 0;
  }
}

int is_full(struct inaddr_db db) {
  if (db.size == db.capacity) {
    return 1;
  } else {
    return 0;
  }
}

int push(u_int32_t ip, struct inaddr_db *db) {
  if (is_full(*db)) {
    return -1;
  } else {
    db->size++;
    db->data[db->last] = ip;
    db->last = (db->last + 1) % db->capacity;
    return 0;
  }
}

int pop(struct inaddr_db *db, u_int32_t *ip) {
  if (is_empty(*db)) {
    return -1;
  } else {
    *ip = db->data[db->first];
    db->first = (db->first + 1) % db->capacity;
    db->size--;
    return 0;
  }
}

void free_db(struct inaddr_db *db) {
  free(db->data);
  db->data = NULL;
}
