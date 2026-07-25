#include "dns_parser.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/*==================== Setting part ======================*/

void set_qr(int qr, u_int16_t *flags) {
  u_int16_t f = ntohs(*flags);
  if (qr) {
    f |= DNS_QR;
  } else {
    f &= ~DNS_QR;
  }
  *flags = htons(f);
}

void set_opcode(int opcode, u_int16_t *flags) {
  u_int16_t f = ntohs(*flags);
  f = (f & ~DNS_OPCODE) | ((opcode & 0xF) << 11);
  *flags = htons(f);
}

void set_aa(int aa, u_int16_t *flags) {
  u_int16_t f = ntohs(*flags);
  if (aa) {
    f |= DNS_AA;
  } else {
    f &= ~DNS_AA;
  }
  *flags = htons(f);
}

void set_tc(int tc, u_int16_t *flags) {
  u_int16_t f = ntohs(*flags);
  if (tc) {
    f |= DNS_TC;
  } else {
    f &= ~DNS_TC;
  }
  *flags = htons(f);
}

void set_rd(int rd, u_int16_t *flags) {
  u_int16_t f = ntohs(*flags);
  if (rd) {
    f |= DNS_RD;
  } else {
    f &= ~DNS_RD;
  }
  *flags = htons(f);
}

void set_ra(int ra, u_int16_t *flags) {
  u_int16_t f = ntohs(*flags);
  if (ra) {
    f |= DNS_RA;
  } else {
    f &= ~DNS_RA;
  }
  *flags = htons(f);
}

void set_z(int z, u_int16_t *flags) {
  u_int16_t f = ntohs(*flags);
  f = (f & ~DNS_Z) | ((z & 0xF) << 4);
  *flags = htons(f);
}

void set_rcode(int rcode, u_int16_t *flags) {
  u_int16_t f = ntohs(*flags);
  f = (f & ~DNS_RCODE) | ((rcode & 0xF) << 0);
  *flags = htons(f);
}

/*======== Getting part ===========*/

int get_qr(const u_int16_t *flags) { return (ntohs(*flags) & DNS_QR) >> 15; }
int get_opcode(const u_int16_t *flags) {
  return (ntohs(*flags) & DNS_OPCODE) >> 11;
}
int get_aa(const u_int16_t *flags) { return (ntohs(*flags) & DNS_AA) >> 10; }
int get_tc(const u_int16_t *flags) { return (ntohs(*flags) & DNS_TC) >> 9; }
int get_rd(const u_int16_t *flags) { return (ntohs(*flags) & DNS_RD) >> 8; }
int get_ra(const u_int16_t *flags) { return (ntohs(*flags) & DNS_RA) >> 9; }
int get_z(const u_int16_t *flags) { return (ntohs(*flags) & DNS_Z) >> 4; }
int get_rcode(const u_int16_t *flags) {
  return (ntohs(*flags) & DNS_RCODE) >> 0;
}

/*========= Reading the requested host ========*/
int read_hostname(struct dns_packet packet, char *host, size_t host_bufsize) {
  if (get_qr(&packet.dnshdr.flags)) {
    fprintf(stderr, "[!] DNS packet is a response not a request !\n");
    return -1;
  }

  char *msg_ptr = packet.content;
  size_t host_size = 0;

  while (*msg_ptr != 0x00 && host_size < host_bufsize) {
    // Start by checking against the mask
    if ((*msg_ptr & DNS_MSG_COMPRESSION)) {
      fprintf(stderr, "[!] Message used compression, unsupported\n");
      return -1;
    }

    size_t length = (*msg_ptr & ~DNS_MSG_COMPRESSION);
    if (length > DNS_LABEL_SIZE) {
      fprintf(stderr, "[!] DNS message is way too big ! Dropping...\n");
      return -1;
    }
    if (msg_ptr + 1 + length > packet.content + DNS_MSG_SIZE) {
      fprintf(
          stderr,
          "[!] Malformed packet : length and packet size are inconsistent\n");
      return -1;
    }
    msg_ptr += 1;
    memcpy(host, msg_ptr, length);
    msg_ptr += length;
    host += length;
    *host = '.';
    host++;
    host_size += length + 1;
  }

  if (host_size > 0) {
    *(host - 1) = '\0';
  }

  return 0;
}
