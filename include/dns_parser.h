#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <stddef.h>
#include <sys/types.h>

// Masks for flags manipulation
#define DNS_QR (1 << 15)
#define DNS_OPCODE (0xF << 11)
#define DNS_AA (1 << 10)
#define DNS_TC (1 << 9)
#define DNS_RD (1 << 8)
#define DNS_RA (1 << 7)
#define DNS_Z (0x7 << 4)
#define DNS_RCODE (0xF << 0)

// Mask to read compression in dns message
#define DNS_MSG_COMPRESSION (3 << 6)

// The DNS packet has to be space-bound
#define DNS_MSG_SIZE                                                           \
  500 // Limit for a UDP packet = 512, but the DNS header is 12 bytes long
#define DNS_LABEL_SIZE 63
#define DOMAIN_MAX_LENGTH 255

#define DNS_HEADER_SIZE 12
/*
 *  DNS header structure
 *  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_header {
  u_int16_t id;
  u_int16_t flags; // We will set these with masks
  u_int16_t qdcount;
  u_int16_t ancount;
  u_int16_t nscount;
  u_int16_t arcount;
};

struct dns_packet {
  struct dns_header dnshdr;
  char content[DNS_MSG_SIZE];
};

// Setting values
void set_qr(int qr, u_int16_t *flags);
void set_opcode(int opcode, u_int16_t *flags);
void set_aa(int aa, u_int16_t *flags);
void set_tc(int tc, u_int16_t *flags);
void set_rd(int rd, u_int16_t *flags);
void set_ra(int ra, u_int16_t *flags);
void set_z(int z, u_int16_t *flags);
void set_rcode(int rcode, u_int16_t *flags);

// Reading
int get_qr(const u_int16_t *flags);
int get_opcode(const u_int16_t *flags);
int get_aa(const u_int16_t *flags);
int get_tc(const u_int16_t *flags);
int get_rd(const u_int16_t *flags);
int get_ra(const u_int16_t *flags);
int get_z(const u_int16_t *flags);
int get_rcode(const u_int16_t *flags);

// Reading hostname
int read_hostname(struct dns_packet packet, char *host,
                  const size_t host_bufsize);

#endif // !DNS_PARSER_H
