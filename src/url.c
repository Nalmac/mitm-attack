/**
 *  Jiazi Yi
 *
 * LIX, Ecole Polytechnique
 * jiazi.yi@polytechnique.edu
 *
 * Updated by Pierre Pfister
 *
 * Cisco Systems
 * ppfister@cisco.com
 *
 */

#include "url.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Tool function to handle memory deallocation (born from code reviews with
 * Claude)*/
static void cleanup_info_url(url_info *info) {
  free(info->protocol);
  info->protocol = NULL;
  free(info->host);
  info->host = NULL;
  free(info->path);
  info->path = NULL;
}

/**
 * parse a URL and store the information in info.
 * return 0 on success, or an integer on failure.
 *
 * Note that this function will heavily modify the 'url' string
 * by adding end-of-string delimiters '\0' into it, hence chunking it into
 * smaller pieces. In general this would be avoided, but it will be simpler
 * this way.
 */

int parse_url(char *url, url_info *info) {
  // url format: [http://]<hostname>[:<port>]/<path>
  // e.g. https://www.polytechnique.edu:80/index.php

  char *column_slash_slash, *host_name_path, *protocol;

  column_slash_slash = strstr(url, "://");
  // it searches :// in the string. if exists,
  // return the pointer to the first char of the match string

  if (column_slash_slash != NULL) {          // protocol type exists
    *column_slash_slash = '\0';              // end of the protocol type
    host_name_path = column_slash_slash + 3; // jump to the host name
    protocol = url;
  } else { // no protocol type: using http by default.
    host_name_path = url;
    protocol = "http";
  }
  /*Storing protocol type*/
  info->protocol = malloc(strlen(protocol) + 1);
  if (info->protocol != NULL) {
    strcpy(info->protocol, protocol);
  } else {
    cleanup_info_url(info);
    return PARSE_URL_MALLOC_FAILED;
  }

  /*
   * To be completed:
   * 	 Return an error (PARSE_URL_PROTOCOL_UNKNOWN) if the protocol is not
   * 'http' using strcmp.
   */
  if (strcmp(info->protocol, "http") != 0) {
    free(info->protocol);
    return PARSE_URL_PROTOCOL_UNKNOWN;
  }

  /*
   * To be completed:
   * 	 Look for the first '/' in host_name_path using strchr
   * 	 Return an error (PARSE_URL_NO_SLASH) if there is no such '/'
   * 	 Store the hostname and the queried path in the structure.
   *
   * 	 Note: The path is stored WITHOUT the first '/'.
   * 	       It simplifies this function, but I'll let you understand how. :-)
   */
  char *hostname_slash, *file;
  hostname_slash = strchr(host_name_path, '/');
  if (!hostname_slash) {
    cleanup_info_url(info);
    return PARSE_URL_NO_SLASH;
  } else {
    *hostname_slash = '\0';
    file = hostname_slash + 1;
    info->path = malloc(strlen(file) + 1);
    if (info->path != NULL) {
      strcpy(info->path, file);
    } else {
      cleanup_info_url(info);
      return PARSE_URL_MALLOC_FAILED;
    }
    info->host = malloc(strlen(host_name_path) + 1);
    if (info->host != NULL) {
      strcpy(info->host, host_name_path);
    } else {
      cleanup_info_url(info);
      return PARSE_URL_MALLOC_FAILED;
    }
  }

  /*
   * To be completed:
   * 	 Look for ':' in the hostname
   * 	 If ':' is not found, the port is 80 (store it)
   * 	 If ':' is found, split the string and use sscanf to parse the
   * port. Return an error if the port is not a number, and store it
   * otherwise.
   */
  char *port_column;
  port_column = strchr(info->host, ':');
  if (!port_column) {
    info->port = 80;
  } else {
    char *port_number = port_column + 1;
    *port_column = '\0';
    int ret = sscanf(port_number, "%d", &(info->port));
    if (ret != 1) {
      cleanup_info_url(info);
      return PARSE_URL_INVALID_PORT;
    }
  }

  // If everything went well, return 0.
  return 0;
}

/**
 * print the url info to std output
 */
void print_url_info(url_info *info) {
  printf("The URL contains following information: \n");
  printf("Protocol:\t%s\n", info->protocol);
  printf("Host name:\t%s\n", info->host);
  printf("Port No.:\t%d\n", info->port);
  printf("Path:\t\t/%s\n", info->path);
}

/**
 * Get the parsing error string to std output
 */
char *get_url_errstr(int err_code) {
  if (err_code < 5 && err_code >= 0) {
    return (char *)parse_url_errstr[err_code];
  } else {
    return "Unknown error";
  }
}
