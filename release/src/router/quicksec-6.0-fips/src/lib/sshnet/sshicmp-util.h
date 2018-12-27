/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Convinience functions for handling ICMP
*/

#ifndef SSHICMP_UTIL_H
#define SSHICMP_UTIL_H


/* Convinience function for converting the 'icmp:type(1,0-255)' type
   field of an ICMP or IPV6ICMP traffic selector string in to the
   port encoded format */
char *
ssh_icmputil_string_to_tsstring(const char *string);

#endif /* SSHICMP_UTIL_H */
