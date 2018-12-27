/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef VXWORKS
#include "sshincludes.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#else /* HAVE_NETINET_IN_H */
#ifndef WINDOWS /* already defined in most OS */
struct in_addr {
  SshUInt32 s_addr;
};
#endif /* ! WINDOWS */
#endif /* HAVE_NETINET_IN_H */

char *inet_ntoa(struct in_addr in)
{
  unsigned char *b;
  static char outstring[16];

  b = (unsigned char *)(&(in.s_addr));
  ssh_snprintf(outstring, sizeof(outstring),
               "%d.%d.%d.%d", (int)(b[0]), (int)(b[1]),
               (int)(b[2]), (int)(b[3]));

  return outstring;
}
#endif /* VXWORKS */
