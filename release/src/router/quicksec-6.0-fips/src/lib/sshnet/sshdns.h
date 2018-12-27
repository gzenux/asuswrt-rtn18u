/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS top level.
*/

#ifndef SSHDNS_H
#define SSHDNS_H

/* Flags to be used by the DNS library. Each layer have separate bitmask for
   flags, which they can use to allocate their own flags. Each layer can be
   given the full flags bitmask, and they will ignore bits for the other
   layers. */
#define SSH_DNS_FLAGS_TRANSPORT_IMPL_MASK       0x000000ff
#define SSH_DNS_FLAGS_TRANSPORT_MASK            0x0000ff00
#define SSH_DNS_FLAGS_QUERY_MASK                0x00ff0000
/* Use TCP instead of UDP. */
#define SSH_DNS_FLAGS_QUERY_USE_TCP             0x00010000
#define SSH_DNS_FLAGS_REQUEST_MASK              0xff000000

#include "sshdnspacket.h"
#include "sshdnstransport.h"
#include "sshdnsnameserver.h"
#include "sshdnsquery.h"
#include "sshdnsrrsetcache.h"
#include "sshdnsresolver.h"

/* Maximum size of the udp packet we can receive. */
#define SSH_DNS_MAX_UDP_PACKET_SIZE 1600

/* Maximum size of the udp packet allowed. */
#define SSH_DNS_MAX_PACKET_SIZE 512

/* Maximum length of the name. */
#define SSH_DNS_MAX_NAME_LEN 255

/* Convert error code to string. */
const char *ssh_dns_response_code_string(SshDNSResponseCode code);

/* Convert error types to string. */
const char *ssh_dns_rrtype_string(SshDNSRRType type);

/* Render function to render names in dns format for %@ format string for
   ssh_e*printf */
int ssh_dns_name_render(unsigned char *buf, int buf_size, int precision,
                        void *datum);

/* Return handle to the internal name server dns resolver. This can
   be used to configure the dns resolver. */
SshDNSResolver ssh_name_server_resolver(void);

/* Print the resource data of type `type' to the given buffer. */
int ssh_dns_rrdata_print(unsigned char *buf, int buf_size,
                         SshDNSRRType type, unsigned char *rdata,
                         size_t rdlength, int indent);

#endif /* SSHDNS_H */
