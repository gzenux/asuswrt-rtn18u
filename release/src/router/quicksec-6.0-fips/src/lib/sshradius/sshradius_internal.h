/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header file for radius client library.
*/

#ifndef SSHRADIUS_INTERNAL_H
#define SSHRADIUS_INTERNAL_H

#include "sshradius.h"
#include "sshtimeouts.h"
#include "sshinet.h"
#include "sshudp.h"
#include "sshcrypt.h"


/************************** Types and definitions ***************************/

/* The RFC 2865 specifies minimum and maximum packet sizes to be 20
   and 4096.  The RFC 2866 specifies the maximum packet size to 4095
   so we use here the biggest value. */
#define SSH_RADIUS_MIN_PACKET_SIZE 20
#define SSH_RADIUS_MAX_PACKET_SIZE 4096

/* The default UDP ports for radius access and accounting servers. */
#define SSH_RADIUS_ACCESS_DEFAULT_PORT          "1812"
#define SSH_RADIUS_ACCOUNTING_DEFAULT_PORT      "1813"

/* MD5 digest length and HMAC block size. */
#define SSH_RADIUS_MD5_LENGTH 16
#define SSH_RADIUS_HMAC_BLOCK 64

/* A radius client object. */
struct SshRadiusClientRec
{
  /* UDP listener. */
  SshUdpListener listener;

  /* Flags. */
  unsigned int destroyed : 1;   /* The client is destroyed. */

  /* Client parameters. */
  SshRadiusClientParamsStruct params;

  /* The NAS IP address, parsed from the parameter string. */
  SshIpAddrStruct nas_ip_addr;

  /* An MD5 hash. */
  SshHash hash;
  size_t hash_digest_length;

  /* List of pending requests. */
  SshRadiusClientRequest requests;

  /* Used request ID's. Must be kept in sync with pending requests, i.e.
     allocated request ID's. */
  SshUInt8 request_ids[32];
  SshUInt8 request_id_last_alloc;

  /* A zero-timeout that destroys the RADIUS client. */
  SshTimeoutStruct destroy_timeout;

  /* Buffer for incoming packets. */
  unsigned char datagram[SSH_RADIUS_MAX_PACKET_SIZE];
};

/* A radius server specification. */
struct SshRadiusClientServerSpecRec
{
  /* Flags. */
  unsigned int failed : 1;      /* The server has failed. */

  /* Server address. */
  unsigned char *address;

  /* UDP ports. */
  unsigned char *port;
  unsigned char *acct_port;

  /* Shared secret between radius client and server. */
  size_t secret_len;
  unsigned char *secret;
};

typedef struct SshRadiusClientServerSpecRec SshRadiusClientServerSpecStruct;
typedef struct SshRadiusClientServerSpecRec *SshRadiusClientServerSpec;

/* A radius server info object. */
struct SshRadiusClientServerInfoRec
{
  /* Number of references to this server info object. */
  SshUInt32 refcount;

  /* The index of the server to use for the next radius operation. */
  SshUInt32 next_server;

  /* Timer for which to check if failed servers have come up again. */
  SshTimeoutStruct retry_timer;

  /* Configured servers. */
  SshRadiusClientServerSpec servers;
  SshUInt32 num_servers;
  SshUInt32 num_servers_allocated;
};

/* A radius client request object. */
struct SshRadiusClientRequestRec
{
  /* Link field, used when the request is active and waiting for reply
     from the server. */
  struct SshRadiusClientRequestRec *next;

  /* Flags. */
  unsigned int accounting : 1;         /* Is this an accounting request. */
  unsigned int active : 1;             /* Operation is active. */
  unsigned int timeout_registered : 1; /* Retransmit timeout registered. */
  unsigned int nas_ip_addr_set : 1;    /* NAS-IP-Address set */
  unsigned int nas_identifier_set : 1; /* NAS-Identifier set. */
  unsigned int nas_port_set : 1;       /* NAS-Port set. */
  unsigned int nas_port_type_set : 1;  /* NAS-Port-Type set. */

  /* The radius client of this operation. */
  SshRadiusClient client;

  /* The radius servers, used for this operation. */
  SshRadiusClientServerInfo servers;

  /* The index of the curent server used for this request. */
  SshUInt32 current_server;

  /* The index of the server to which this request is explicitly bound to */
  int bound_server_index;

  /* The request packet. */
  unsigned char *request;
  size_t request_allocated;

  /* The number of bytes used from the request. */
  size_t request_used;

  /* The offset of a possible user password.  This has the value 0 if
     the AVP is not set. */
  size_t user_password_offset;

  /* The User-Password AVP in plain-text.  Its length can be derived
     from the `request' when we know that the AVP is at
     `user_password_offset'.  We must save the value here since we can
     send the request to multiple servers with different secret and we
     can not encrypt it multiple times. */
  unsigned char *user_password;

  /* The offset of a possible request authenticator.  This has the
     value 0 if the AVP is not set. */
  size_t authenticator_offset;

  /* The SshOperationHandle for this request. */
  SshOperationHandle handle;

  /* Completion callback and context for this request. */
  SshRadiusClientRequestCB callback;
  void *context;

  /* The current retransmission timer value. */
  SshUInt32 retransmit_timer;

  /* The number of retransmissions so far. */
  SshUInt32 num_retransmissions;

  /* Handle for retransmit timeout. */
  SshTimeoutStruct retransmit_timeout;

  /* Combined total number of retransmissions with multiple servers */
  SshUInt32 num_total_retransmissions;

  /* The response attributes.  This points to the client's UDP
     datagram buffer and must not be freed when destroying this
     request. */
  unsigned char *response_attributes;
  size_t response_attributes_len;
};

#endif /* not SSHRADIUS_INTERNAL_H */
