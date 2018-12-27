/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header file for radius client library.
*/

#ifndef SSHRADIUS_URL_H

#define SSHRADIUS_URL_H 1

#ifdef SSHDIST_RADIUS

typedef struct SshRadiusUrlAvpRec
{
  SshUInt8 *buf;
  SshUInt8 type;
  SshUInt8 len;
} SshRadiusUrlAvpStruct;

typedef struct SshRadiusUrlRequestRec
{
  /* Configuration provided by user */

  unsigned char **url;
  size_t nurls;

  SshRadiusUrlAvpSetStruct avp_set;

  SshRadiusClientRequestCB cb;
  void *ctx;

  /* Practical details */

  SshOperationHandle url_handle; /* Our operation handle */

  SshOperationHandle op_handle; /* ssh_radius_client_request() handle */
  SshRadiusClientRequest req;   /* Actual request */
  SshRadiusClientServerInfo s_info; /* Server info, etc.. */
  size_t url_idx;

  SshRadiusClient rad_client;
  SshRadiusClientParamsStruct rad_params;
} *SshRadiusUrlRequest, SshRadiusUrlStruct;

#endif /* SSHDIST_RADIUS */

#endif
