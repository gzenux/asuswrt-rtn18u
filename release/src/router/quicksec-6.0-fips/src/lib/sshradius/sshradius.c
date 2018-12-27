/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Radius client implementation.
*/

#include "sshincludes.h"
#include "sshradius_internal.h"

#define SSH_DEBUG_MODULE "SshRadius"

/* The interval in seconds after which the library will try to connect
   to Radius servers that have previously found to have failed. */
#define SSH_RADIUS_CLIENT_SERVER_RETRY_TIMER (10 * 60)

/******************* Prototypes for static help functions *******************/

/* This function is called periodically from a timeout and marks all servers
   previously found to have failed as up again. */
static void ssh_radius_client_server_retry_timer(void *context);

/* A timeout that destroys the radius client `context'. */
static void ssh_radius_client_destroy_real(void *context);

/* Remove the request `request' from the client's list of pending
   requests.  The operation must be active and registered to a client
   when calling this function. */
static void ssh_radius_request_dequeue(SshRadiusClientRequest request);

/* A timeout callback to send the request `context'.  This is also
   used to do the initial send operation. */
static void ssh_radius_request_timeout(void *context);

/* Prepare the request `request' for the next server in the requests'
   server info. */
static SshRadiusClientRequestStatus
ssh_radius_client_request_prepare(SshRadiusClientRequest request);

/* Abort callback for SshOperationHandle. */
static void ssh_radius_request_abort(void *context);

/* Encrypt the `data_len' bytes of data in `data' using the radius
   password hiding. */
static void ssh_radius_encrypt(SshRadiusClientRequest request,
                               unsigned char *data, size_t data_len);

/* Check the reply message authenticator. */
static Boolean ssh_radius_check_reply_auth(SshRadiusClientRequest request,
                                           unsigned char *data,
                                           size_t data_len,
                                           size_t auth_offset);

/* Simple HMAC-MD5 computation for the Message-Authenticator AVP
   [RFC2869]. */
static Boolean ssh_radius_req_msg_authenticator(
                                        SshRadiusClientRequest request);

/* UDP callback for receiving replies. */
static void ssh_radius_udp_callback(SshUdpListener listener, void *context);


/****************** Creating and destroying radius clients ******************/

SshRadiusClient
ssh_radius_client_create(SshRadiusClientParams params)
{
  SshRadiusClient client;

  client = ssh_calloc(1, sizeof(*client));
  if (client == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate memory for client context"));
      goto error;
    }

  /* Init parameters. */
  if (params)
    {
      memcpy(&client->params, params, sizeof(*params));

      if (client->params.nas_ip_address)
        {
          if (!ssh_ipaddr_parse(&client->nas_ip_addr,
                                client->params.nas_ip_address)
              || !SSH_IP_DEFINED(&client->nas_ip_addr))
            {
              SSH_DEBUG(SSH_D_ERROR, ("Invalid NAS-IP-Address `%s'",
                                      client->params.nas_ip_address));
              /* Set NAS-Identifier to NULL so we won't free the
                 user's copy of the value. */
              client->params.nas_identifier = NULL;
              goto error;
            }
          client->params.nas_ip_address = NULL;
        }

      if (client->params.nas_identifier)
        {
          client->params.nas_identifier
            = ssh_strdup(client->params.nas_identifier);
          if (client->params.nas_identifier == NULL)
            goto error;
        }
    }

  if (client->params.address == NULL)
    client->params.address = (unsigned char *) SSH_IPADDR_ANY;

  if (client->params.max_retransmit_timer == 0)
    client->params.max_retransmit_timer = 8;

  if (client->params.max_retransmissions == 0)
    client->params.max_retransmissions = 4;

  /* Create an UDP listener. */
  client->listener = ssh_udp_make_listener(client->params.address,
                                           client->params.port,
                                           NULL, NULL, -1, 0, NULL,
                                           ssh_radius_udp_callback,
                                           client);
  if (client->listener == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not start UDP listener"));
      goto error;
    }

  /* Allocate an MD5 hash. */
  if (ssh_hash_allocate("md5", &client->hash) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate MD5 hash"));
      goto error;
    }

  client->hash_digest_length
    = ssh_hash_digest_length(ssh_hash_name(client->hash));

  /* Clear dangling user pointers from parameters. */
  client->params.address = NULL;
  client->params.port = NULL;

  return client;


  /* Error handling. */

 error:

  if (client)
    {
      if (client->params.nas_identifier)
        ssh_free(client->params.nas_identifier);

      if (client->listener)
        ssh_udp_destroy_listener(client->listener);
      if (client->hash)
        ssh_hash_free(client->hash);

      ssh_free(client);
    }

  return NULL;
}


void
ssh_radius_client_cancel_all_requests(SshRadiusClient client)
{
  if (client == NULL || client->destroyed)
    return;


  while (client->requests != NULL)
    {
      SshRadiusClientRequest request = client->requests;

      /* Remove a reference from the servers. */
      ssh_radius_client_server_info_destroy(request->servers);

      ssh_operation_unregister(request->handle);

      request->servers = NULL;

      ssh_radius_request_dequeue(request);
      (*request->callback)(
              SSH_RADIUS_CLIENT_REQ_CANCELLED,
              request,
              0,
              request->context);
    }
}


void
ssh_radius_client_destroy(SshRadiusClient client)
{
  if (client == NULL || client->destroyed)
    return;

  client->destroyed = 1;

  /* Destroy the client from the bottom of the event loop. */
  ssh_register_timeout(&client->destroy_timeout, 0, 0,
                       ssh_radius_client_destroy_real, client);
}


unsigned int
ssh_radius_client_request_get_retranmit_count(
        SshRadiusClientRequest request)
{
  return request->num_total_retransmissions;
}


/************************ Configuring RADIUS servers ************************/

SshRadiusClientServerInfo
ssh_radius_client_server_info_create(void)
{
  SshRadiusClientServerInfo info;

  info = ssh_calloc(1, sizeof(*info));
  if (info == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate server info"));
      return NULL;
    }

  ssh_register_timeout(&info->retry_timer,
                       SSH_RADIUS_CLIENT_SERVER_RETRY_TIMER, 0,
                       ssh_radius_client_server_retry_timer, info);

  info->refcount = 1;

  return info;
}


void
ssh_radius_client_server_info_destroy(SshRadiusClientServerInfo info)
{
  SshUInt32 i;

  if (info == NULL)
    return;

  if (--info->refcount > 0)
    /* This was not the last reference. */
    return;

  /* Cancel timeouts. */
  ssh_cancel_timeout(&info->retry_timer);

  for (i = 0; i < info->num_servers; i++)
    {
      ssh_free(info->servers[i].address);
      ssh_free(info->servers[i].port);
      ssh_free(info->servers[i].acct_port);
      ssh_free(info->servers[i].secret);
    }

  ssh_free(info->servers);
  ssh_free(info);
}


Boolean
ssh_radius_client_server_info_add_server(SshRadiusClientServerInfo info,
                                         const unsigned char *server_addr,
                                         const unsigned char *server_port,
                                         const unsigned char *server_acct_port,
                                         const unsigned char *secret,
                                         size_t secret_len)
{
  SshRadiusClientServerSpec s;
  int i;

  /* Scan if we already have this server configured */

  if (server_port == NULL)
    server_port = (unsigned char *)SSH_RADIUS_ACCESS_DEFAULT_PORT;

  if (server_acct_port == NULL)
    server_acct_port = (unsigned char *)SSH_RADIUS_ACCOUNTING_DEFAULT_PORT;

  for (i = 0; i < info->num_servers; i++)
    {
      s = &info->servers[i];
      if (ssh_ustrcmp(s->address, server_addr) == 0
          && ssh_ustrcmp(s->port, server_port) == 0
          && ssh_ustrcmp(s->acct_port, server_acct_port) == 0
          && s->secret_len == secret_len
          && ssh_ustrcmp(s->secret, secret) == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Duplicate server entry for the client."));
          return TRUE;
        }
    }

  /* Do we have space for a new server? */
  if (info->num_servers >= info->num_servers_allocated)
    {
      /* Let's expand our array. */
      s = ssh_realloc(info->servers,
                      info->num_servers_allocated * sizeof(*s),
                      (info->num_servers_allocated + 3) * sizeof(*s));
      if (s == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not allocate space for a new server"));
          return FALSE;
        }

      info->servers = s;
      info->num_servers_allocated += 3;
    }

  s = &info->servers[info->num_servers];

  s->failed = 0;

  s->address = ssh_strdup(server_addr);
  s->port = ssh_strdup(server_port);
  s->acct_port = ssh_strdup(server_acct_port);
  s->secret = ssh_memdup(secret, secret_len);
  s->secret_len = secret_len;

  if (s->address == NULL || s->port == NULL || s->acct_port == NULL
      || s->secret == NULL)
    {
      ssh_free(s->address);
      ssh_free(s->port);
      ssh_free(s->acct_port);
      ssh_free(s->secret);

      return FALSE;
    }

  /* Server added. */
  info->num_servers++;

  return TRUE;
}


/***************************** Client requests ******************************/

SshRadiusClientRequest
ssh_radius_client_request_create(SshRadiusClient radius_client,
                                 SshRadiusOperationCode code)
{
  SshRadiusClientRequest req;
  size_t i;

  SSH_ASSERT(code == SSH_RADIUS_ACCESS_REQUEST
             || code == SSH_RADIUS_ACCOUNTING_REQUEST);

  req = ssh_calloc(1, sizeof(*req));
  if (req == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate client request"));
      goto error;
    }

  /* Allocate request buffer with decent default size. */
  req->request_allocated = 128;
  req->request = ssh_malloc(req->request_allocated);
  if (req->request == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate request buffer"));
      goto error;
    }

  if (code == SSH_RADIUS_ACCOUNTING_REQUEST)
    req->accounting = 1;

  req->client = radius_client;

  /* Prepare packet header.  The `Identifier' and `Length' fields are
     left unset.  They are set when we actually send the request.
     Also, the `Request Authenticator' for accounting requests is set
     when the packet is send. */

  req->request[0] = (unsigned char) code;

  if (!req->accounting)
    for (i = 0; i < 16; i++)
      req->request[4 + i] = ssh_random_get_byte();

  /* So far we have only consumed the header. */
  req->request_used = 20;

  /* Use next usable server */
  req->bound_server_index = -1;

  /* All done. */
  return req;


  /* Error handling. */

 error:

  if (req)
    {
      ssh_free(req->request);
      ssh_free(req);
    }

  return NULL;
}


void
ssh_radius_client_request_destroy(SshRadiusClientRequest request)
{
  if (request == NULL)
    return;

  /* The request must not be active. */
  SSH_ASSERT(!request->active);

  /* Release the possible server reference. */
  ssh_radius_client_server_info_destroy(request->servers);

  ssh_free(request->request);
  ssh_free(request->user_password);
  ssh_free(request);
}

SshRadiusAvpStatus
ssh_radius_client_request_add_vs_attribute(SshRadiusClientRequest request,
                                           SshRadiusVendorId vendor_id,
                                           unsigned int vs_type,
                                           const unsigned char *value,
                                           size_t value_len)
{
  unsigned char *tmpbuf;
  SshRadiusAvpStatus ret;

  if (vendor_id == SSH_RADIUS_VENDOR_ID_NONE)
    return ssh_radius_client_request_add_attribute(request,vs_type,
                                                    value,value_len);

  tmpbuf = ssh_malloc(value_len + 4 + 2);

  if (tmpbuf == NULL)
    return SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY;

  SSH_PUT_32BIT(tmpbuf,vendor_id);
  tmpbuf[4] = (SshUInt8)vs_type;
  tmpbuf[5] = value_len + 2;
  memcpy(tmpbuf+6,value,value_len);

  ret = ssh_radius_client_request_add_attribute(request,
                                                SSH_RADIUS_AVP_VENDOR_SPECIFIC,
                                                tmpbuf,
                                                value_len+6);

  ssh_free(tmpbuf);
  return ret;
}

SshRadiusAvpStatus
ssh_radius_client_request_add_attribute(SshRadiusClientRequest request,
                                        SshRadiusAvpType type,
                                        const unsigned char *value,
                                        size_t value_len)
{
  size_t pad_len = 0;
  size_t size;
  unsigned char *ucp;

  SSH_ASSERT(!request->active);

  /* Compute the possible padding. */
  if (type == SSH_RADIUS_AVP_USER_PASSWORD)
    {
      if (request->user_password_offset > 0)
        /* The User-Password is already set. */
        return SSH_RADIUS_AVP_STATUS_ALREADY_EXISTS;

      pad_len = value_len % 16;
      if (pad_len)
        pad_len = 16 - pad_len;
    }

  if (type == SSH_RADIUS_AVP_MESSAGE_AUTHENTICATOR)
    {
      if (request->authenticator_offset > 0)
        /* The User-Password is already set. */
        return SSH_RADIUS_AVP_STATUS_ALREADY_EXISTS;

      value_len = 0;
      pad_len = 16;
    }

  /* Is the value valid? */
  if (value_len + pad_len > 253)
    return SSH_RADIUS_AVP_STATUS_VALUE_TOO_LONG;

  /* Does the request has space for this attribute. */
  if (request->request_used + 2 + value_len + pad_len
      > SSH_RADIUS_MAX_PACKET_SIZE)
    return SSH_RADIUS_AVP_STATUS_TOO_MANY;

  /* Expand buffer if needed. */
  if (request->request_used + 2 + value_len + pad_len
      > request->request_allocated)
    {
      /* Compute new buffer size. */
      for (size = request->request_allocated;
           request->request_used + 2 + value_len + pad_len > size;
           size *= 2)
        ;
      if (size > SSH_RADIUS_MAX_PACKET_SIZE)
        size = SSH_RADIUS_MAX_PACKET_SIZE;
      SSH_ASSERT(request->request_used + 2 + value_len + pad_len <= size);

      ucp = ssh_realloc(request->request, request->request_allocated, size);
      if (ucp == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not expand request buffer"));
          return SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY;
        }

      request->request = ucp;
      request->request_allocated = size;
    }

  /* Add this attribute. */

  ucp = request->request + request->request_used;
  ucp[0] = (unsigned char) type;
  ucp[1] = (unsigned char) (2 + value_len + pad_len);
  memcpy(ucp + 2, value, value_len);
  memset(ucp + 2 + value_len, 0, pad_len);

  /* Check if we need any special handling for the value. */
  switch (type)
    {
    case SSH_RADIUS_AVP_USER_PASSWORD:
      request->user_password_offset = request->request_used;
      break;

    case SSH_RADIUS_AVP_NAS_PORT:
      request->nas_port_set = 1;
      break;

    case SSH_RADIUS_AVP_NAS_PORT_TYPE:
      request->nas_port_type_set = 1;
      break;

    case SSH_RADIUS_AVP_NAS_IP_ADDRESS:
    case SSH_RADIUS_AVP_NAS_IPV6_ADDRESS:
      request->nas_ip_addr_set = 1;
      break;

    case SSH_RADIUS_AVP_NAS_IDENTIFIER:
      request->nas_identifier_set = 1;
      break;

    case SSH_RADIUS_AVP_MESSAGE_AUTHENTICATOR:
      request->authenticator_offset = request->request_used;
      break;

    default:
      break;
    }

  request->request_used += 2 + value_len + pad_len;

  return SSH_RADIUS_AVP_STATUS_SUCCESS;
}

SshOperationHandle
ssh_radius_client_request(SshRadiusClientRequest request,
                          SshRadiusClientServerInfo servers,
                          SshRadiusClientRequestCB callback,
                          void *context)
{
  SshRadiusClientRequestStatus status;

  SSH_ASSERT(!request->active);

  /* Release the possible old server reference. */
  ssh_radius_client_server_info_destroy(request->servers);

  /* Take a reference to the servers. */
  servers->refcount++;
  request->servers = servers;
  request->current_server = servers->next_server++;

  if (servers->next_server >= servers->num_servers)
    servers->next_server = 0;

  /* Prepare the request for the next server in the servers array. */
  status = ssh_radius_client_request_prepare(request);
  if (status == SSH_RADIUS_CLIENT_REQ_TIMEOUT)
    {
      /* All servers have timeouted.  In case there is only one server
         clear the failed flag and retry.
      */
      if (servers->num_servers == 1)
        {
          servers->servers[0].failed = 0;
          status = ssh_radius_client_request_prepare(request);
        }
    }

  if (status != SSH_RADIUS_CLIENT_REQ_SUCCESS)
    {
      /* Remove a reference from the servers. */
      ssh_radius_client_server_info_destroy(servers);
      request->servers = NULL;

      (*callback)(status, request, 0, context);
      return NULL;
    }

  /* Link the request to the client's list of active requests. */
  request->next = request->client->requests;
  request->client->requests = request;

  request->callback = callback;
  request->context = context;

  /* All done.  Just wrap the request in an SshOperationHandle. */
  request->handle = ssh_operation_register(ssh_radius_request_abort,
                                           request);
  if (!request->handle)
    {
      /* Remove a reference from the servers. */
      ssh_radius_client_server_info_destroy(servers);
      request->servers = NULL;

      ssh_radius_request_dequeue(request);
      (*callback)(SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES,
                  request, 0, context);

      return NULL;
    }

  /* Send request. */
  ssh_radius_request_timeout(request);

  return request->handle;
}

Boolean ssh_radius_client_request_get_server(SshRadiusClientRequest request,
                                             int *server_index)
{
  if (request->servers != NULL
      && request->current_server < request->servers->num_servers)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Request current server index %d",
                              request->current_server));
      *server_index = (int) request->current_server;
      return TRUE;
    }

  (*server_index) = -1;
  return FALSE;
}

Boolean ssh_radius_client_request_set_server(SshRadiusClientRequest request,
                                             SshRadiusClientServerInfo servers,
                                             int server_index)
{
  if (server_index >= servers->num_servers)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid server index %d (num servers %d)",
                             server_index, servers->num_servers));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Request bound to server index %d", server_index));
  request->bound_server_index = server_index;
  return TRUE;
}

/************************ Reply processing functions ************************/

static Boolean
ssh_radius_decrypt_ms_mppe_attribute(SshRadiusClientRequest request,
                                     unsigned char *data,
                                     size_t *return_len)
{
  SshRadiusClientServerSpec server;
  SshHash hash = request->client->hash;
  unsigned char *tmp, digest[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char prev_block[16];
  size_t i, orig_data_len, data_len;

  tmp = data;

  SSH_ASSERT(data[0] == SSH_RADIUS_VENDOR_MS_MPPE_SEND_KEY ||
             data[0] == SSH_RADIUS_VENDOR_MS_MPPE_RECV_KEY);

  /* We must use MD5 hash */
  SSH_ASSERT(!strcmp(ssh_hash_name(request->client->hash), "md5"));
  SSH_ASSERT(request->client->hash_digest_length == 16);

  data_len = orig_data_len = tmp[1];

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Attribute before decryption (length %d)",
                                  data_len), data, data_len);

  if ((data_len <= 4) || ((data_len - 4) % 16 != 0))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Data length is not a multiple of 16"));
      return FALSE;
    }
  /* Take a shortcut to our server. */
  server = &request->servers->servers[request->current_server];

  /* Count the initial hash. */
  ssh_hash_reset(hash);
  ssh_hash_update(hash, server->secret, server->secret_len);
  ssh_hash_update(hash, request->request + 4, 16);

  /* Hash the salt value */
  ssh_hash_update(hash, tmp + 2, 2);

  /* Skip over the type, length and salt */
  tmp += 4;
  data_len -= 4;

  while (1)
    {
      SSH_ASSERT(data_len >= 16);
      if (ssh_hash_final(hash, digest) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("ssh_hash_final failed"));
          return FALSE;
        }

      memcpy(prev_block, tmp, 16);

      for (i = 0; i < 16 && data_len > 0; i++)
        {
          tmp[i] ^= digest[i];
          data_len--;
        }
      tmp += 16;

      if (data_len <= 0)
        /* All done. */
        break;

      /* Continue */
      ssh_hash_reset(hash);
      ssh_hash_update(hash, server->secret, server->secret_len);
      ssh_hash_update(hash, prev_block, 16);
    }

  *return_len = data[4];

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                    ("Decrpyted attribute (orig/return length %d/%d)",
                     orig_data_len, *return_len), data, orig_data_len);

  if (*return_len > orig_data_len - 5)
    return FALSE;

  return TRUE;
}

void
ssh_radius_client_reply_enumerate_init(SshRadiusClientReplyEnumerator e,
                                       SshRadiusClientRequest req,
                                       SshRadiusVendorId vendor_id,
                                       unsigned int type)
{
  SSH_ASSERT(e != NULL);
  SSH_ASSERT(req != NULL);

  e->req = req;
  e->vendor_selector = vendor_id;
  e->type_selector = (unsigned int)type;

  e->current_offset = 0;
  e->avp_offset = 0;

  e->vendor_id = SSH_RADIUS_VENDOR_ID_NONE;

  e->current_length = req->response_attributes_len;
  e->prev_length = 0;
}

SshRadiusVendorId
ssh_radius_client_reply_enumerate_get_vendor(SshRadiusClientReplyEnumerator e)
{
  SshRadiusClientRequest req;
  SshRadiusVendorId vendor_id;

  SSH_ASSERT(e->prev_length == 0);
  SSH_ASSERT(e->vendor_id == SSH_RADIUS_VENDOR_ID_NONE);

  req = e->req;

  if (e->current_offset + 6 < e->current_length)
    {
      unsigned char *data = req->response_attributes + e->avp_offset;
      vendor_id = (SshRadiusVendorId) SSH_GET_32BIT(data+2);

      return vendor_id;
    }
  return SSH_RADIUS_VENDOR_ID_NONE;
}

Boolean
ssh_radius_client_reply_enumerate_subtypes(SshRadiusClientReplyEnumerator e)
{
  SshRadiusClientRequest req;

  SSH_ASSERT(e->prev_length == 0);
  SSH_ASSERT(e->vendor_id == SSH_RADIUS_VENDOR_ID_NONE);

  req = e->req;

  if (e->current_offset < e->current_length + 6)
    {
      unsigned char *data = req->response_attributes + e->current_offset;
      e->prev_length = e->current_length;
      e->vendor_id = SSH_GET_32BIT(data+2);
      e->avp_offset = e->current_offset + 6;
      e->current_length = e->current_offset + data[1];

      return TRUE;
    }
  return FALSE;
}

SshRadiusAvpStatus
ssh_radius_client_reply_enumerate_next(SshRadiusClientReplyEnumerator e,
                                       SshRadiusVendorId *vendor_id_return,
                                       SshRadiusAvpType *type_return,
                                       unsigned char **value_return,
                                       size_t *value_len_return)
{
  SshRadiusClientRequest req;

  req = e->req;

  SSH_ASSERT(req != NULL);

  SSH_ASSERT(e->current_length <= req->response_attributes_len);

  while ((e->avp_offset+1) < e->current_length)
    {
      unsigned char *data = req->response_attributes + e->avp_offset;

      /* Prepare for the next attribute. */
      e->current_offset = e->avp_offset;
      e->avp_offset += data[1];

      /* If enumeration selector contains vendor id, then
         assume that the vendor specific type is RFC compliant. */
      if (e->vendor_selector != SSH_RADIUS_VENDOR_ID_NONE
          && e->vendor_id == SSH_RADIUS_VENDOR_ID_NONE
          && data[0] == SSH_RADIUS_AVP_VENDOR_SPECIFIC)
        {
          ssh_radius_client_reply_enumerate_subtypes(e);
          return ssh_radius_client_reply_enumerate_next(e,
                                                        vendor_id_return,
                                                        type_return,
                                                        value_return,
                                                        value_len_return);
        }

      if (e->type_selector == 0
          || (data[0] == e->type_selector
              && e->vendor_id == e->vendor_selector))
        {
          /* Found a match. */
          if (type_return)
            *type_return = data[0];

          if (vendor_id_return)
            *vendor_id_return = e->vendor_id;

          if ((e->vendor_id == SSH_RADIUS_VENDOR_ID_MS) &&
              (data[0] == SSH_RADIUS_VENDOR_MS_MPPE_SEND_KEY ||
               data[0] == SSH_RADIUS_VENDOR_MS_MPPE_RECV_KEY))
            {
              size_t decrypted_len;

              if (!ssh_radius_decrypt_ms_mppe_attribute(req, data,
                                                        &decrypted_len))
                return SSH_RADIUS_AVP_STATUS_VALUE_TOO_LONG;

              /* Remove the type/len salt and decrypted key length
                 after MD5 decryption */
              *value_return = data + 5;
              *value_len_return = decrypted_len;
              return SSH_RADIUS_AVP_STATUS_SUCCESS;
            }

          *value_return = data + 2;
          *value_len_return = data[1] - 2;

          return SSH_RADIUS_AVP_STATUS_SUCCESS;
        }
      /* Move forward. */
    }

  if (e->prev_length != 0)
    {
      SSH_ASSERT(e->current_length <= e->prev_length);
      e->current_length = e->prev_length;
      e->prev_length = 0;
      e->vendor_id = SSH_RADIUS_VENDOR_ID_NONE;
      return ssh_radius_client_reply_enumerate_next(e,
                                                    vendor_id_return,
                                                    type_return,
                                                    value_return,
                                                    value_len_return);
    }
  return SSH_RADIUS_AVP_STATUS_NOT_FOUND;
}

#if 0
void
ssh_radius_client_reply_enumerate_start(SshRadiusClientRequest request,
                                        SshRadiusAvpType type)
{
  request->type_selector = type;
  request->avp_offset = 0;
}


SshRadiusAvpStatus
ssh_radius_client_reply_enumerate_next(SshRadiusClientRequest req,
                                       SshRadiusAvpType *type_return,
                                       unsigned char **value_return,
                                       size_t *value_len_return)
{
  while (req->avp_offset < req->response_attributes_len)
    {
      unsigned char *data = req->response_attributes + req->avp_offset;

      /* Prepare for the next attribute. */
      req->avp_offset += data[1];

      if (req->type_selector == 0
          || data[0] == req->type_selector)
        {
          /* Found a match. */
          if (type_return)
            *type_return = data[0];

          *value_return = data + 2;
          *value_len_return = data[1] - 2;

          return SSH_RADIUS_AVP_STATUS_SUCCESS;
        }
      /* Move forward. */
    }

  return SSH_RADIUS_AVP_STATUS_NOT_FOUND;
}
#endif

/************************** Static help functions ***************************/

static void ssh_radius_client_server_retry_timer(void *context)
{
  SshRadiusClientServerInfo info = context;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_MIDOK, ("In the Client Server retry timer, marking all "
                          "previously failed servers as up again."));

  /* Indicate that the server is now up. */
  for (i = 0; i < info->num_servers; i++)
    info->servers[i].failed = 0;

  /* Reschedule */
 ssh_register_timeout(&info->retry_timer,
                      SSH_RADIUS_CLIENT_SERVER_RETRY_TIMER, 0,
                      ssh_radius_client_server_retry_timer, info);
}

static void
ssh_radius_client_destroy_real(void *context)
{
  SshRadiusClient client = (SshRadiusClient) context;

  SSH_ASSERT(client != NULL);
  SSH_ASSERT(client->destroyed);
  SSH_ASSERT(client->requests == NULL);

  ssh_udp_destroy_listener(client->listener);
  ssh_free(client->params.nas_identifier);
  ssh_hash_free(client->hash);
  ssh_free(client);
}


static void
ssh_radius_request_dequeue(SshRadiusClientRequest request)
{
  SshRadiusClientRequest *reqp;
  SshUInt8 request_id;

  SSH_ASSERT(request->client != NULL);

  /* Remove us from the client's list of active requests. */
  for (reqp = &request->client->requests; *reqp; reqp = &(*reqp)->next)
    if (*reqp == request)
      {
        *reqp = request->next;

        request->active = 0;
        request->next = NULL;

        /* Cancel retransmit timeout. */
        if (request->timeout_registered)
          ssh_cancel_timeout(&request->retransmit_timeout);

        /* Free the request id for somebody elses usage. */
        request_id = request->request[1];

        SSH_ASSERT(request->client->request_ids[request_id >> 3] &
                   (1 << (request_id & 7)));

        request->client->request_ids[request_id >> 3] &=
          ~(1 << (request_id & 7));
        return;
      }

  /* The request was active but it was not on the client's list of
     active requests. */
  SSH_NOTREACHED;
}


static void
ssh_radius_request_timeout(void *context)
{
  SshRadiusClientRequest req = (SshRadiusClientRequest) context;
  SshRadiusClientServerSpec server;

  SSH_ASSERT(req->active);

  /* Timeout is no longer registered. */
  req->timeout_registered = 0;

  if (req->num_retransmissions > req->client->params.max_retransmissions)
    {
      SshRadiusClientRequestStatus status;

      /* The request timed out. */

      if (req->num_retransmissions != 0)
        {
          req->num_total_retransmissions += req->num_retransmissions - 1;
        }

      /* Take a shortcut to the request's server. */
      server = &req->servers->servers[req->current_server];

      SSH_DEBUG(SSH_D_FAIL,
                ("Request timed out for server %s:%s",
                 server->address,
                 req->accounting ? server->acct_port : server->port));

      /* This server has now failed. */
      server->failed = 1;

      /* Try the next server. */

      req->current_server++;
      if (req->current_server >= req->servers->num_servers)
        req->current_server = 0;

      status = ssh_radius_client_request_prepare(req);
      if (status != SSH_RADIUS_CLIENT_REQ_SUCCESS)
        goto fail;


      /* Try the next server. */
    }

  /* Update retransmissions count. */
  req->num_retransmissions++;

  /* Update retransmission timer. */
  if (req->retransmit_timer == 0)
    {
      /* This is the first send request. */
      req->retransmit_timer = 1;
    }
  else
    {
      req->retransmit_timer *= 2;
      if (req->retransmit_timer > req->client->params.max_retransmit_timer)
        req->retransmit_timer = req->client->params.max_retransmit_timer;
    }

  /* Send the request. */

  /* Take a shortcut to our server. */
  server = &req->servers->servers[req->current_server];

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Sending packet: server=%s:%s, code=%u, id=%u, timout=%d, "
             "#retransmits=%d",
             server->address,
             req->accounting ? server->acct_port : server->port,
             req->request[0], req->request[1],
             (int) req->retransmit_timer,
             (int) req->num_retransmissions - 1));

  ssh_udp_send(req->client->listener, server->address,
               req->accounting ? server->acct_port : server->port,
               req->request, req->request_used);

  /* And order a retransmission timeout. */
  if (ssh_register_timeout(&req->retransmit_timeout, req->retransmit_timer, 0,
                           ssh_radius_request_timeout, req))
    {
      req->timeout_registered = 1;
      return;
    }

 fail:

  SSH_ASSERT(req->handle != NULL);

  /* No more servers to try. */
  ssh_radius_request_dequeue(req);
  ssh_operation_unregister(req->handle);

  (*req->callback)(SSH_RADIUS_CLIENT_REQ_TIMEOUT, req, 0,
                   req->context);
  return;
}


static SshRadiusClientRequestStatus
ssh_radius_client_request_prepare(SshRadiusClientRequest request)
{
  SshRadiusAvpStatus avp_status;
  SshRadiusClientServerSpec server;
  Boolean allocated_id = FALSE;
  int j;

  /* Use bound server */
  if (request->bound_server_index != -1)
    {
      j = request->bound_server_index;
      if (request->servers->servers[j].failed != 0)
        return SSH_RADIUS_CLIENT_REQ_TIMEOUT;
    }

  /* Find the next server to use. */
  else
    {
      while (1)
        {
          for (j = request->current_server;
               (j < request->servers->num_servers
                && request->servers->servers[j].failed);
               j++)
            ;

          if (j < request->servers->num_servers)
            /* Found a valid server. */
            break;

          /* Have we tried them all? */
          if (request->current_server == 0)
            /* Yes we have. */
            return SSH_RADIUS_CLIENT_REQ_TIMEOUT;

          /* No, restart from the beginning of the servers array. */
          request->current_server = 0;
        }
    }

  SSH_ASSERT(j < request->servers->num_servers);
  request->current_server = j;

  server = &request->servers->servers[request->current_server];

  /* Add default attributes if needed. */

  if (!request->nas_ip_addr_set
      && SSH_IP_DEFINED(&request->client->nas_ip_addr))
    {
      unsigned char buf[16];
      size_t addr_len;
      SshRadiusAvpType type;

      if (SSH_IP_IS4(&request->client->nas_ip_addr))
        type = SSH_RADIUS_AVP_NAS_IP_ADDRESS;
      else
        type = SSH_RADIUS_AVP_NAS_IPV6_ADDRESS;

      SSH_IP_ENCODE(&request->client->nas_ip_addr, buf, addr_len);
      avp_status = ssh_radius_client_request_add_attribute(request, type, buf,
                                                           addr_len);
      if (avp_status != SSH_RADIUS_AVP_STATUS_SUCCESS)
        {
          if (avp_status == SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY)
            return SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES;

          return SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST;
        }
      request->nas_ip_addr_set = 1;
    }

  if (!request->nas_identifier_set
      && request->client->params.nas_identifier)
    {
      avp_status
        = ssh_radius_client_request_add_attribute(
                request,
                SSH_RADIUS_AVP_NAS_IDENTIFIER,
                (unsigned char *) request->client->params.nas_identifier,
                ssh_ustrlen(request->client->params.nas_identifier));
      if (avp_status != SSH_RADIUS_AVP_STATUS_SUCCESS)
        {
          if (avp_status == SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY)
            return SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES;

          return SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST;
        }
      request->nas_identifier_set = 1;
    }

  if (!request->nas_port_set
      && request->client->params.nas_port_isvalid)
    {
      unsigned char buf[4];

      SSH_PUT_32BIT(&buf, request->client->params.nas_port);

      avp_status = ssh_radius_client_request_add_attribute(
                                                request,
                                                SSH_RADIUS_AVP_NAS_PORT,
                                                buf, 4);

      if (avp_status != SSH_RADIUS_AVP_STATUS_SUCCESS)
        {
          if (avp_status == SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY)
            return SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES;

          return SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST;
        }
      request->nas_port_set = 1;
    }

  if (!request->nas_port_type_set
      && request->client->params.nas_port_type_isvalid)
    {
      unsigned char buf[4];

      SSH_PUT_32BIT(&buf, request->client->params.nas_port_type);

      avp_status = ssh_radius_client_request_add_attribute(
                                                request,
                                                SSH_RADIUS_AVP_NAS_PORT_TYPE,
                                                buf, 4);

      if (avp_status != SSH_RADIUS_AVP_STATUS_SUCCESS)
        {
          if (avp_status == SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY)
            return SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES;

          return SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST;
        }
      request->nas_port_type_set = 1;
    }

  /* Allocate request id. */
    {
      SshUInt8 *request_ids = request->client->request_ids;
      int i;
      int id;

      id = request->client->request_id_last_alloc;
      id = (id + 1) & 0xff;

      for (i = 0; i < 256; i++)
        {
          unsigned int table_index = id >> 3;
          unsigned int bit_mask = 1 << (id & 7);

          if ((request_ids[table_index] & bit_mask) == 0)
            {
              /* Found a free request id. It is mark to be in used
                 in the end of the function when we return successfully.
              */
              request->request[1] = id;
              allocated_id = TRUE;
              break;
            }

          id = (id + 1) & 0xff;
        }
    }

  if (allocated_id == FALSE)
    return SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES;

  /* Set message length. */
  SSH_PUT_16BIT(request->request + 2, request->request_used);

  /* Encrypt the User-Password if set. */
  if (request->user_password_offset)
    {
      unsigned char *ucp = request->request + request->user_password_offset;
      size_t len;

      /* Fetch the encryption length of the User-Password AVP. */

      SSH_ASSERT(request->user_password_offset + 2 <= request->request_used);
      len = ucp[1];
      SSH_ASSERT(request->user_password_offset + len <= request->request_used);

      len -= 2;

      /* Save the plain-text password if not done yet. */
      if (request->user_password == NULL)
        {
          request->user_password = ssh_memdup(ucp + 2, len);
          if (request->user_password == NULL)
            {
              return SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES;
            }
        }
      else
        {
          /* Copy in the plain-text password. */
          memcpy(ucp + 2, request->user_password, len);
        }

      /* Encrypt the attribute value. */
      ssh_radius_encrypt(request, ucp + 2, len);
    }

  /* Initialize Request Authenticator for accouting requests. */
  if (request->accounting)
    {
      SshHash hash = request->client->hash;

      /* Clear possible old authenticator. */
      memset(request->request + 4, 0, SSH_RADIUS_MD5_LENGTH);

      ssh_hash_reset(hash);
      ssh_hash_update(hash, request->request, request->request_used);
      ssh_hash_update(hash, server->secret, server->secret_len);

      ssh_hash_final(hash, request->request + 4);
    }

  /* Perform Message-Authenticator computation. */
  if (request->authenticator_offset)
    {
      if (ssh_radius_req_msg_authenticator(request) == FALSE)
        {
          return SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES;
        }
    }


  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("Final packet: code=%u, id=%u:",
                     request->request[0], request->request[1]),
                    request->request, request->request_used);

  /* Init some request parameters. */
  request->active = 1;
  request->retransmit_timer = 0;
  request->num_retransmissions = 0;
  request->response_attributes = NULL;
  request->response_attributes_len = 0;

    {
      /* Mark the selected request id as allocated. */

      int id = request->request[1];
      unsigned int table_index = id >> 3;
      unsigned int bit_mask = 1 << (id & 7);

      request->client->request_id_last_alloc = id;
      request->client->request_ids[table_index] |= bit_mask;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocated ID %d", id));
    }

  return SSH_RADIUS_CLIENT_REQ_SUCCESS;
}


static void
ssh_radius_request_abort(void *context)
{
  ssh_radius_request_dequeue(context);
}


static void
ssh_radius_encrypt(SshRadiusClientRequest request,
                   unsigned char *data, size_t data_len)
{
  size_t i;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  SshHash hash = request->client->hash;
  size_t digest_len = request->client->hash_digest_length;
  SshRadiusClientServerSpec server;

  /* Take a shortcut to our server. */
  server = &request->servers->servers[request->current_server];

  /* Count the initial hash. */
  ssh_hash_reset(hash);
  ssh_hash_update(hash, server->secret, server->secret_len);
  ssh_hash_update(hash, request->request + 4, 16);

  /* Encrypt the data. */
  while (1)
    {
      ssh_hash_final(hash, digest);

      for (i = 0; i < digest_len && data_len > 0; i++)
        {
          *data = *data ^ digest[i];
          data++;
          data_len--;
        }

      if (data_len <= 0)
        /* All done. */
        break;

      /* Continue. */
      ssh_hash_reset(hash);
      ssh_hash_update(hash, server->secret, server->secret_len);
      ssh_hash_update(hash, data - digest_len, digest_len);
    }
}


static Boolean
ssh_radius_check_reply_auth(SshRadiusClientRequest request,
                            unsigned char *data,
                            size_t data_len,
                            size_t auth_offset)
{
  SshHash hash = request->client->hash;
  SshUInt8 md5_hash[SSH_RADIUS_MD5_LENGTH];
  SshUInt8 key[SSH_RADIUS_HMAC_BLOCK];
  SshUInt8 backup[SSH_RADIUS_MD5_LENGTH];
  int i;
  SshRadiusClientServerSpec server;

  SSH_PRECOND(request != NULL);

  /* Take a shortcut to our server. */
  server = &request->servers->servers[request->current_server];

  /* Some additional sanity checks */

  if ((auth_offset + SSH_RADIUS_MD5_LENGTH + 2 > data_len)
      || (data[auth_offset + 1] != (SSH_RADIUS_MD5_LENGTH + 2))
      || (data[auth_offset] != SSH_RADIUS_AVP_MESSAGE_AUTHENTICATOR))
    {
      return FALSE;
    }

  if (request->client->hash_digest_length > SSH_RADIUS_MD5_LENGTH
      || request->client->hash_digest_length > SSH_RADIUS_HMAC_BLOCK)
    {
      return FALSE;
    }

  if (request->request_used < 20)
    {
      return FALSE;
    }

  /* Grab a backup of the MD5-HMAC */

  auth_offset += 2;

  memcpy(backup, data + auth_offset, SSH_RADIUS_MD5_LENGTH);
  memset(data + auth_offset, 0, SSH_RADIUS_MD5_LENGTH);

  /* Compute key */

  memset(key, 0, SSH_RADIUS_HMAC_BLOCK);

  if (server->secret_len > SSH_RADIUS_HMAC_BLOCK)
    {
      ssh_hash_reset(hash);
      ssh_hash_update(hash, server->secret, server->secret_len);
      ssh_hash_final(hash, key);
    }
  else
    {
      memcpy(key, server->secret, server->secret_len);
    }

  /* Compute inner MD5 */

  for (i = 0; i < SSH_RADIUS_HMAC_BLOCK; i++)
    key[i] ^= 0x36;

  ssh_hash_reset(hash);
  ssh_hash_update(hash, key, SSH_RADIUS_HMAC_BLOCK);
  ssh_hash_update(hash, data, 4);
  ssh_hash_update(hash, request->request + 4, SSH_RADIUS_MD5_LENGTH);
  ssh_hash_update(hash, data + 20, data_len - 20);

  ssh_hash_final(hash,md5_hash);

  /* Compute outer MD5 */

  for (i = 0; i < SSH_RADIUS_HMAC_BLOCK; i++)
    key[i] ^= 0x36 ^ 0x5c;

  ssh_hash_reset(hash);
  ssh_hash_update(hash, key, SSH_RADIUS_HMAC_BLOCK);
  ssh_hash_update(hash, md5_hash, sizeof(md5_hash));

  ssh_hash_final(hash, md5_hash);

  memcpy(data + auth_offset, backup, SSH_RADIUS_MD5_LENGTH);

  if (memcmp(md5_hash, backup, SSH_RADIUS_MD5_LENGTH) != 0)
    {
      SSH_DEBUG(SSH_D_NETGARB,("Message-authenticator at offset %d invalid",
                               auth_offset));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,("Message-authenticator at offset %d valid",
                              auth_offset));

  return TRUE;
}


static Boolean
ssh_radius_req_msg_authenticator(SshRadiusClientRequest request)
{
  SshHash hash = request->client->hash;
  SshUInt8 md5_hash[SSH_RADIUS_MD5_LENGTH];
  SshUInt8 key[SSH_RADIUS_HMAC_BLOCK];
  int i;
  SshRadiusClientServerSpec server;

  /* Take a shortcut to our server. */
  server = &request->servers->servers[request->current_server];

  /* Compute key for HMAC-MD5 */

  SSH_ASSERT(request->client->hash_digest_length == SSH_RADIUS_MD5_LENGTH);
  SSH_ASSERT(request->client->hash_digest_length <= SSH_RADIUS_HMAC_BLOCK);

  if (request->client->hash_digest_length > SSH_RADIUS_MD5_LENGTH
      || request->client->hash_digest_length > SSH_RADIUS_HMAC_BLOCK)
    {
      return FALSE;
    }

  /* Compute Key */

  memset(key, 0, SSH_RADIUS_HMAC_BLOCK);

  if (server->secret_len > SSH_RADIUS_HMAC_BLOCK)
    {
      ssh_hash_reset(hash);
      ssh_hash_update(hash, server->secret, server->secret_len);
      ssh_hash_final(hash, key);
    }
  else
    {
      memcpy(key, server->secret, server->secret_len);
    }

  /* Clear possible old message authenticator. */
  memset(request->request + request->authenticator_offset + 2, 0,
         SSH_RADIUS_MD5_LENGTH);

  /* Compute inner MD5 */

  for (i = 0; i < SSH_RADIUS_HMAC_BLOCK; i++)
    key[i] ^= 0x36;

  ssh_hash_reset(hash);
  ssh_hash_update(hash, key, SSH_RADIUS_HMAC_BLOCK);
  ssh_hash_update(hash, request->request, request->request_used);
  ssh_hash_final(hash, md5_hash);

  /* Compute outer MD5 */

  for (i = 0; i < SSH_RADIUS_HMAC_BLOCK; i++)
    key[i] ^= 0x36 ^ 0x5c;

  ssh_hash_reset(hash);
  ssh_hash_update(hash, key, SSH_RADIUS_HMAC_BLOCK);
  ssh_hash_update(hash, md5_hash, sizeof(md5_hash));

  ssh_hash_final(hash, request->request + request->authenticator_offset + 2);

  return TRUE;
}


static void
ssh_radius_udp_callback(SshUdpListener listener, void *context)
{
  SshRadiusClient client = (SshRadiusClient) context;
  Boolean has_eap;
  int auth_ok;
  Boolean b;
  Boolean has_authenticator;

  /* Process all incoming messages. */
  while (!client->destroyed)
    {
      SshUdpError error;
      unsigned char remote_addr[128];
      unsigned char remote_port[64];
      size_t datagram_len;

      error = ssh_udp_read(client->listener,
                           remote_addr, sizeof(remote_addr),
                           remote_port, sizeof(remote_port),
                           client->datagram, sizeof(client->datagram),
                           &datagram_len);

      if (error == SSH_UDP_OK)
        {
          SshRadiusOperationCode code;
          SshRadiusClientRequest req;
          unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
          unsigned char *data;
          size_t data_len;
          SshRadiusClientRequestStatus status;
          SshRadiusClientServerSpec server;

          status = SSH_RADIUS_CLIENT_REQ_SUCCESS;

          SSH_DEBUG(SSH_D_LOWSTART, ("New packet from %s:%s: %d bytes",
                                     remote_addr, remote_port, datagram_len));
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Incoming packet:"),
                            client->datagram, datagram_len);

          /* Verify message length.  */

          if (datagram_len < SSH_RADIUS_MIN_PACKET_SIZE)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Too short packet"));
              continue;
            }

          /* The length in the header must not be longer than the
             physical length. */
          if (SSH_GET_16BIT(client->datagram + 2) > datagram_len)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Truncated packet: datagram_len=%d, Length=%d",
                         datagram_len, SSH_GET_16BIT(client->datagram + 2)));
              continue;
            }

          /* The physical length of the packet can be longer than the
             length in the header.  According to the RFCs, all extra
             bytes are considered to be padding and they are
             ignored. */
          datagram_len = SSH_GET_16BIT(client->datagram + 2);

          /* Check message code. */
          code = client->datagram[0];
          if (code != SSH_RADIUS_ACCESS_ACCEPT
              && code != SSH_RADIUS_ACCESS_REJECT
              && code != SSH_RADIUS_ACCOUNTING_RESPONSE
              && code != SSH_RADIUS_ACCESS_CHALLENGE)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Invalid message code %d", code));
              continue;
            }

          /* Do we have a pending message matching this packet? */
          for (req = client->requests; req; req = req->next)
            {
              if (req->request[1] != client->datagram[1])
                continue;

              server = &req->servers->servers[req->current_server];

              if (ssh_ustrcmp(server->address, remote_addr) != 0)
                continue;

              if (req->accounting
                  && ssh_ustrcmp(server->acct_port, remote_port) != 0)
                continue;

              if (!req->accounting &&
                  ssh_ustrcmp(server->port, remote_port) != 0)
                continue;

              /* We found a match. */
              break;
            }

          if (req == NULL)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Reply message with unknown request ID %u",
                         client->datagram[1]));
              continue;
            }

          /* Verify that the reply message code matches the request. */
          if (req->accounting && code != SSH_RADIUS_ACCOUNTING_RESPONSE)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Invalid reply message code %d for request code %d",
                         code, req->request[0]));
              continue;
            }

          /* Take a shortcut to our server. */
          server = &req->servers->servers[req->current_server];

          /* Verify response authenticator. */

          ssh_hash_reset(client->hash);
          ssh_hash_update(client->hash, client->datagram, 4);
          ssh_hash_update(client->hash, req->request + 4, 16);
          ssh_hash_update(client->hash, client->datagram + 20,
                          datagram_len - 20);
          ssh_hash_update(client->hash, server->secret, server->secret_len);

          ssh_hash_final(client->hash, digest);

          if (memcmp(digest, client->datagram + 4, 16) != 0)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Response Authenticator failure"));
              SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                ("Response Authenticator in packet:"),
                                client->datagram + 4, 16);
              SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                                ("Computed Response Authenticator:"),
                                digest, 16);

              /* Do not complete the pending request since this can be
                 a fake response. */
              continue;
            }

          /* It is a valid response packet.  After this, all failures
             will be reported to the user of our pending request `req'
             and they will complete the request. */

          /* Verify individual attributes. */

          data = client->datagram + 20;
          data_len = datagram_len - 20;

          has_eap = FALSE;
          auth_ok = 1;
          has_authenticator = FALSE;

          while (data_len)
            {
              size_t length;

              if (data_len < 2)
                {
                  /* Packet ends abrubtly in middle of AVP header */
                  status = SSH_RADIUS_CLIENT_REQ_MALFORMED_REPLY;
                  goto out;
                }

              length = data[1];

              if (length > data_len)
                {
                  /* Attribute extending over packet's physical length. */
                  status = SSH_RADIUS_CLIENT_REQ_MALFORMED_REPLY;
                  goto out;
                }

              if (data[0] == SSH_RADIUS_AVP_EAP_MESSAGE)
                has_eap = TRUE;

              if (data[0] == SSH_RADIUS_AVP_MESSAGE_AUTHENTICATOR)
                {
                  has_authenticator = TRUE;
                  b = ssh_radius_check_reply_auth(req,
                                                  client->datagram,
                                                  datagram_len,
                                                  data - client->datagram);

                  auth_ok &= (b == TRUE ? 1 : 0 );
                }

              data += length;
              data_len -= length;
            }

          if (auth_ok == 0)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Message authenticator present in "
                                        "message is invalid"));
              continue;
            }

          if ((code == SSH_RADIUS_ACCESS_ACCEPT
               || code == SSH_RADIUS_ACCESS_REJECT
               || code == SSH_RADIUS_ACCESS_CHALLENGE)
              && (has_eap == TRUE && has_authenticator == FALSE))
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Message authenticator lacking "
                                        "in message containing EAP-Message"));
              continue;
            }

          /* The reply was correctly formed.  Let's prepare to extract
             attributes from the response. */
          req->response_attributes = client->datagram + 20;
          req->response_attributes_len = datagram_len - 20;

          /* All done.  Let's complete this request. */
        out:

          ssh_radius_request_dequeue(req);
          ssh_operation_unregister(req->handle);

          (*req->callback)(status, req, client->datagram[0], req->context);

          /* Note that the request can be freed at the callback.  We
             must not refer to it anymore. */
        }
      else if (error == SSH_UDP_NO_DATA)
        {
          break;
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR, ("UDP read failed: %s",
                                  ssh_udp_error_string(error)));
        }
    }
}

