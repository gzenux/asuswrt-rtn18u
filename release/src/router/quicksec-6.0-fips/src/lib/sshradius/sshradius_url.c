/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Radius usage based on a proprietary radius:// style URL.

   Please note that this interface is for the moment still
   experimental, and will probably change.
*/

#define SSH_DEBUG_MODULE "SshRadiusUrl"

#include "sshincludes.h"
#include "sshurl.h"
#include "sshgetput.h"
#include "sshinet.h"

#ifdef SSHDIST_RADIUS

#include "sshradius_internal.h"
#include "sshradius_url.h"

#include <string.h>

/* Static private functions */

static SshRadiusUrlStatus
ssh_radius_url_do_next(SshRadiusUrlRequest req);

static unsigned char*
ssh_radius_get_url_path(const unsigned char *url);

static SshRadiusUrlStatus
ssh_radius_url_add_avp_by_type(SshRadiusUrlAvpSet avp_set,
                               const SshRadiusAvpInfoStruct *avp_info,
                               unsigned char *value,
                               size_t value_length);

static SshRadiusUrlStatus
ssh_radius_url_add_avp(SshRadiusUrlAvpSet avp_set,
                       const SshRadiusAvpInfoStruct *avp_info,
                       unsigned char *value,
                       size_t value_len);


static void
ssh_radius_url_destroy_request(SshRadiusUrlRequest req);

static unsigned char*
ssh_radius_get_url_path(const unsigned char *url)
{
  Boolean res;
  unsigned char *path;

  res = ssh_url_parse(url, NULL, NULL, NULL, NULL, NULL, &path);
  if (res == FALSE)
    return NULL;

  if (path == NULL)
    return NULL;

  return path;
}

























static void
ssh_radius_url_request_abort(void *ctx)
{
  SshRadiusUrlRequest req;

  req = (SshRadiusUrlRequest)ctx;

  SSH_ASSERT(req != NULL);

  req->url_handle = NULL;
  ssh_radius_url_destroy_request(req);
}

static void
ssh_radius_url_cb(SshRadiusClientRequestStatus status,
                  SshRadiusClientRequest request,
                  SshRadiusOperationCode reply_code,
                  void *context)
{
  SshRadiusUrlRequest req;
  SshRadiusUrlStatus url_status;

  SSH_DEBUG(SSH_D_MIDOK,("received RADIUS reply"));

  req = (SshRadiusUrlRequest)context;

  req->op_handle = NULL;

  /* Allow for use of secondary RADIUS servers */

  if (status == SSH_RADIUS_CLIENT_REQ_TIMEOUT)
    {
      req->url_idx++;
      url_status = ssh_radius_url_do_next(req);

      if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
        {
          if (req->cb != NULL_FNPTR)
            req->cb(SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES,
                    request, reply_code, req->ctx);

          ssh_radius_url_destroy_request(req);
        }
      return;
    }

  if (req->cb != NULL_FNPTR)
    req->cb(status,request,reply_code,req->ctx);

  ssh_radius_url_destroy_request(req);
}

static void
ssh_radius_url_destroy_request(SshRadiusUrlRequest req)
{
  size_t i;

  if (req == NULL)
    return;

  if (req->url != NULL)
    {
      for (i = 0; i < req->nurls; i++)
        {
          if (req->url[i] != NULL)
            ssh_free(req->url[i]);
        }

      ssh_free(req->url);
    }

  ssh_radius_url_uninit_avpset(&req->avp_set);

  if (req->op_handle != NULL)
    ssh_operation_abort(req->op_handle);

  if (req->req != NULL)
    ssh_radius_client_request_destroy(req->req);

  if (req->rad_client != NULL)
    ssh_radius_client_destroy(req->rad_client);

  if (req->s_info != NULL)
    ssh_radius_client_server_info_destroy(req->s_info);

  if (req->url_handle != NULL)
    ssh_operation_unregister(req->url_handle);

  ssh_radius_url_uninit_params(&req->rad_params);
  ssh_free(req);
}

static SshRadiusUrlStatus
ssh_radius_url_add_avp_by_type(SshRadiusUrlAvpSet avp_set,
                               const SshRadiusAvpInfoStruct *avp_info,
                               unsigned char *value,
                               size_t value_length)
{
  long val;
  const SshKeywordStruct *keywords;
  SshUInt8 number_buf[4];

  SSH_PRECOND(avp_set != NULL);
  SSH_PRECOND(avp_info != NULL);

  /* If value == NULL, then choose default value based on value type */

  if (value == NULL)
    return SSH_RADIUS_URL_STATUS_NONE;

  if (avp_info->value_type != SSH_RADIUS_AVP_VALUE_INTEGER)
    return SSH_RADIUS_URL_STATUS_NONE;

  /* Special cases for some attributes */

  switch (avp_info->type)
    {
    case SSH_RADIUS_AVP_FRAMED_PROTOCOL:
      keywords = ssh_radius_framed_protocols;
      break;
    case SSH_RADIUS_AVP_SERVICE_TYPE:
      keywords = ssh_radius_service_types;
      break;
    case SSH_RADIUS_AVP_NAS_PORT_TYPE:
      keywords = ssh_radius_nas_port_types;
      break;
    default:
      keywords = NULL;
      break;
    }

  if (keywords == NULL)
    return SSH_RADIUS_URL_STATUS_NONE;

  val = ssh_find_partial_keyword_number_case_insensitive(keywords,
                                                         ssh_csstr(value),
                                                         NULL);

  if (val == -1)
    return SSH_RADIUS_URL_INVALID_AVP_VALUE;

  SSH_PUT_32BIT(number_buf, val);

  if (ssh_radius_url_set_avpset_avp(avp_set, avp_info->type,
                                    number_buf, 4) == FALSE)
    return SSH_RADIUS_URL_OUT_OF_MEMORY;

  return SSH_RADIUS_URL_STATUS_SUCCESS;
}

static SshRadiusUrlStatus
ssh_radius_url_add_avp(SshRadiusUrlAvpSet avp_set,
                       const SshRadiusAvpInfoStruct *avp_info,
                       unsigned char *value,
                       size_t value_len)
{
  unsigned long val;
  SshRadiusUrlStatus url_status;

  SSH_PRECOND(avp_set != NULL);
  SSH_PRECOND(avp_info != NULL);

  /* Try to allow for "magic keyword" substituion for selected
     parameter values. */

  if (avp_info->value_type == SSH_RADIUS_AVP_VALUE_INTEGER)
    {
      url_status =
        ssh_radius_url_add_avp_by_type(avp_set, avp_info, value, value_len);

      if (url_status != SSH_RADIUS_URL_STATUS_NONE)
        return url_status;
    }

  /* Perform setting based on type */

  switch (avp_info->value_type)
    {
    case SSH_RADIUS_AVP_VALUE_TEXT:
      if (ssh_radius_url_set_avpset_avp(avp_set, avp_info->type,
                                        (SshUInt8 *) value,
                                        (SshUInt8)value_len)
          == FALSE)
        return SSH_RADIUS_URL_OUT_OF_MEMORY;
      break;

    case SSH_RADIUS_AVP_VALUE_TAG_INTEGER:
    case SSH_RADIUS_AVP_VALUE_TAG_STRING:
    case SSH_RADIUS_AVP_VALUE_IPV6_ADDRESS:
      SSH_DEBUG(SSH_D_FAIL,("TAG and IPV6 attributes not yet supported"));
      return SSH_RADIUS_URL_UNKNOWN_AVP_TYPE;
      break;

    case SSH_RADIUS_AVP_VALUE_TIME:
    case SSH_RADIUS_AVP_VALUE_INTEGER:
      {
        SshUInt8 number_buf[4];
        val = (value != NULL ? ssh_ustrtol(value, NULL, 0) : 0);
        SSH_PUT_32BIT(number_buf, val);

        if (ssh_radius_url_set_avpset_avp(avp_set, avp_info->type,
                                          number_buf, 4) == FALSE)
          return SSH_RADIUS_URL_OUT_OF_MEMORY;
      }
      break;

      /* Convert IPv4 address to 32-bit integer */
    case SSH_RADIUS_AVP_VALUE_ADDRESS:
      {
        SshIpAddrStruct ip_addr;
        SshUInt8 number_buf[4];

        if (value == NULL)
          return SSH_RADIUS_URL_INVALID_AVP_VALUE;

        if (ssh_ipaddr_parse(&ip_addr, value) == FALSE)
          return SSH_RADIUS_URL_INVALID_AVP_VALUE;

        if (SSH_IP_IS4(&ip_addr) == FALSE)
          return SSH_RADIUS_URL_INVALID_AVP_VALUE;

        SSH_PUT_32BIT(number_buf, SSH_IP4_TO_INT(&ip_addr));

        if (ssh_radius_url_set_avpset_avp(avp_set, avp_info->type,
                                          number_buf, 4) == FALSE)
          return SSH_RADIUS_URL_OUT_OF_MEMORY;
      }
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL,
                ("Unknown RADIUS attribute value type %d!",
                 avp_info->value_type));
      return SSH_RADIUS_URL_UNKNOWN_AVP_TYPE;
    }

  return SSH_RADIUS_URL_STATUS_SUCCESS;
}

static SshRadiusUrlStatus
ssh_radius_url_parse_nas_id(unsigned char *url, unsigned char **result)
{
  Boolean res;
  SshRadiusUrlStatus url_status;
  unsigned char *scheme, *name;

  SSH_PRECOND(url != NULL);

  /* Note that we can not detect if this failed due
     to an out of memory error! If we could, then we
     would provide more than an equivalent of FALSE/TRUE
     in the return code. */

  res = ssh_url_parse(url, &scheme, NULL, NULL, &name, NULL, NULL);

  if (res == FALSE)
    return SSH_RADIUS_URL_MALFORMED;

  url_status = SSH_RADIUS_URL_INVALID_SCHEME;

  if (scheme == NULL)
    goto fail;

  if (ssh_usstrcmp(scheme, "radius") != 0)
    goto fail;

  ssh_free(scheme);
  *result = name;

  if (name == NULL)
    return SSH_RADIUS_URL_EXPECTING_NAS_ID;

  return SSH_RADIUS_URL_STATUS_SUCCESS;

 fail:
  if (scheme != NULL)
    ssh_free(scheme);

  if (name != NULL)
    ssh_free(name);

  *result = NULL;

  return url_status;
}

static SshRadiusUrlStatus
ssh_radius_url_do_next(SshRadiusUrlRequest req)
{
  SshRadiusUrlStatus url_status;

  if (req->url_idx >= req->nurls)
    return FALSE;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Performing request (index %d) %s",
             req->url_idx,
             (req->url[req->url_idx] != NULL ? req->url[req->url_idx]
              : ssh_ustr("<null>"))));

  /* First zero all state related to previous req's */

  if (req->op_handle != NULL)
    ssh_operation_abort(req->op_handle);

  if (req->req != NULL)
    ssh_radius_client_request_destroy(req->req);

  if (req->rad_client != NULL)
    ssh_radius_client_destroy(req->rad_client);

  if (req->s_info != NULL)
    ssh_radius_client_server_info_destroy(req->s_info);

  ssh_radius_url_uninit_params(&req->rad_params);

  req->s_info = NULL;
  req->req = NULL;
  req->op_handle = NULL;
  req->rad_params.nas_identifier = NULL;
  req->rad_client = NULL;

  /* Create a new request from scratch */

  url_status = ssh_radius_url_init_params(&req->rad_params,
                                          req->url[req->url_idx]);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    return url_status;

  req->s_info = ssh_radius_client_server_info_create();

  if (req->s_info == NULL)
    return SSH_RADIUS_URL_OUT_OF_MEMORY;

  url_status = ssh_radius_url_add_server(req->s_info,
                                         req->url[req->url_idx]);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    return url_status;

  req->rad_client = ssh_radius_client_create(&req->rad_params);

  if (req->rad_client == NULL)
    return SSH_RADIUS_URL_OUT_OF_MEMORY;

  req->req = ssh_radius_client_request_create(req->rad_client,
                                              SSH_RADIUS_ACCESS_REQUEST);

  if (req->req == NULL)
    return SSH_RADIUS_URL_OUT_OF_MEMORY;

  /* Add AVP's so that the ones specified on the command line
     have precedence */

  {
    SshRadiusUrlAvpSet avp_url, avp_comb;

    url_status = ssh_radius_url_create_avpset(&avp_url,
                                              req->url[req->url_idx]);
    if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
      return url_status;

    avp_comb = ssh_radius_url_add_avpset(&req->avp_set, avp_url);

    if (avp_comb == NULL)
      {
        ssh_radius_url_destroy_avpset(avp_url);
        return SSH_RADIUS_URL_OUT_OF_MEMORY;
      }

    if (ssh_radius_url_add_avps(req->req, avp_comb) == FALSE)
      {
        ssh_radius_url_destroy_avpset(avp_comb);
        ssh_radius_url_destroy_avpset(avp_url);
        return SSH_RADIUS_URL_OUT_OF_MEMORY;
      }

    ssh_radius_url_destroy_avpset(avp_comb);
    ssh_radius_url_destroy_avpset(avp_url);
  }

  /* .. Finally send the request */

  req->op_handle = ssh_radius_client_request(req->req,
                                             req->s_info,
                                             ssh_radius_url_cb,
                                             req);

  if (req->op_handle == NULL)
    return SSH_RADIUS_URL_OUT_OF_MEMORY;

  return SSH_RADIUS_URL_STATUS_SUCCESS;
}

/* Actual API functions */

SshRadiusUrlStatus
ssh_radius_url_init_params(SshRadiusClientParams params, unsigned char *url)
{
  SshRadiusUrlStatus url_status;

  memset(params,0,sizeof(*params));

  url_status = ssh_radius_url_parse_nas_id(url,
                                           &params->nas_identifier);


  return url_status;
}

void
ssh_radius_url_uninit_params(SshRadiusClientParams params)
{
  if (params->nas_identifier != NULL)
    ssh_free(params->nas_identifier);

  params->nas_identifier = NULL;
}

void
ssh_radis_url_remove_avpset_avp(SshRadiusUrlAvpSet avp_set,
                                SshRadiusAvpType avp_type)
{
  size_t i;

  for (i = 0; i < avp_set->navps; i++)
    {
      if (avp_set->avp[i].type == avp_type)
        break;
    }

  if (i == avp_set->navps)
    return;

  if (avp_set->avp[i].buf != NULL)
    ssh_free(avp_set->avp[i].buf);

  if (i != (avp_set->navps-1))
    {
      memmove(&avp_set->avp[i], &avp_set->avp[i+1],
              sizeof(SshRadiusUrlAvpStruct) * (avp_set->navps - i - 1));
    }

  avp_set->navps--;
}

Boolean
ssh_radius_url_set_avpset_avp(SshRadiusUrlAvpSet avp_set,
                              SshRadiusAvpType avp_type,
                              SshUInt8 *buf,
                              SshUInt8 len)
{
  size_t i;
  SshUInt8 *new_buf;
  SshRadiusUrlAvp avp;

  SSH_PRECOND(avp_set != NULL);

  /* First see if we can get a buffer for the contents of the AVP */

  avp = NULL;
  new_buf = NULL;

  if (buf != NULL)
    {
      new_buf = ssh_malloc(len);
      if (new_buf == NULL)
        return FALSE;

      memcpy(new_buf, buf, len);
    }

  /* .. then try to enlarge the AVP set in such a manner that it does
     not break if we run out of memory.. */

  for (i = 0; i < avp_set->navps; i++)
    {
      if (avp_set->avp[i].type == avp_type)
        break;
    }

  if (i == avp_set->navps)
    {
      avp = ssh_malloc((avp_set->navps+1)*sizeof(SshRadiusUrlAvpStruct));

      if (avp == NULL)
        return FALSE;

      avp_set->navps++;

      memcpy(avp, avp_set->avp,
             (avp_set->navps)*sizeof(SshRadiusUrlAvpStruct));

      ssh_free(avp_set->avp);
      avp_set->avp = avp;

      avp[i].type = 0;
      avp[i].buf = NULL;
      avp[i].len = 0;
    }
  else
    {
      avp = avp_set->avp;

      if (avp[i].buf != NULL)
        ssh_free(avp[i].buf);
      avp[i].buf = NULL;
      avp[i].len = 0;
      avp[i].type = 0;
    }


  avp[i].buf = new_buf;
  avp[i].len = len;
  avp[i].type = avp_type;
  return TRUE;
}

SshRadiusUrlAvpSet
ssh_radius_url_add_avpset(SshRadiusUrlAvpSet set_super,
                          SshRadiusUrlAvpSet set_sub)
{
  size_t i;
  SshRadiusUrlAvpSet avp_set;
  SshRadiusUrlStatus url_status;

  url_status = ssh_radius_url_create_avpset(&avp_set,NULL);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    return NULL;

  for (i = 0; i < set_sub->navps; i++)
    {
      if (ssh_radius_url_set_avpset_avp(avp_set,
                                        set_sub->avp[i].type,
                                        set_sub->avp[i].buf,
                                        set_sub->avp[i].len) == FALSE)
        {
          ssh_radius_url_destroy_avpset(avp_set);
          return NULL;
        }
    }

  for (i = 0; i < set_super->navps; i++)
    {
      if (ssh_radius_url_set_avpset_avp(avp_set,
                                        set_super->avp[i].type,
                                        set_super->avp[i].buf,
                                        set_super->avp[i].len) == FALSE)
        {
          ssh_radius_url_destroy_avpset(avp_set);
          return NULL;
        }
    }
  return avp_set;
}

SshRadiusUrlStatus
ssh_radius_url_init_avpset(SshRadiusUrlAvpSet set, unsigned char *url)
{

  unsigned char *path, *type;
  const unsigned char *key, *value;
  size_t key_length, value_length;
  SshUrlQuery query;
  const SshRadiusAvpInfoStruct *avp_info;
  SshRadiusUrlStatus url_status;
  SshRadiusUrlStatus bad_url_status;

  url_status = SSH_RADIUS_URL_STATUS_NONE;
  set->avp = NULL;
  set->navps = 0;

  if (url == NULL)
    return SSH_RADIUS_URL_STATUS_SUCCESS;

  path = ssh_radius_get_url_path(url);
  type = NULL;
  query = NULL;

  if (path != NULL && path[0] != '\0')
    {
      if (ssh_url_parse_get(path,
                            NULL, NULL, &type, &query, NULL, FALSE)
          != SSH_URL_OK)
        {
          url_status = SSH_RADIUS_URL_AVPLIST_MALFORMED;
          goto fail;
        }
    }

  if (query != NULL)
    {
      SshUrlEntry entry;

      bad_url_status = SSH_RADIUS_URL_STATUS_NONE;

      for (entry = ssh_url_query_enumerate_start(query);
           entry;
           entry = ssh_url_query_enumerate_next(query, entry))
        {

          key = ssh_url_entry_key(entry, &key_length);
          value = ssh_url_entry_value(entry, &value_length);

          if (key != NULL)
            {
              avp_info = ssh_radius_avp_info_name((char *)key);

              if (avp_info == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("unrecognized RADIUS attribute name: %s",
                             key));
                  bad_url_status = SSH_RADIUS_URL_UNKNOWN_AVP_TYPE;
                }
              else
                {
                  url_status = ssh_radius_url_add_avp(set, avp_info,
                                                      (unsigned char *) value,
                                                      value_length);
                  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
                    {
                      SSH_DEBUG(SSH_D_FAIL,
                                ("failed to add attribute %s to "
                                 "request",key));
                      bad_url_status = url_status;
                    }
                }
            }
        }

      ssh_url_query_free(query);

      if (bad_url_status != SSH_RADIUS_URL_STATUS_NONE)
        {
          url_status = bad_url_status;
          goto fail;
        }
    }

  if (type != NULL)
    ssh_free(type);

  ssh_free(path);
  return SSH_RADIUS_URL_STATUS_SUCCESS;

 fail:
  if (path != NULL)
    ssh_free(path);

  if (type != NULL)
    ssh_free(type);

  return url_status;
}

void
ssh_radius_url_uninit_avpset(SshRadiusUrlAvpSet avp_set)
{
  size_t i;

  if (avp_set == NULL)
    return;

  if (avp_set->avp != NULL)
    {
      for (i = 0; i < avp_set->navps; i++)
        {
          if (avp_set->avp[i].buf != NULL)
            ssh_free(avp_set->avp[i].buf);
        }
      ssh_free(avp_set->avp);
    }
  avp_set->avp = NULL;
  avp_set->navps = 0;
}

void
ssh_radius_url_destroy_avpset(SshRadiusUrlAvpSet avp_set)
{
  if (avp_set != NULL)
    {
      ssh_radius_url_uninit_avpset(avp_set);
      ssh_free(avp_set);
    }
}

SshRadiusUrlStatus
ssh_radius_url_create_avpset(SshRadiusUrlAvpSet *result, unsigned char *url)
{
  SshRadiusUrlAvpSet avp_set;
  SshRadiusUrlStatus url_status;

  avp_set = ssh_malloc(sizeof(*avp_set));
  if (avp_set == NULL)
    return SSH_RADIUS_URL_OUT_OF_MEMORY;

  url_status = ssh_radius_url_init_avpset(avp_set, url);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    {
      ssh_radius_url_destroy_avpset(avp_set);
      return url_status;
    }
  *result = avp_set;
  return SSH_RADIUS_URL_STATUS_SUCCESS;
}

SshRadiusUrlStatus
ssh_radius_url_add_server(SshRadiusClientServerInfo s_info, unsigned char *url)
{
  unsigned char *scheme, *host, *port, *username, *password, *path;
  const unsigned char *real_port, *real_secret;
  Boolean res;

  SSH_PRECOND(url != NULL);

  real_port = NULL;
  scheme = host = port = username = password = path = NULL;

  res = ssh_url_parse(url, &scheme, &host, &port, &username,
                      &password, &path);

  if (res == FALSE)
    goto fail;

  res = FALSE;

  if (scheme == NULL)
    goto fail;

  if (ssh_usstrcmp(scheme, "radius") != 0)
    goto fail;

  if (host == NULL)
    goto fail;

  real_port =   (port !=  NULL ? port : (unsigned char *)"1812");
  real_secret = (password != NULL ? password : (unsigned char *)"");

  res = ssh_radius_client_server_info_add_server(s_info,
                                                 host,
                                                 real_port,
                                                 real_port,
                                                 real_secret,
                                                 ssh_ustrlen(real_secret));

 fail:
  if (scheme != NULL)
    ssh_free(scheme);

  if (host != NULL)
    ssh_free(host);

  if (port != NULL)
    ssh_free(port);

  if (username != NULL)
    ssh_free(username);

  if (password != NULL)
    ssh_free(password);

  if (path != NULL)
    ssh_free(path);

  return res;
}


Boolean
ssh_radius_url_add_avps(SshRadiusClientRequest req,
                        SshRadiusUrlAvpSet avp_set)
{
  SshRadiusUrlAvp avp;
  SshRadiusAvpStatus avp_stat;
  size_t i;

  SSH_PRECOND(req != NULL);
  SSH_PRECOND(avp_set != NULL);

  avp = avp_set->avp;

  for (i = 0; i < avp_set->navps; i++)
    {
      avp_stat = ssh_radius_client_request_add_attribute(req,
                                                         avp[i].type,
                                                         avp[i].buf,
                                                         avp[i].len);

      if (avp_stat != SSH_RADIUS_AVP_STATUS_SUCCESS)
        return FALSE;
    }

  return TRUE;
}

SshRadiusUrlStatus
ssh_radius_url_create_request(SshOperationHandle *result,
                              SshRadiusClientRequestCB cb, void *ctx, ...)
{
  SshRadiusUrlRequest url_req;
  SshRadiusAvpType avp_type;
  va_list ap;
  unsigned char *cp;
  size_t idx,len;
  SshRadiusUrlStatus url_status;

  SSH_DEBUG(SSH_D_HIGHSTART,("creating RADIUS URL request"));

  *result = NULL;

  url_req = ssh_calloc(1, sizeof(*url_req));

  if (url_req == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("Out of memory"));
      return SSH_RADIUS_URL_OUT_OF_MEMORY;
    }

  url_req->cb = cb;

  /* Scan for memory needs */

  va_start(ap, ctx);

  while ((cp = va_arg(ap, unsigned char*)) != NULL)
    url_req->nurls++;

  va_end(ap);

  url_req->url = ssh_calloc(1,sizeof(unsigned char*)*url_req->nurls);
  ssh_radius_url_init_avpset(&url_req->avp_set, NULL);

  if (url_req->url == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("Out of memory"));
      ssh_radius_url_destroy_request(url_req);
      return SSH_RADIUS_URL_OUT_OF_MEMORY;
    }

  /* Grab a copy of the user parameters */

  va_start(ap,ctx);

  for (idx = 0; idx < url_req->nurls; idx++)
    {
      cp = va_arg(ap,unsigned char *);
      SSH_ASSERT(cp != NULL);

      url_req->url[idx] = ssh_strdup(cp);
      if (url_req->url[idx] == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,("Out of memory"));
          ssh_radius_url_destroy_request(url_req);
          va_end(ap);
          return SSH_RADIUS_URL_OUT_OF_MEMORY;
        }

      url_status = ssh_radius_url_isok(cp);

      if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL,("error parsing URL %s",cp));
          ssh_radius_url_destroy_request(url_req);
          va_end(ap);
          return url_status;
        }
    }

  while ((cp = va_arg(ap, unsigned char*)) != NULL)
    {
      len = va_arg(ap, size_t);
      avp_type = va_arg(ap, SshRadiusAvpType);
      SSH_ASSERT(cp != NULL);

      if (ssh_radius_url_set_avpset_avp(&url_req->avp_set,
                                        avp_type, cp,
                                        (SshUInt8)len)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL,("Out of memory"));

          ssh_radius_url_destroy_request(url_req);
          return SSH_RADIUS_URL_OUT_OF_MEMORY;
        }
    }

  va_end(ap);

  url_req->req = NULL;
  url_req->s_info = NULL;
  url_req->url_idx = 0;
  url_req->ctx = ctx;

  url_req->url_handle = ssh_operation_register(ssh_radius_url_request_abort,
                                               url_req);


  if (url_req->url_handle == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("Failed to register operation handle"));
      ssh_radius_url_destroy_request(url_req);
      return SSH_RADIUS_URL_OUT_OF_MEMORY;
    }

  url_status = ssh_radius_url_do_next(url_req);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    {
      ssh_radius_url_destroy_request(url_req);
      return url_status;
    }

  *result = url_req->url_handle;

  return SSH_RADIUS_URL_STATUS_SUCCESS;
}

SshRadiusUrlStatus
ssh_radius_url_isok(unsigned char *url)
{
  SshRadiusUrlAvpSetStruct avp_set;
  SshRadiusUrlStatus url_status;
  SshRadiusClientServerInfo s_info;
  SshRadiusClientParamsStruct params;

  SSH_PRECOND(url != NULL);

  /* Check Params specification */

  url_status = ssh_radius_url_init_params(&params, url);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    return url_status;

  ssh_radius_url_uninit_params(&params);

  /* Check server spec. */

  s_info = ssh_radius_client_server_info_create();

  if (s_info == NULL)
    return SSH_RADIUS_URL_OUT_OF_MEMORY;

  url_status = ssh_radius_url_add_server(s_info, url);

  ssh_radius_client_server_info_destroy(s_info);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    return url_status;

  /* Check AVP spec */

  url_status = ssh_radius_url_init_avpset(&avp_set, url);

  if (url_status != SSH_RADIUS_URL_STATUS_SUCCESS)
    return url_status;

  ssh_radius_url_uninit_avpset(&avp_set);

  return SSH_RADIUS_URL_STATUS_SUCCESS;
}

#endif /* SSHDIST_RADIUS */
