/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp module.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshcrc32.h"

#define SSH_DEBUG_MODULE "SshIke"

#ifdef DEBUG_LIGHT
SSH_GLOBAL_DEFINE_INIT(int, ssh_ike_logging_level) = 0;
#endif /* DEBUG_LIGHT */

/*                                                              shade{0.9}
 * Uninitialize isakmp local data                               shade{1.0}
 */
void ssh_ike_uninit(SshIkeContext context)
{
  SshIkeSA sa;
  SshIkeAuditContext audit, next;
  SshADTHandle h;

  SSH_DEBUG(5, ("Start"));

  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, context);
  ike_default_groups_uninit(context);

  /* Remove all sa's */
  while ((h = ssh_adt_enumerate_start(context->isakmp_sa_mapping)) !=
         SSH_ADT_INVALID)
    {
      sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);
      /* Remove ISAKMP SAs */
      sa->lock_flags |= SSH_IKE_ISAKMP_LOCK_FLAG_DELETED;
      ike_remove_callback(sa->isakmp_negotiation);
    }

  audit = context->ike_audit_contexts;
  while (audit)
    {
      next = audit->next;
      ssh_free(audit);
      audit = next;
    }

  ssh_adt_destroy(context->isakmp_sa_mapping);
  ssh_adt_destroy(context->isakmp_cookie_mapping);
  ssh_adt_destroy(context->prime_mapping);
  ssh_free(context->default_port);
  ssh_free(context->default_ip);
  ssh_free(context);
}

/*                                                              shade{0.9}
 * Hash function for prime numbers                              shade{1.0}
 */
unsigned long ike_adt_prime_hash(void *ptr, void *ctx)
{
  return crc32_buffer(ptr, strlen(ptr));
}

/*                                                              shade{0.9}
 * Duplicate function for prime numbers                         shade{1.0}
 */
void *ike_adt_prime_dup(void *ptr, void *ctx)
{
  return ssh_strdup(ptr);
}

/*                                                              shade{0.9}
 * Compare function for prime numbers                           shade{1.0}
 */
int ike_adt_prime_cmp(void *ptr1, void *ptr2, void *ctx)
{
  return strcmp(ptr1, ptr2);
}

/*                                                              shade{0.9}
 * Destroy function for prime numbers                           shade{1.0}
 */
void ike_adt_prime_destroy(void *obj, void *context)
{
  ssh_free(obj);
  return;
}

/*                                                              shade{0.9}
 * Hash function for cookie                                    shade{1.0}
 */
unsigned long ike_adt_cookie_hash(void *ptr, void *ctx)
{
  unsigned char *cookie;
  unsigned long hash = 0;
  int i;
  cookie = ptr;

  for (i = 0; i < SSH_IKE_COOKIE_LENGTH; i++)
    {
      hash = (hash << 8) | (hash >> (sizeof(hash) * 8 - 8));
      hash ^= cookie[i];
    }
  return hash;
}

/*                                                              shade{0.9}
 * Compare function for cookie                                  shade{1.0}
 */
int ike_adt_cookie_cmp(void *ptr1, void *ptr2, void *ctx)
{
  return memcmp(ptr1, ptr2, SSH_IKE_COOKIE_LENGTH);
}

/*                                                              shade{0.9}
 * Isakmp SA hash function.                                     shade{1.0}
 */
unsigned long ike_adt_cookies_hash(void *ptr, void *ctx)
{
  SshIkeCookies c = (SshIkeCookies) ptr;
  unsigned long hash = 0;
  int i;

  for (i = 0; i < SSH_IKE_COOKIE_LENGTH; i++)
    {
      hash = (hash << 8) | (hash >> (sizeof(hash) * 8 - 8));
      hash ^= c->initiator_cookie[i];
      hash ^= c->responder_cookie[i];
    }
  return hash;
}

/*                                                              shade{0.9}
 * Isakmp SA compare function.                                  shade{1.0}
 */
int ike_adt_cookies_cmp(void *ptr1, void *ptr2, void *ctx)
{
  SshIkeCookies c1 = (SshIkeCookies) ptr1;
  SshIkeCookies c2 = (SshIkeCookies) ptr2;
  int a;
  a = memcmp(c1->initiator_cookie, c2->initiator_cookie,
             SSH_IKE_COOKIE_LENGTH);
  if (a != 0)
    return a;

  a = memcmp(c1->responder_cookie, c2->responder_cookie,
             SSH_IKE_COOKIE_LENGTH);
  return a;
}

/*                                                              shade{0.9}
 * Initialize isakmp local data                                 shade{1.0}
 */
SshIkeContext ssh_ike_init(SshIkeParams params,
                           SshAuditContext audit_context)
{
  SshIkeContext context;

  SSH_DEBUG(5, ("Start"));
  SSH_DEBUG(4, ("params->ignore_cr_payloads = %s",
                params->ignore_cr_payloads ? "TRUE" : "FALSE"));
  SSH_DEBUG(4, ("params->no_key_hash_payload = %s",
                params->no_key_hash_payload ? "TRUE" : "FALSE"));
  SSH_DEBUG(4, ("params->no_cr_payloads = %s",
                params->no_cr_payloads ? "TRUE" : "FALSE"));
  SSH_DEBUG(4, ("params->do_not_send_crls = %s",
                params->do_not_send_crls ? "TRUE" : "FALSE"));
  SSH_DEBUG(4, ("params->send_full_chains = %s",
                params->send_full_chains ? "TRUE" : "FALSE"));
  SSH_DEBUG(4, ("params->trust_icmp_messages = %s",
                params->trust_icmp_messages ? "TRUE" : "FALSE"));
  SSH_DEBUG(4, ("params->spi_size = %d", params->spi_size));
  SSH_DEBUG(4, ("params->zero_spi = %s",
                params->zero_spi ? "TRUE" : "FALSE"));
  SSH_DEBUG(4, ("params->max_key_length = %d", params->max_key_length));
  SSH_DEBUG(4, ("params->max_isakmp_sa_count = %d",
                params->max_isakmp_sa_count));
  SSH_DEBUG(4, ("params->randomizers_default_cnt = %d",
                params->randomizers_default_cnt));
  SSH_DEBUG(4, ("params->randomizers_default_max_cnt = %d",
                params->randomizers_default_max_cnt));
  SSH_DEBUG(4, ("params->randomizers_default_retry = %d",
                params->randomizers_default_retry));
  SSH_DEBUG(4, ("params->randomizers_private_cnt = %d",
                params->randomizers_private_cnt));
  SSH_DEBUG(4, ("params->randomizers_private_max_cnt = %d",
                params->randomizers_private_max_cnt));
  SSH_DEBUG(4, ("params->randomizers_private_retry = %d",
                params->randomizers_private_retry));

  if (params->length_of_local_secret != 0)
    {
      ssh_warning("Obsolete parameter length_of_local_secret is "
                  "not set to zero in ssh_ike_init");
    }
  if (params->token_hash_type != NULL)
    {
      ssh_warning("Obsolete parameter token_hash_type is "
                  "not set to zero in ssh_ike_init");
    }

  /* Allocate context */
  context = ssh_calloc(1, sizeof(*context));
  if (context == NULL)
    return NULL;

  if (audit_context != NULL)
    {
      if (!ssh_ike_attach_audit_context(context, audit_context))
        {
          ssh_free(context);
          return NULL;
        }
    }

  if (params->default_ip != NULL)
    {
      context->default_ip = ssh_strdup(params->default_ip);
      SSH_DEBUG(4, ("params->default_ip = %s", params->default_ip));
    }
  else
    context->default_ip = ssh_strdup(SSH_IKE_DEFAULT_IP);

  if (params->default_port != NULL)
    {
      context->default_port = ssh_strdup(params->default_port);
      SSH_DEBUG(4, ("params->default_port = %s", params->default_port));
    }
  else
    context->default_port = ssh_strdup(SSH_IKE_DEFAULT_PORT);

  if (context->default_ip == NULL ||
      context->default_port == NULL)
    {
      ssh_free(context->ike_audit_contexts);
      ssh_free(context->default_ip);
      ssh_free(context->default_port);
      ssh_free(context);
      return NULL;
    }

  if (params->base_retry_limit > 0)
    {
      context->base_retry_limit = params->base_retry_limit;
      SSH_DEBUG(4, ("params->base_retry_limit = %u",
                    (unsigned int) params->base_retry_limit));
    }
  else
    context->base_retry_limit = SSH_IKE_BASE_RETRY_LIMIT;

  if (params->base_retry_timer > 0 || params->base_retry_timer_usec > 0)
    {
      context->base_retry_timer = params->base_retry_timer;
      context->base_retry_timer_usec = params->base_retry_timer_usec;
      SSH_DEBUG(4, ("params->base_retry_timer = %u.%06u",
                    (unsigned int) params->base_retry_timer,
                    (unsigned int) params->base_retry_timer_usec));
    }
  else
    {
      context->base_retry_timer = SSH_IKE_BASE_RETRY_TIMER;
      context->base_retry_timer_usec = SSH_IKE_BASE_RETRY_TIMER_USEC;
    }

  if (params->base_retry_timer_max > 0 ||
      params->base_retry_timer_max_usec > 0)
    {
      context->base_retry_timer_max = params->base_retry_timer_max;
      context->base_retry_timer_max_usec = params->base_retry_timer_max_usec;
      SSH_DEBUG(4, ("params->base_retry_timer_max = %u.%06u",
                    (unsigned int) params->base_retry_timer_max,
                    (unsigned int) params->base_retry_timer_max_usec));
    }
  else
    {
      context->base_retry_timer_max = SSH_IKE_BASE_RETRY_TIMER_MAX;
      context->base_retry_timer_max_usec = SSH_IKE_BASE_RETRY_TIMER_MAX_USEC;
    }

  if (params->base_expire_timer > 0 || params->base_expire_timer_usec > 0)
    {
      context->base_expire_timer = params->base_expire_timer;
      context->base_expire_timer_usec = params->base_expire_timer_usec;
      SSH_DEBUG(4, ("params->base_expire_timer = %u.%06u",
                    (unsigned int) params->base_expire_timer,
                    (unsigned int) params->base_expire_timer_usec));
    }
  else
    {
      context->base_expire_timer = SSH_IKE_BASE_EXPIRE_TIMER;
      context->base_expire_timer_usec = SSH_IKE_BASE_EXPIRE_TIMER_USEC;
    }

  if (params->extended_retry_limit > 0)
    {
      context->extended_retry_limit = params->extended_retry_limit;
      SSH_DEBUG(4, ("params->extended_retry_limit = %u",
                    (unsigned int) params->extended_retry_limit));
    }
  else
    context->extended_retry_limit = SSH_IKE_EXTENDED_RETRY_LIMIT;

  if (params->extended_retry_timer > 0 ||
      params->extended_retry_timer_usec > 0)
    {
      context->extended_retry_timer = params->extended_retry_timer;
      context->extended_retry_timer_usec = params->extended_retry_timer_usec;
      SSH_DEBUG(4, ("params->extended_retry_timer = %u.%06u",
                    (unsigned int) params->extended_retry_timer,
                    (unsigned int) params->extended_retry_timer_usec));
    }
  else
    {
      context->extended_retry_timer = SSH_IKE_EXTENDED_RETRY_TIMER;
      context->extended_retry_timer_usec = SSH_IKE_EXTENDED_RETRY_TIMER_USEC;
    }

  if (params->extended_retry_timer_max > 0 ||
      params->extended_retry_timer_max_usec > 0)
    {
      context->extended_retry_timer_max = params->extended_retry_timer_max;
      context->extended_retry_timer_max_usec =
        params->extended_retry_timer_max_usec;
      SSH_DEBUG(4, ("params->extended_retry_timer_max = %u.%06u",
                    (unsigned int) params->extended_retry_timer_max,
                    (unsigned int) params->extended_retry_timer_max_usec));
    }
  else
    {
      context->extended_retry_timer_max = SSH_IKE_EXTENDED_RETRY_TIMER_MAX;
      context->extended_retry_timer_max_usec =
        SSH_IKE_EXTENDED_RETRY_TIMER_MAX_USEC;
    }

  if (params->extended_expire_timer > 0 ||
      params->extended_expire_timer_usec > 0)
    {
      context->extended_expire_timer = params->extended_expire_timer;
      context->extended_expire_timer_usec = params->extended_expire_timer_usec;
      SSH_DEBUG(4, ("params->extended_expire_timer = %u.%06u",
                    (unsigned int) params->extended_expire_timer,
                    (unsigned int) params->extended_expire_timer_usec));
    }
  else
    {
      context->extended_expire_timer = SSH_IKE_EXTENDED_EXPIRE_TIMER;
      context->extended_expire_timer_usec = SSH_IKE_EXTENDED_EXPIRE_TIMER_USEC;
    }

  if (params->randomizers_default_cnt > 0)
    context->randomizers_default_cnt = params->randomizers_default_cnt;
  else
    context->randomizers_default_cnt = SSH_IKE_RANDOMIZERS_DEFAULT_CNT;

  if (params->randomizers_default_max_cnt > 0)
    context->randomizers_default_max_cnt = params->randomizers_default_max_cnt;
  else
    context->randomizers_default_max_cnt = SSH_IKE_RANDOMIZERS_DEFAULT_MAX_CNT;

  if (params->randomizers_default_retry > 0)
    context->randomizers_default_retry = params->randomizers_default_retry;
  else
    context->randomizers_default_retry = SSH_IKE_RANDOMIZERS_DEFAULT_RETRY;

  if (params->randomizers_private_cnt > 0)
    context->randomizers_private_cnt = params->randomizers_private_cnt;
  else
    context->randomizers_private_cnt = SSH_IKE_RANDOMIZERS_PRIVATE_CNT;

  if (params->randomizers_private_max_cnt > 0)
    context->randomizers_private_max_cnt = params->randomizers_private_max_cnt;
  else
    context->randomizers_private_max_cnt = SSH_IKE_RANDOMIZERS_PRIVATE_MAX_CNT;

  if (params->randomizers_private_retry > 0)
    context->randomizers_private_retry = params->randomizers_private_retry;
  else
    context->randomizers_private_retry = SSH_IKE_RANDOMIZERS_PRIVATE_RETRY;

#ifdef SSHDIST_EXTERNALKEY
  context->external_key = params->external_key;
  context->accelerator_short_name = params->accelerator_short_name;
#endif /* SSHDIST_EXTERNALKEY */

  context->no_key_hash_payload = params->no_key_hash_payload;
  context->no_cr_payloads = params->no_cr_payloads;
  context->trust_icmp_messages = params->trust_icmp_messages;
  context->private_payload_phase_1_check =
    params->private_payload_phase_1_check;
  context->private_payload_phase_1_input =
    params->private_payload_phase_1_input;
  context->private_payload_phase_1_output =
    params->private_payload_phase_1_output;

  context->private_payload_phase_2_check =
    params->private_payload_phase_2_check;
  context->private_payload_phase_2_input =
    params->private_payload_phase_2_input;
  context->private_payload_phase_2_output =
    params->private_payload_phase_2_output;

  context->private_payload_phase_qm_check =
    params->private_payload_phase_qm_check;
  context->private_payload_phase_qm_input =
    params->private_payload_phase_qm_input;
  context->private_payload_phase_qm_output =
    params->private_payload_phase_qm_output;

  context->private_payload_context =
    params->private_payload_context;

  if (params->ignore_cr_payloads)
    context->default_compat_flags |= SSH_IKE_FLAGS_IGNORE_CR_PAYLOADS;
  if (params->do_not_send_cert_chains)
    context->default_compat_flags |= SSH_IKE_FLAGS_DO_NOT_SEND_CERT_CHAINS;
  if (params->do_not_send_crls)
    context->default_compat_flags |= SSH_IKE_FLAGS_DO_NOT_SEND_CRLS;
  if (params->send_full_chains)
    context->default_compat_flags |= SSH_IKE_FLAGS_SEND_FULL_CHAINS;
  if (params->zero_spi)
    context->default_compat_flags |= SSH_IKE_FLAGS_USE_ZERO_SPI;
  if (params->zero_spi)
    {
      if (params->spi_size < 0)
        context->spi_size = 0;
      else
        context->spi_size = params->spi_size;
    }
  else
    {
      context->spi_size = SSH_IKE_COOKIE_LENGTH;
    }

  if (params->max_key_length > 0)
    context->max_key_length = params->max_key_length;
  else
    context->max_key_length = 512;

  if (params->max_isakmp_sa_count > 0)
    context->max_isakmp_sa_count = params->max_isakmp_sa_count;
  else
    context->max_isakmp_sa_count = 512;

  context->debug_config = params->debug_config;

  /* This is mapping whose key is the cookies, and whose value is the SshIkeSA
     pointer. */
  context->isakmp_sa_mapping =
    ssh_adt_create_generic(SSH_ADT_MAP,
                           SSH_ADT_HASH, ike_adt_cookies_hash,
                           SSH_ADT_COMPARE, ike_adt_cookies_cmp,
                           SSH_ADT_SIZE, (size_t) SSH_IKE_COOKIE_LENGTH * 2,
                           SSH_ADT_ARGS_END);

  /* This is mapping whose key is the initiator cookie, and whose value is the
     SshIkeSA pointer. */
  context->isakmp_cookie_mapping =
    ssh_adt_create_generic(SSH_ADT_MAP,
                           SSH_ADT_HASH, ike_adt_cookie_hash,
                           SSH_ADT_COMPARE, ike_adt_cookie_cmp,
                           SSH_ADT_SIZE, (size_t) SSH_IKE_COOKIE_LENGTH,
                           SSH_ADT_ARGS_END);

  /* This is a mapping whose key is the number (represented as null terminated
     string) and whose value is 0 (false) or 1 (true). If the value is 0 then
     the number is not prime, if it is 1 then it is prime. If the value is not
     represented in the mapping then we do not know if it is prime or not. */
  context->prime_mapping =
    ssh_adt_create_generic(SSH_ADT_MAP,
                           SSH_ADT_HASH, ike_adt_prime_hash,
                           SSH_ADT_COMPARE, ike_adt_prime_cmp,
                           SSH_ADT_DUPLICATE, ike_adt_prime_dup,
                           SSH_ADT_DESTROY, ike_adt_prime_destroy,
                           SSH_ADT_ARGS_END);

  if (context->isakmp_sa_mapping == NULL ||
      context->isakmp_cookie_mapping == NULL ||
      context->prime_mapping == NULL)
    {
      ssh_adt_destroy(context->isakmp_sa_mapping);
      ssh_adt_destroy(context->isakmp_cookie_mapping);
      ssh_adt_destroy(context->prime_mapping);
      ssh_free(context->ike_audit_contexts);
      ssh_free(context->default_ip);
      ssh_free(context->default_port);
      ssh_free(context);
      return NULL;
    }
  if (!ike_default_groups_init(context))
    {
      ike_default_groups_uninit(context);
      ssh_adt_destroy(context->isakmp_sa_mapping);
      ssh_adt_destroy(context->isakmp_cookie_mapping);
      ssh_adt_destroy(context->prime_mapping);
      ssh_free(context->ike_audit_contexts);
      ssh_free(context->default_ip);
      ssh_free(context->default_port);
      ssh_free(context);
      return NULL;
    }
  return context;
}


/*                                                              shade{0.9}
 * Calculate ipsec key (of given size (in bits)) for
 * given spi and protocol.                                      shade{1.0}
 */
SshCryptoStatus ssh_ike_ipsec_keys(SshIkeNegotiation negotiation,
                                   SshIkeIpsecKeymat keymat,
                                   size_t spi_size,
                                   unsigned char *spi,
                                   SshIkeProtocolIdentifiers protocol_id,
                                   size_t key_len,
                                   unsigned char *key_out)
{
  SshMac mac;
  SshCryptoStatus cret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len;
  unsigned char c;
  size_t len;

  /* Allocate mac */
  cret = ssh_mac_allocate(ssh_csstr(keymat->skeyid_d_mac_alg),
                          keymat->skeyid_d,
                          keymat->skeyid_d_size, &mac);
  if (cret != SSH_CRYPTO_OK)
    return cret;

  hash_len = ssh_mac_length(ssh_mac_name(mac));

  /* Convert length from bits to bytes */
  key_len = (key_len + 7) / 8;

  SSH_IKE_DEBUG(6, negotiation, ("Ipsec keys, mac = %s, proto = %d",
                                 keymat->skeyid_d_mac_alg,
                                 protocol_id));
  SSH_IKE_DEBUG_BUFFER(7, negotiation, "spi", spi_size, spi);
  SSH_IKE_DEBUG_BUFFER(7, negotiation, "keymat.skeyid_d",
                       keymat->skeyid_d_size, keymat->skeyid_d);
  if (keymat->gqmxy_size != 0)
    {
      SSH_IKE_DEBUG_BUFFER(7, negotiation, "keymat.gqmxy", keymat->gqmxy_size,
                           keymat->gqmxy);
    }

  SSH_IKE_DEBUG_BUFFER(7, negotiation, "keymat.ni", keymat->ni_size,
                       keymat->ni);
  SSH_IKE_DEBUG_BUFFER(7, negotiation, "keymat.nr", keymat->nr_size,
                       keymat->nr);

  len = 0;
  /* K1 = prf(SKEYID_d, [g(qm)^xy] | protocol | SPI | Ni | Nr)
     Kn = prf(SKEYID_d, Kn-1 | [g(qm)^xy] | protocol | SPI | Ni | Nr)
     KEYMAT = K1 | ... | Kn */
  while (len < key_len)
    {
      ssh_mac_reset(mac);
      SSH_IKE_DEBUG(9, negotiation, ("Start round, len = %d/%d",
                                     len, key_len));

      /* Not on first round */
      if (len != 0)
        {
          ssh_mac_update(mac, hash, hash_len);
          SSH_IKE_DEBUG_BUFFER(9, negotiation, "hash .= hash", hash_len, hash);
        }

      /* Do we have g(qm)^xy */
      if (keymat->gqmxy_size != 0)
        {
          ssh_mac_update(mac, keymat->gqmxy, keymat->gqmxy_size);
          SSH_IKE_DEBUG_BUFFER(9, negotiation, "hash .= gqmxy",
                               keymat->gqmxy_size,
                               keymat->gqmxy);
        }

      /* Protocol id */
      c = protocol_id;
      ssh_mac_update(mac, &c, 1);
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "hash .= protocol_id", 1, &c);

      /* Spi */
      ssh_mac_update(mac, spi, spi_size);
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "hash .= spi", spi_size, spi);

      /* Ni */
      ssh_mac_update(mac, keymat->ni, keymat->ni_size);
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "hash .= ni", keymat->ni_size,
                           keymat->ni);

      /* Nr */
      ssh_mac_update(mac, keymat->nr, keymat->nr_size);
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "hash .= nr", keymat->nr_size,
                           keymat->nr);

      /* Output */
      ssh_mac_final(mac, hash);
      SSH_IKE_DEBUG_BUFFER(9, negotiation, "hash.out", hash_len, hash);

      /* Copy output to output buffer */
      if (len + hash_len > key_len)
        memcpy(key_out + len, hash, key_len - len);
      else
        memcpy(key_out + len, hash, hash_len);
      len += hash_len;
    }
  SSH_IKE_DEBUG_BUFFER(7, negotiation, "key.out", key_len, key_out);
  ssh_mac_free(mac);
  return SSH_CRYPTO_OK;
}

void ssh_ike_detach_server(SshIkeServerContext server_context)
{
  Boolean removed_something;
  SshIkeContext context;
  SshADTHandle h, hnext;
  SshIkeSA sa;

  if ((context = server_context->isakmp_context) == NULL)
    return;

  /* Note, that when we remove something from the mapping during the mapping
     enumartion, the mapping index is lost, which means that we have to restart
     the operation as long as there was some entries removed during the loop.
     After we loop through the mapping without deleting anything we can assume
     we had deleted everything */
  do {
    removed_something = FALSE;

    for (h = ssh_adt_enumerate_start(context->isakmp_sa_mapping);
         h != SSH_ADT_INVALID;
         h = hnext)
      {
        hnext = ssh_adt_enumerate_next(context->isakmp_sa_mapping, h);

        sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);
        if (sa->server_context != server_context)
          continue;
        /* Immediately remove all ISAKMP SAs still active for this server */
        sa->lock_flags |= SSH_IKE_ISAKMP_LOCK_FLAG_DELETED;
        SSH_DEBUG(7, ("Removed SA %p", sa));
        ike_remove_callback(sa->isakmp_negotiation);
        removed_something = TRUE;
      }
  } while (removed_something);
}

/* Stop isakmp/oakley server. */
void ssh_ike_stop_server(SshIkeServerContext server_context)
{
  SSH_DEBUG(5, ("Start"));

  ssh_ike_detach_server(server_context);
  ssh_udp_destroy_listener(server_context->normal_listener);
  ssh_free(server_context);
}

/* Get the isakmp/oakley server used for the negotiation. */
SshIkeServerContext ssh_ike_get_server_by_negotiation(
                                                SshIkeNegotiation negotiation)
{
  return negotiation->sa->server_context;
}

/* Get the policy manager Phase-1 information from the IKE negotiation
   `negotiation'.  The function returns a pointer to the IKE info or
   NULL if the `negotiation' is not a valid IKE SA. */
SshIkePMPhaseI ssh_ike_get_pm_phase_i_info_by_negotiation(
                                                SshIkeNegotiation negotiation)
{
  if (negotiation->exchange_type != SSH_IKE_XCHG_TYPE_AGGR
      && negotiation->exchange_type != SSH_IKE_XCHG_TYPE_IP)
    return NULL;

  return negotiation->ike_pm_info;
}

/* Configure contexts and callbacks to ikev2 server context represented by
   server. */
void ssh_ike_attach_server(SshIkeServerContext server,
                           SshIkeContext ike,
                           SshIkePMContext pm,
                           SshIkeIpsecSAHandler sa_callback,
                           void *sa_callback_context)
{
  server->isakmp_context = ike;
  server->pm = pm;
  server->sa_callback = sa_callback;
  server->sa_callback_context = sa_callback_context;
}


/*                                                              shade{0.9}
 * Start isakmp/oakley server. This will return server
 * context that can be used later to destroy server. All
 * server share security assosiations, but there can be
 * several servers each on separate ip/port pair.
 * This return NULL if it runs out of memory.                   shade{1.0}
 */
SshIkeServerContext ssh_ike_start_server(SshIkeContext context,
                                         const unsigned char *server_name,
                                         const unsigned char *server_port,
                                         int interface_index,
                                         int routing_instance_id,
                                         SshIkePMContext pm,
                                         SshIkeIpsecSAHandler sa_callback,
                                         void *sa_callback_context)
{
  SshIkeServerContext server;

  if (server_name == NULL)
    server_name = context->default_ip;
  if (server_port == NULL)
    server_port = context->default_port;

  SSH_DEBUG(5, ("Start, server_name = %s:%s", server_name, server_port));
  server = ssh_calloc(1, sizeof(struct SshIkeServerContextRec));
  if (server == NULL)
    return NULL;

  ssh_ike_attach_server(server,
                        context, pm, sa_callback, sa_callback_context);

  server->routing_instance_id = routing_instance_id;
  server->interface_index = interface_index;

  if (!ssh_ipaddr_parse(server->ip_address, server_name) ||
      (server->normal_local_port = atoi((char *)server_port)) == 0)
    {
      ssh_free(server);
      return NULL;
    }

  server->normal_listener =
          ssh_udp_make_listener_ip(server->ip_address,
                                   server->normal_local_port,
                                   NULL, 0,
                                   server->interface_index,
                                   server->routing_instance_id,
                                   NULL,
                                   ike_udp_callback, server);

  if (server->normal_listener == NULL)
    {
      SSH_DEBUG(3, ("ssh_iskamp_start_server: ssh_udp_make_listener failed"));
      ssh_free(server);
      return NULL;
    }

  return server;
}

/*                                                              shade{0.9}
 * First step of the negotiation. Return
 * TRUE if everything ok, otherwise free
 * negotiation and return FALSE.                                shade{1.0}
 */
Boolean ike_first_step(SshIkeNegotiation negotiation)
{
  SshIkeSA sa;
  SshIkePacket isakmp_packet_out;
  SshBuffer buffer;
  SshIkeNotifyMessageType ret;

  sa = negotiation->sa;

  /* Execute first step. */
  ret = ike_state_step(sa->server_context->isakmp_context, NULL,
                       &isakmp_packet_out, sa, negotiation);

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    goto error;

  if (ret == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
    {
      SSH_DEBUG(7, ("Connected, sending notify"));
      ike_send_notify(sa->server_context, negotiation, ret);
      ssh_buffer_free(buffer);
      return TRUE;
    }
  if (ret != 0)
    goto error;

  /* Check if we have output packet */
  if (isakmp_packet_out == NULL)
    {
      /* No output packet return */
      ssh_buffer_free(buffer);
      return TRUE;
    }

  /* Encode response packet. */
  ret = ike_encode_packet(sa->server_context->isakmp_context,
                          isakmp_packet_out, sa, negotiation,
                          buffer);
  if (ret != 0)
    goto error;

  ret = ike_send_packet(negotiation,
                        ssh_buffer_ptr(buffer),
                        ssh_buffer_len(buffer), FALSE, FALSE);
  if (ret != 0)
    goto error;
  ssh_buffer_free(buffer);
  return TRUE;
error:
  SSH_DEBUG(7, ("Error %s in initial packet, but after encode, send notify",
                ssh_ike_error_code_to_string(ret)));
  ike_debug_exchange_fail_local(negotiation, ret);
  ike_call_callbacks(negotiation, ret);
  ike_delete_negotiation(negotiation);
  if (buffer)
    ssh_buffer_free(buffer);
  return FALSE;

}

/*                                                              shade{0.9}
 * Establish isakmp SA with some other host.
 * Returns error code if error occurs when sending
 * first packet, and does NOT call notify
 * callback, or allocate anything. Otherwise
 * return allocated IsakmpNegotiation structure in
 * negotiation parameter that can be used to clear
 * state later. If the error occurs when sending
 * the first packet but after it has already
 * changed the data given to it, it will call the
 * callback, free the data, return
 * SSH_IKE_ERROR_OK, but set returned negotiation
 * pointer to NULL.
 *
 * If error occurs later the error_callback
 * function is called and context is added to
 * freelist (it will be automatically freed later
 * when retransmit timeout is expired, and other
 * end cannot send more packets).
 *
 * The remote_name, and remote_port are used to
 * send packet. Local_id is used as isakmp
 * identity given to other end. The sa_proposal is
 * our proposal for sa negotiation. They are both
 * freed by isakmp code after they are not needed
 * anymore. Note that this code assumes that if
 * the id is fqdn, user_fqdn, der_asn1_dn or
 * der_asn1_gn then the memory used is mallocated.
 *
 * Also the sa proposal sa_attributes are assumed
 * to be allocated with one malloc so freeing
 * sa_attributes table will free both the tables
 * and the data. If the spi is given it is used
 * (the data is freed). If spi pointers are NULL
 * then they are filled with either zeros or our
 * initiator cookie, depending on the zero_spi
 * parameter to ssh_isakmp_init.
 *
 * The exchange_type must be either
 * SSH_IKE_XCHG_TYPE_IP (identity protection ==
 * oakley main mode), or SSH_IKE_XCHG_TYPE_AGGR
 * (aggressive == oakley aggressive).
 *
 * When isakmp sa negotiation is done, the
 * notify_callback will be called with value
 * SSH_IKE_NOTIFY_MESSAGE_CONNECTED as error code.
 *
 * The policy_manager_data pointer is stored in the
 * policy manager information structure in the
 * policy_manager_data field.
 *
 * Flags can be any combination of the compat
 * flags (SSH_IKE_FLAGS_*) or'ed together. shade{1.0} */
SshIkeErrorCode ssh_ike_connect(SshIkeServerContext context,
                                SshIkeNegotiation *negotiation_out,
                                /* Destination address */
                                const unsigned char *remote_name,
                                /* May be NULL == use default (500) */
                                const unsigned char *remote_port,
                                SshIkePayloadID local_id,
                                SshIkePayloadSA sa_proposal,
                                SshIkeExchangeType exchange_type,
                                const unsigned char *initiator_cookie,
                                void *policy_manager_data,
                                SshUInt32 connect_flags,
                                SshIkeNotify notify_callback,
                                void *notify_callback_context)
{
  SshIkeSA sa;
  SshIkeNegotiation negotiation;
  SshIkeAuthMeth auth_method_type;
  char id_txt[255];
  int auth_method = -1;
  int j, k, l;
  SshIkeGroupMap grp = NULL;
  unsigned char n[64], p[6];
  SshUInt16 local_port;
#ifdef SSHDIST_IKEV2
  unsigned char r[6];
#endif /* SSHDIST_IKEV2 */

  *negotiation_out = NULL;

  if (remote_port == NULL)
    {
      remote_port = context->isakmp_context->default_port;
#ifdef SSHDIST_IKEV2
      if (connect_flags & SSH_IKE_FLAGS_START_WITH_NAT_T)
        remote_port = ike_port_string(context->nat_t_remote_port,
                                      r, sizeof(r));
#endif /* SSHDIST_IKEV2 */
    }

  SSH_DEBUG(5, ("Start, remote_name = %s:%s, xchg = %d, flags = %08lx",
                remote_name, remote_port, exchange_type,
                (unsigned long) connect_flags));

  /* Allocate sa */
  sa = ike_sa_allocate_half(context, remote_name, remote_port,
                            initiator_cookie);

  if (sa == NULL)
    return SSH_IKE_ERROR_OUT_OF_MEMORY;

  local_port = context->normal_local_port;
#ifdef SSHDIST_IKEV2
  if (connect_flags & SSH_IKE_FLAGS_START_WITH_NAT_T)
    local_port = context->nat_t_local_port;
#endif /* SSHDIST_IKEV2 */

  if (!ike_init_isakmp_sa(sa,
                          ike_ip_string(context->ip_address, n, sizeof(n)),
                          ike_port_string(local_port, p, sizeof(p)),
                          remote_name, remote_port,
                          SSH_IKE_MAJOR_VERSION, SSH_IKE_MINOR_VERSION,
                          exchange_type, TRUE,
                          (connect_flags & SSH_IKE_FLAGS_USE_EXTENDED_TIMERS)
                          != 0))
    {
      ike_sa_delete(context->isakmp_context, sa);
      ssh_free(sa);
      return SSH_IKE_ERROR_OUT_OF_MEMORY;
    }

  negotiation = sa->isakmp_negotiation;

  negotiation->ed->notify_callback = notify_callback;
  negotiation->ed->notify_callback_context = notify_callback_context;
  if ((connect_flags & 0xffff) == SSH_IKE_FLAGS_USE_DEFAULTS)
    negotiation->ed->compat_flags =
      context->isakmp_context->default_compat_flags;
  else
    negotiation->ed->compat_flags = connect_flags & 0xffff;
  negotiation->ike_ed->connect_flags = connect_flags;
  negotiation->ike_pm_info->sa_start_time = ssh_time();
  negotiation->ike_pm_info->sa_expire_time = 0;

#ifdef SSHDIST_IKEV2
  if (connect_flags & SSH_IKE_FLAGS_START_WITH_NAT_T)
    {
      sa->use_natt = 1;
      SSH_DEBUG(5, ("Starting negotiation with floated ports %@:%d -> %s:%s",
                    ssh_ipaddr_render, context->ip_address, local_port,
                    remote_name, remote_port));
    }
#endif /* SSHDIST_IKEV2 */

  if (sa_proposal->number_of_proposals != 1)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Warning: Number of proposals != 1 in ISAKMP SA, "
                     "this is against draft!"));
    }

  SSH_IKE_DEBUG(9, negotiation, ("SA: Number of proposals = %d",
                                 sa_proposal->number_of_proposals));
  for (j = 0; j < sa_proposal->number_of_proposals; j++)
    {
      SSH_IKE_DEBUG(9, negotiation,
                    ("SA[%d]: Number of protocols = %d",
                     j, sa_proposal->proposals[j].number_of_protocols));
      for (k = 0; k < sa_proposal->proposals[j].number_of_protocols; k++)
        {
          SSH_IKE_DEBUG(9, negotiation,
                        ("SA[%d][%d]: Number of transforms = %d",
                         j, k, sa_proposal->proposals[j].
                         protocols[k].number_of_transforms));
          if (sa_proposal->proposals[j].protocols[k].protocol_id !=
              SSH_IKE_PROTOCOL_ISAKMP)
            continue;
          for (l = 0;
              l < sa_proposal->proposals[j].
                protocols[k].number_of_transforms;
              l++)
            {
              struct SshIkeAttributesRec attrs;

              SSH_IKE_DEBUG(9, negotiation,
                            ("SA[%d][%d][%d]: ISAKMP protocol",
                                 j, k, l));

              ssh_ike_clear_isakmp_attrs(&attrs);
              if (ssh_ike_read_isakmp_attrs(negotiation,
                                            &(sa_proposal->proposals[j].
                                              protocols[k].transforms[l]),
                                            &attrs))
                {
                  if (auth_method == -1)
                    {
                      auth_method = attrs.auth_method;
                    }
                  else if (auth_method != attrs.auth_method)
                    {
                      if (exchange_type == SSH_IKE_XCHG_TYPE_AGGR)
                        {
                          SSH_DEBUG(3,
                                    ("Different authentication methods "
                                     "in local proposal in aggressive mode"));
                          goto invalid_arg_error;
                        }
                      auth_method = -2;
                    }
                  if (grp == NULL)
                    {
                      grp = attrs.group_desc;
                    }
                  else if (grp != attrs.group_desc)
                    {
                      if (exchange_type == SSH_IKE_XCHG_TYPE_AGGR)
                        {
                          SSH_DEBUG(3,
                                    ("Different groups "
                                     "in local proposal in aggressive mode"));
                          goto invalid_arg_error;
                        }
                    }

                  if (attrs.life_duration_secs != 0 &&
                      negotiation->ike_pm_info->sa_start_time +
                      attrs.life_duration_secs >
                       negotiation->ike_pm_info->sa_expire_time)
                    {
                      negotiation->ike_pm_info->sa_expire_time =
                        negotiation->ike_pm_info->sa_start_time +
                        attrs.life_duration_secs;
                    }
                }
              else
                {
                  SSH_DEBUG(3,
                            ("Warning: Local proposal includes "
                             "unknown or unsupported values"));
                }
            }
        }
    }
  if (negotiation->ike_pm_info->sa_expire_time == 0)
    negotiation->ike_pm_info->sa_expire_time =
      negotiation->ike_pm_info->sa_start_time +
      SSH_IKE_DEFAULT_LIFE_DURATION;

  switch (auth_method)
    {
    case -2:
      /* Different authentication methods inside the exchange */
      auth_method_type = SSH_IKE_AUTH_METHOD_ANY;
      break;
    case SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_PRE_SHARED:
#endif /* SSHDIST_IKE_XAUTH */
      auth_method_type = SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY;
      break;
#ifdef SSHDIST_IKE_CERT_AUTH
    case SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES:
#endif /* SSHDIST_IKE_XAUTH */
      auth_method_type = SSH_IKE_AUTH_METHOD_SIGNATURES;
      break;
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED:
#endif /* SSHDIST_IKE_XAUTH */
      auth_method_type = SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION;
      break;
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef REMOVED_BY_DOI_DRAFT_07
    case SSH_IKE_VALUES_AUTH_METH_GSSAPI:
      ssh_warning("GSSAPI authentication not yet supported");
      goto invalid_arg_error;
#endif
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521:
      auth_method_type = SSH_IKE_AUTH_METHOD_SIGNATURES;
      break;
#endif /* SSHDIST_CRYPT_ECP */
#endif /* SSHDIST_IKE_CERT_AUTH */
    default:
      goto invalid_arg_error;
    }

  negotiation->ike_ed->local_sa_proposal = sa_proposal;
  negotiation->ike_pm_info->local_id = local_id;
  ssh_ike_id_to_string(id_txt, sizeof(id_txt), local_id);
  ssh_free(negotiation->ike_pm_info->local_id_txt);
  negotiation->ike_pm_info->local_id_txt = ssh_strdup(id_txt);
  if (negotiation->ike_pm_info->local_id_txt == NULL)
    goto out_of_memory_error;
  negotiation->ike_pm_info->policy_manager_data = policy_manager_data;

  negotiation->ike_pm_info->auth_method =
    (SshIkeAttributeAuthMethValues) auth_method;
  negotiation->ike_pm_info->auth_method_type = auth_method_type;
  negotiation->ed->auth_method_type = auth_method_type;
  negotiation->ed->current_state = SSH_IKE_ST_START_SA_NEGOTIATION_I;

  if (connect_flags & SSH_IKE_IKE_FLAGS_TRUST_ICMP_MESSAGES ||
      context->isakmp_context->trust_icmp_messages)
    {
      SshIpAddrStruct r_addr;
      SshUInt16 r_port;

      ssh_ipaddr_parse(&r_addr, remote_name);
      r_port = (SshUInt16) strtoul((char *)remote_port, NULL, 0);

      negotiation->ike_ed->listener =
        ssh_udp_make_listener_ip(context->ip_address,
                                 context->normal_local_port,
                                 &r_addr, r_port,
                                 context->interface_index,
                                 context->routing_instance_id,
                                 NULL,
                                 ike_udp_callback_first, negotiation);

      /* If making listener fails, we just use default listener. We just don't
         get those connection refused messages from the other end, but it
         doesn't matter. Because ssh_udp_make_listener returns NULL in that
         case, and that means that we use the default listener, so there no
         need to do anything */
      if (negotiation->ike_ed->listener == NULL)
        SSH_DEBUG(4, ("Creating udp listener failed"));
    }

  *negotiation_out = negotiation;

  SSH_DEBUG(5, ("SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                negotiation->negotiation_index));

  SSH_IKE_DEBUG(6, negotiation, ("Start isakmp sa negotiation"));
  ike_debug_exchange_begin(negotiation);

  if (ike_first_step(negotiation))
    return SSH_IKE_ERROR_OK;
  /* local_sa_proposal, local_id, and policy_manager_data are already
     freed here, return NULL negotiation_out */
  *negotiation_out = NULL;
  return SSH_IKE_ERROR_OK;
invalid_arg_error:
  SSH_DEBUG(7, ("Error invalid arguments, do not send notify"));
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
  ike_delete_negotiation(negotiation);
  *negotiation_out = NULL;
  return SSH_IKE_ERROR_INVALID_ARGUMENTS;
out_of_memory_error:
  SSH_DEBUG(7, ("Out of memory, do not send notify"));
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
  ike_delete_negotiation(negotiation);
  *negotiation_out = NULL;
  return SSH_IKE_ERROR_OUT_OF_MEMORY;
}

/*                                                              shade{0.9}
 * Create ipsec SA with some other host. Returns
 * error code if error occurs when sending first
 * packet, and does NOT call notify callback, or
 * allocate anything. Otherwise return allocated
 * SshIkeNegotiation structure in negotiation
 * parameters that can be used to clear state
 * later. If there is no Isakmp SA already
 * negotiated with other end this function will
 * return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND and
 * does not do anything. If the error occurs when sending
 * the first packet but after it has already
 * changed the data given to it, it will call the
 * callback, free the data, return
 * SSH_IKE_ERROR_OK, but set returned negotiation
 * pointer to NULL.
 *
 * If error occurs later the error_callback
 * function is called and context is added to
 * freelist (it will be automatically freed later
 * when retransmit timeout is expired, and other
 * end cannot send more packets).
 *
 * If isakmp_sa_negotiation is given then it is
 * assumed to be ISAKMP SA negotiation pointer
 * returned by previous ssh_ike_connect call. If
 * that pointer is no longer valid
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
 * returned.
 *
 * If isakmp_sa_negotiation is NULL, then the
 * remote_name, and remote_port are used to find
 * matching isakmp SA. Local_id and remote_id are
 * used as isakmp identities given to other end
 * (they can be NULL, in which case no identity is
 * given to other end).
 *
 * The number_of_sa_proposals parameters
 * identifies the count of ipsec security
 * associations to negotiate with other end. The
 * sa_proposals contains a table of our proposals
 * for each sa negotiation (note that all those sa
 * negotiations are send as one quick mode
 * negotiation, so they all must use same group
 * for pfs, if they dont have consistent group for
 * each sa / proposal / transform a
 * SSH_IKE_ERROR_INVALID_ARGUMENTS error code is
 * returned).
 *
 * They are all freed by isakmp code after they
 * are not needed anymore. Note that this code
 * assumes that if the id is fqdn, user_fqdn,
 * der_asn1_dn or der_asn1_gn then the memory used
 * is mallocated.
 *
 * Also the sa proposal sa_attributes are assumed
 * to be allocated with one malloc so freeing
 * sa_attributes table will free both the tables
 * and the data. The spi value is also freed.
 *
 * The policy_manager_data pointer is stored in the
 * policy manager information structure in the
 * policy_manager_data field.
 *
 * Flags can be any combination of the compat
 * flags (SSH_IKE_FLAGS_*) or'ed together. If the
 * connect_flags has SSH_IKE_IPSEC_FLAGS_WANT_PFS
 * set then quick mode will use perfect forward
 * secrecy.
 *
 * When quick mode negotiation is done, the
 * notify_callback will be called with value
 * SSH_IKE_NOTIFY_MESSAGE_CONNECTED as error code.
 *
 * Note, that isakmp routines automatically also
 * call SshIkeIpsecSAHandler associated with
 * SshIkeServerContext when any new ipsec sa is
 * created, so you can set notify callback to
 * NULL, or use it as extra notification that this
 * specific negotiation is now finished. Keying
 * material etc are given only to
 * SshIkeIpsecSAHandler.                                        shade{1.0} */
SshIkeErrorCode ssh_ike_connect_ipsec(SshIkeServerContext context,
                                      SshIkeNegotiation *negotiation_out,
                                      SshIkeNegotiation isakmp_sa_negotiation,
                                      const unsigned char *remote_name,
                                      const unsigned char *remote_port,
                                      SshIkePayloadID local_id,
                                      SshIkePayloadID remote_id,
                                      int number_of_sa_proposals,
                                      SshIkePayloadSA *sa_proposals,
                                      void *policy_manager_data,
                                      SshUInt32 connect_flags,
                                      SshIkeNotify notify_callback,
                                      void *notify_callback_context)
{
  SshIkeSA sa;
  SshIkeNegotiation negotiation;
  int i, j, k, l;
  int group_descriptor;
  Boolean first_attrs;
  char id_txt[255];
  const unsigned char *empty;
  unsigned char n[64], p[6];

  *negotiation_out = NULL;
  if (remote_port == NULL)
    remote_port = context->isakmp_context->default_port;

  empty = ssh_custr("");
  SSH_DEBUG(5, ("Start, remote_name = %s:%s, flags = %08lx",
                (remote_name == NULL ? empty : remote_name),
                remote_port, (unsigned long) connect_flags));

  if ((local_id == NULL && remote_id != NULL) ||
      (local_id != NULL && remote_id == NULL))
    {
      SSH_DEBUG(3, ("Must give both local_id and remote_id or "
                    "neither one in ssh_ike_connect_ipsec"));
      return SSH_IKE_ERROR_INVALID_ARGUMENTS;
    }

  /* Find isakmp sa */
  sa = ike_sa_find_ip_port(context->isakmp_context,
                           isakmp_sa_negotiation,
                           NULL, NULL,
                           remote_name, remote_port);
  if (sa == NULL)
    return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND;
  if (!sa->phase_1_done)
    return SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS;

  if (remote_name == NULL)
    {
      remote_name = sa->isakmp_negotiation->ike_pm_info->remote_ip;
      remote_port = sa->isakmp_negotiation->ike_pm_info->remote_port;
    }

  negotiation = ike_alloc_negotiation(sa);
  if (negotiation == NULL)
    return SSH_IKE_ERROR_OUT_OF_MEMORY;

  SSH_DEBUG(5, ("SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                negotiation->negotiation_index));

  if (!ike_init_qm_negotiation(negotiation,
                               sa->isakmp_negotiation->ike_pm_info,
                               ike_ip_string(context->ip_address,
                                             n, sizeof(n)),
                               ike_port_string(context->normal_local_port,
                                          p, sizeof(p)),
                               remote_name, remote_port,
                               SSH_IKE_XCHG_TYPE_QM,
                               TRUE,
                               ike_random_message_id(sa, context),
                               (connect_flags &
                                SSH_IKE_FLAGS_USE_EXTENDED_TIMERS)
                               != 0))
    goto out_of_memory_error;

  negotiation->ed->notify_callback = notify_callback;
  negotiation->ed->notify_callback_context = notify_callback_context;
  if ((connect_flags & 0xffff) == SSH_IKE_FLAGS_USE_DEFAULTS)
    negotiation->ed->compat_flags =
      context->isakmp_context->default_compat_flags;
  else
    negotiation->ed->compat_flags = connect_flags & 0xffff;
  negotiation->qm_ed->connect_flags = connect_flags;
  negotiation->qm_ed->number_of_sas = number_of_sa_proposals;
  negotiation->ed->auth_method_type = SSH_IKE_AUTH_METHOD_PHASE_1;
  negotiation->ed->current_state = SSH_IKE_ST_START_QM_I;

  *negotiation_out = negotiation;

  group_descriptor = 0;
  first_attrs = TRUE;
  /* Find group descriptor and check that all sa/proposals/transforms have
     same group number */
  SSH_IKE_DEBUG(9, negotiation, ("Number of SA proposals = %d",
                                 number_of_sa_proposals));
  for (i = 0; i < number_of_sa_proposals; i++)
    {
      SSH_IKE_DEBUG(9, negotiation, ("SA[%d]: Number of proposals = %d",
                                     i, sa_proposals[i]->number_of_proposals));
      for (j = 0; j < sa_proposals[i]->number_of_proposals; j++)
        {
          SSH_IKE_DEBUG(9, negotiation,
                        ("SA[%d][%d]: Number of protocols = %d",
                         i, j, sa_proposals[i]->proposals[j].
                         number_of_protocols));
          for (k = 0;
               k < sa_proposals[i]->proposals[j].number_of_protocols;
               k++)
            {
              SSH_IKE_DEBUG(9, negotiation,
                            ("SA[%d][%d][%d]: Number of transforms = %d",
                             i, j, k, sa_proposals[i]->proposals[j].
                             protocols[k].number_of_transforms));
              if (sa_proposals[i]->proposals[j].protocols[k].protocol_id !=
                  SSH_IKE_PROTOCOL_IPSEC_AH &&
                  sa_proposals[i]->proposals[j].protocols[k].protocol_id !=
                  SSH_IKE_PROTOCOL_IPSEC_ESP &&
                  sa_proposals[i]->proposals[j].protocols[k].protocol_id !=
                  SSH_IKE_PROTOCOL_IPCOMP)
                continue;
              for (l = 0;
                  l < sa_proposals[i]->proposals[j].
                    protocols[k].number_of_transforms;
                  l++)
                {
                  struct SshIkeIpsecAttributesRec attrs;

                  ssh_ike_clear_ipsec_attrs(&attrs);
                  SSH_IKE_DEBUG(9, negotiation,
                                ("SA[%d][%d][%d][%d]: %s protocol",
                                 i, j, k, l,
                                 (sa_proposals[i]->proposals[j].
                                  protocols[k].protocol_id ==
                                  SSH_IKE_PROTOCOL_IPSEC_ESP ? "ESP" :
                                  ((sa_proposals[i]->proposals[j].
                                    protocols[k].protocol_id ==
                                    SSH_IKE_PROTOCOL_IPSEC_AH ? "AH" :
                                    (sa_proposals[i]->proposals[j].
                                     protocols[k].protocol_id ==
                                     SSH_IKE_PROTOCOL_IPCOMP ? "IPCOMP" :
                                     "Unknown"))))));
                  if (ssh_ike_read_ipsec_attrs(negotiation,
                                               &(sa_proposals[i]->proposals[j].
                                                 protocols[k].transforms[l]),
                                               &attrs))
                    {
                      /* Check the same PFS group is used for all non-IPcomp
                         protocols. Do not enforce the IPcomp protocols
                         have a PFS group, but if they do it must be the
                         same as the group the other protocols use. */
                      if ((sa_proposals[i]->proposals[j].protocols[k].
                           protocol_id != SSH_IKE_PROTOCOL_IPCOMP) ||
                          attrs.group_desc != 0)
                        {
                          if (first_attrs)
                            {
                              first_attrs = FALSE;
                              group_descriptor = attrs.group_desc;
                            }
                          if (attrs.group_desc != group_descriptor)
                            {
                              SSH_IKE_DEBUG(3, negotiation,
                                            ("Proposal contained several "
                                             "different groups, %d != %d",
                                             attrs.group_desc,
                                             group_descriptor));
                              goto invalid_arg_error;
                            }
                        }
                    }
                  else
                    {
                      SSH_IKE_DEBUG(3, negotiation,
                                    ("Proposal contained unsupported values"));
                      goto invalid_arg_error;
                    }
                }
            }
        }
    }

  negotiation->qm_ed->group = ike_find_group(sa, group_descriptor);
  if (negotiation->qm_ed->group == NULL &&
      connect_flags & SSH_IKE_IPSEC_FLAGS_WANT_PFS)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("No group defined, and the connect flags require PFS"));
      goto invalid_arg_error;
    }

  negotiation->qm_ed->local_sa_proposals = sa_proposals;
  negotiation->qm_pm_info->local_i_id = local_id;
  negotiation->qm_pm_info->remote_i_id = remote_id;
  negotiation->qm_pm_info->policy_manager_data = policy_manager_data;

  if (local_id)
    {
      ssh_ike_id_to_string(id_txt, sizeof(id_txt), local_id);
      ssh_free(negotiation->qm_pm_info->local_i_id_txt);
      negotiation->qm_pm_info->local_i_id_txt = ssh_strdup(id_txt);
    }

  if (remote_id)
    {
      ssh_ike_id_to_string(id_txt, sizeof(id_txt), remote_id);
      ssh_free(negotiation->qm_pm_info->remote_i_id_txt);
      negotiation->qm_pm_info->remote_i_id_txt = ssh_strdup(id_txt);
    }
  if (negotiation->qm_pm_info->local_i_id_txt == NULL ||
      negotiation->qm_pm_info->remote_i_id_txt == NULL)
    goto out_of_memory_error;

  SSH_IKE_DEBUG(6, negotiation, ("Start ipsec sa negotiation"));
  ike_debug_exchange_begin(negotiation);

  if (ike_first_step(negotiation))
    return SSH_IKE_ERROR_OK;

  /* local_sa_proposal, local_i_id, remote_i_id, and policy_manager_data
     are already freed here, return NULL negotiation_out */
  *negotiation_out = NULL;
  return SSH_IKE_ERROR_OK;
invalid_arg_error:
  SSH_DEBUG(7, ("Error invalid arguments, do not send notify"));
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
  ike_delete_negotiation(negotiation);
  *negotiation_out = NULL;
  return SSH_IKE_ERROR_INVALID_ARGUMENTS;
out_of_memory_error:
  SSH_DEBUG(7, ("Out of memory, do not send notify"));
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
  ike_delete_negotiation(negotiation);
  *negotiation_out = NULL;
  return SSH_IKE_ERROR_OUT_OF_MEMORY;
}


/*                                                              shade{0.9}
 * Create new group with some other host. Returns
 * error code if error occurs when sending first
 * packet, and does NOT call notify callback, or
 * allocate anything. Otherwise return allocated
 * SshIkeNegotiation structure in negotiation
 * parameter that can be used to clear state
 * later. If there is no Isakmp SA already
 * negotiated with other end this function will
 * return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND and
 * does not do anything. If the error occurs when sending
 * the first packet but after it has already
 * changed the data given to it, it will call the
 * callback, free the data, return
 * SSH_IKE_ERROR_OK, but set returned negotiation
 * pointer to NULL.
 *
 * If error occurs later the error_callback
 * function is called and context is added to
 * freelist (it will be automatically freed later
 * when retransmit timeout is expired, and other
 * end cannot send more packets).
 *
 * If isakmp_sa_negotiation is given then it is
 * assumed to be ISAKMP SA negotiation pointer
 * returned by previous ssh_ike_connect call. If
 * that pointer is no longer valid
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
 * returned.
 *
 * If isakmp_sa_negotiation is NULL, then the
 * remote_name, and remote_port are used to find
 * matching isakmp SA.
 *
 * The sa_proposals contains our proposals. It is
 * freed by isakmp code after they are not needed
 * anymore.
 *
 * The sa proposal sa_attributes are assumed to be
 * allocated with one malloc so freeing
 * sa_attributes table will free both the tables
 * and the data. If the spi is given it is used
 * (the data is freed). If spi pointers are NULL
 * then they are filled with either zeros or our
 * initiator cookie, depending on the zero_spi
 * parameter to ssh_isakmp_init.
 *
 * When new group negotiation is done, the
 * notify_callback will be called with value
 * ISAKMP_NOTIFY_MESSAGE_CONNECTED as error code.
 *
 * The policy_manager_data pointer is stored in the
 * policy manager information structure in the
 * policy_manager_data field.
 *
 * Flags can be any combination of the compat
 * flags (SSH_IKE_FLAGS_*) or'ed together.                      shade{1.0}
 */
SshIkeErrorCode ssh_ike_connect_ngm(SshIkeServerContext context,
                                    SshIkeNegotiation *negotiation_out,
                                    SshIkeNegotiation isakmp_sa_negotiation,
                                    const unsigned char *remote_name,
                                    const unsigned char *remote_port,
                                    SshIkePayloadSA sa_proposal,
                                    void *policy_manager_data,
                                    SshUInt32 connect_flags,
                                    SshIkeNotify notify_callback,
                                    void *notify_callback_context)
{
  SshIkeSA sa;
  SshIkeNegotiation negotiation;
  const unsigned char *empty;
  unsigned char n[64], p[6];

  *negotiation_out = NULL;
  if (remote_port == NULL)
    remote_port = context->isakmp_context->default_port;

  empty = ssh_custr("");
  SSH_DEBUG(5, ("Start, remote_name = %s:%s, flags = %08lx",
                (remote_name == NULL ? empty : remote_name),
                remote_port, (unsigned long) connect_flags));

  /* Find isakmp sa */
  sa = ike_sa_find_ip_port(context->isakmp_context,
                           isakmp_sa_negotiation,
                           NULL, NULL,
                           remote_name, remote_port);
  if (sa == NULL)
    return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND;
  if (!sa->phase_1_done)
    return SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS;

  if (remote_name == NULL)
    {
      remote_name = sa->isakmp_negotiation->ike_pm_info->remote_ip;
      remote_port = sa->isakmp_negotiation->ike_pm_info->remote_port;
    }

  negotiation = ike_alloc_negotiation(sa);
  if (negotiation == NULL)
    return SSH_IKE_ERROR_OUT_OF_MEMORY;

  SSH_DEBUG(5, ("SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                negotiation->negotiation_index));

  if (!ike_init_ngm_negotiation(negotiation,
                                sa->isakmp_negotiation->ike_pm_info,
                                ike_ip_string(context->ip_address,
                                              n, sizeof(n)),
                                ike_port_string(context->normal_local_port,
                                                p, sizeof(p)),
                                remote_name, remote_port,
                                SSH_IKE_MAJOR_VERSION, SSH_IKE_MINOR_VERSION,
                                SSH_IKE_XCHG_TYPE_NGM,
                                TRUE, ike_random_message_id(sa, context),
                                (connect_flags &
                                 SSH_IKE_FLAGS_USE_EXTENDED_TIMERS)
                                != 0))
    {
      negotiation->notification_state =
        SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
      ike_delete_negotiation(negotiation);
      *negotiation_out = NULL;
      return SSH_IKE_ERROR_OUT_OF_MEMORY;
    }

  negotiation->ed->notify_callback = notify_callback;
  negotiation->ed->notify_callback_context = notify_callback_context;
  if ((connect_flags & 0xffff) == SSH_IKE_FLAGS_USE_DEFAULTS)
    negotiation->ed->compat_flags =
      context->isakmp_context->default_compat_flags;
  else
    negotiation->ed->compat_flags = connect_flags & 0xffff;
  negotiation->ngm_ed->connect_flags = connect_flags;
  negotiation->ngm_ed->local_sa_proposal = sa_proposal;
  ssh_ike_clear_grp_attrs(&(negotiation->ngm_ed->attributes));

  negotiation->ngm_pm_info->policy_manager_data = policy_manager_data;

  negotiation->ed->auth_method_type = SSH_IKE_AUTH_METHOD_PHASE_1;
  negotiation->ed->current_state = SSH_IKE_ST_START_NGM_I;

  *negotiation_out = negotiation;

  SSH_IKE_DEBUG(6, negotiation, ("Start ngm sa negotiation"));
  ike_debug_exchange_begin(negotiation);

  if (ike_first_step(negotiation))
    return SSH_IKE_ERROR_OK;
  /* local_sa_proposal, and policy_manager_data are already freed here,
     return NULL negotiation_out */
  *negotiation_out = NULL;
  return SSH_IKE_ERROR_OK;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE

/*                                                              shade{0.9}
 * Normal notify callback wrapper that will
 * convert it to cfg callback.                                  shade{1.0}
 */
void ike_cfg_notify(SshIkeNotifyMessageType error,
                    SshIkeNegotiation negotiation,
                    void *callback_context)
{
  if (negotiation->cfg_ed->notify_callback)
    {
      if (error != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
        (*negotiation->cfg_ed->notify_callback)(negotiation,
                                                negotiation->cfg_pm_info,
                                                error, 0, NULL,
                                                negotiation->cfg_ed->
                                                notify_callback_context);
      else
        (*negotiation->cfg_ed->
         notify_callback)(negotiation,
                          negotiation->cfg_pm_info,
                          SSH_IKE_NOTIFY_MESSAGE_CONNECTED,
                          negotiation->cfg_ed->
                          number_of_remote_attr_payloads,
                          negotiation->cfg_ed->
                          remote_attrs,
                          negotiation->cfg_ed->
                          notify_callback_context);
    }
  return;
}

/*                                                              shade{0.9}
 * Start configuration exchange with some other
 * host. Returns error code if error occurs when
 * sending first packet, and does NOT call notify
 * callback, or allocate anything. Otherwise
 * return allocated SshIkeNegotiation structure in
 * negotiation parameter that can be used to clear
 * state later. If there is no isakmp SA already
 * negotiated and SSH_IKE_CFG_FLAGS_WANT_ISAKMP_SA
 * is given then this function will return
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND and does not
 * do anything. If the error occurs when sending
 * the first packet but after it has already
 * changed the data given to it, it will call the
 * callback, free the data, return
 * SSH_IKE_ERROR_OK, but set returned negotiation
 * pointer to NULL.
 *
 * If error occurs later the error_callback
 * function is called and context is added to
 * freelist (it will be automatically freed later
 * when retransmit timeout is expired, and other
 * end cannot send more packets).
 *
 * If isakmp_sa_negotiation is given then it is
 * assumed to be ISAKMP SA negotiation pointer
 * returned by previous ssh_ike_connect call. If
 * that pointer is no longer valid
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
 * returned.
 *
 * If isakmp_sa_negotiation is NULL, then the
 * remote_name, and remote_port are used to find
 * matching isakmp SA.
 *
 * The attributes contains attribute payload to
 * send to other end. It is freed by isakmp code
 * after they are not needed anymore.
 *
 * The attribute table is assumed to be allocated
 * with one malloc so freeing that table will free
 * both the tables and the data.
 *
 * When configuration mode negotiation is done,
 * the notify_callback will be called with
 * returned attributes, or with error code if the
 * negotiation failed.
 *
 * The policy_manager_data pointer is stored in the
 * policy manager information structure in the
 * policy_manager_data field.
 *
 * Flags can be any combination of the compat
 * flags (SSH_IKE_FLAGS_*) or'ed together. shade{1.0} */
SshIkeErrorCode ssh_ike_connect_cfg(SshIkeServerContext context,
                                    SshIkeNegotiation *negotiation_out,
                                    SshIkeNegotiation isakmp_sa_negotiation,
                                    const unsigned char *remote_name,
                                    const unsigned char *remote_port,
                                    int number_of_attr_payloads,
                                    SshIkePayloadAttr *attributes,
                                    void *policy_manager_data,
                                    SshUInt32 connect_flags,
                                    SshIkeCfgNotify notify_callback,
                                    void *notify_callback_context)
{
  SshIkeSA sa;
  SshIkeNegotiation negotiation;
  Boolean sa_allocated = FALSE;
  const unsigned char *empty;
  unsigned char n[64], p[6];

  *negotiation_out = NULL;
  if (remote_port == NULL)
    remote_port = context->isakmp_context->default_port;

  empty = ssh_custr("");
  SSH_DEBUG(5, ("Start, remote_name = %s:%s, flags = %08lx",
                (remote_name == NULL ? empty : remote_name),
                remote_port, (unsigned long) connect_flags));

  /* Find isakmp sa */
  sa = ike_sa_find_ip_port(context->isakmp_context,
                           isakmp_sa_negotiation,
                           NULL, NULL,
                           remote_name, remote_port);
  if (sa == NULL && isakmp_sa_negotiation != NULL)
    return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND;
  if (connect_flags & SSH_IKE_CFG_FLAGS_WANT_ISAKMP_SA && sa == NULL)
    {
      SSH_DEBUG(3, ("No isakmp sa found and connect flags require it"));
      return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND;
    }
  if (connect_flags & SSH_IKE_CFG_FLAGS_WANT_ISAKMP_SA && !sa->phase_1_done)
    {
      SSH_DEBUG(3, ("Isakmp sa in progress and connect flags require it"));
      return SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS;
    }

  /* If no sa found, create fake SA */
  if (sa == NULL)
    {
      sa = ike_sa_allocate_half(context, remote_name, remote_port, NULL);
      if (sa == NULL)
        return SSH_IKE_ERROR_OUT_OF_MEMORY;

      if (!ike_init_isakmp_sa(sa,
                              ike_ip_string(context->ip_address, n, sizeof(n)),
                              ike_port_string(context->normal_local_port,
                                              p, sizeof(p)),
                              remote_name, remote_port,
                              SSH_IKE_MAJOR_VERSION, SSH_IKE_MINOR_VERSION,
                              SSH_IKE_XCHG_TYPE_IP, TRUE,
                              (connect_flags &
                               SSH_IKE_FLAGS_USE_EXTENDED_TIMERS)
                              != 0))
        {
          ike_sa_delete(context->isakmp_context, sa);
          ssh_free(sa);
          return SSH_IKE_ERROR_OUT_OF_MEMORY;
        }
      sa_allocated = TRUE;

      /* Mark it so that we never send any notifications for this */
      sa->isakmp_negotiation->notification_state =
        SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
    }

  if (remote_name == NULL)
    {
      remote_name = sa->isakmp_negotiation->ike_pm_info->remote_ip;
      remote_port = sa->isakmp_negotiation->ike_pm_info->remote_port;
    }

  negotiation = ike_alloc_negotiation(sa);
  if (negotiation == NULL)
    {
      if (sa_allocated)
        ike_delete_negotiation(sa->isakmp_negotiation);
      return SSH_IKE_ERROR_OUT_OF_MEMORY;
    }

  SSH_DEBUG(5, ("SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                negotiation->negotiation_index));

  if (!ike_init_cfg_negotiation(negotiation,
                                sa->isakmp_negotiation->ike_pm_info,
                                ike_ip_string(context->ip_address,
                                              n, sizeof(n)),
                                ike_port_string(context->normal_local_port,
                                                p, sizeof(p)),
                                remote_name, remote_port,
                                SSH_IKE_MAJOR_VERSION, SSH_IKE_MINOR_VERSION,
                                SSH_IKE_XCHG_TYPE_CFG,
                                TRUE, ike_random_message_id(sa, context),
                                (connect_flags &
                                 SSH_IKE_FLAGS_USE_EXTENDED_TIMERS)
                                != 0))
    {
      ike_delete_negotiation(negotiation);
      if (sa_allocated)
        ike_delete_negotiation(sa->isakmp_negotiation);
      return SSH_IKE_ERROR_OUT_OF_MEMORY;
    }

  if ((connect_flags & 0xffff) == SSH_IKE_FLAGS_USE_DEFAULTS)
    negotiation->ed->compat_flags =
      context->isakmp_context->default_compat_flags;
  else
    negotiation->ed->compat_flags = connect_flags & 0xffff;
  negotiation->ed->notify_callback = ike_cfg_notify;
  negotiation->ed->notify_callback_context = notify_callback_context;
  negotiation->cfg_ed->notify_callback = notify_callback;
  negotiation->cfg_ed->notify_callback_context = notify_callback_context;
  negotiation->cfg_ed->connect_flags = connect_flags;
  negotiation->cfg_ed->number_of_local_attr_payloads = number_of_attr_payloads;
  negotiation->cfg_ed->local_attrs = attributes;
  negotiation->cfg_pm_info->policy_manager_data = policy_manager_data;

  if (sa->phase_1_done)
    negotiation->ed->auth_method_type = SSH_IKE_AUTH_METHOD_PHASE_1;
  else
    negotiation->ed->auth_method_type = SSH_IKE_AUTH_METHOD_ANY;
  negotiation->ed->current_state = SSH_IKE_ST_START_CFG_I;

  *negotiation_out = negotiation;

  SSH_IKE_DEBUG(6, negotiation, ("Start cfg sa negotiation"));
  ike_debug_exchange_begin(negotiation);

  if (ike_first_step(negotiation))
    return SSH_IKE_ERROR_OK;

  /* local_attrs, and policy_manager_data are already freed here, return NULL
     negotiation_out */
  if (sa_allocated)
    ike_delete_negotiation(sa->isakmp_negotiation);

  *negotiation_out = NULL;
  return SSH_IKE_ERROR_OK;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/*                                                              shade{0.9}
 * Send notification to other end. Returns error
 * code if error occurs when sending message. If
 * there is a isakmp sa established, use that to
 * send the message, otherwise the message is sent
 * unauthenticated.
 *
 * Flags can be any combination of the compat
 * flags (SSH_IKE_FLAGS_*) or'ed together. If the
 * connect_flags has
 * SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA set then
 * notify is always sent using the existing isakmp
 * sa.
 *
 * If no isakmp sa is established and
 * connect_flags is
 * SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA then
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND is returned.
 *
 * If isakmp_sa_negotiation is given then it is
 * assumed to be ISAKMP SA negotiation pointer
 * returned by previous ssh_ike_connect call. If
 * that pointer is no longer valid
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
 * returned.
 *
 * If isakmp_sa_negotiation is NULL, then the
 * remote_name, and remote_port are used to find
 * matching isakmp SA.
 *
 * The doi, protocol_id, spi_size, spi,
 * notify_message_type, notification_data and
 * notification_data_size are used to create
 * notification message.                                       shade{1.0}
 */
SshIkeErrorCode ssh_ike_connect_notify(SshIkeServerContext context,
                                       SshIkeNegotiation isakmp_sa_negotiation,
                                       const unsigned char *remote_name,
                                       const unsigned char *remote_port,
                                       SshUInt32 connect_flags,
                                       SshIkeDOI doi,
                                       SshIkeProtocolIdentifiers protocol_id,
                                       unsigned char *spi,
                                       size_t spi_size,
                                       SshIkeNotifyMessageType
                                       notify_message_type,
                                       unsigned char *notification_data,
                                       size_t notification_data_size)
{
  SshIkeSA sa;
  SshIkeNotifyMessageType ret;
  SshIkePacket isakmp_packet_out;
  SshBuffer buffer;
  SshIkeNegotiation negotiation;
  SshIkePayload pl;
  Boolean sa_allocated = FALSE;
  const unsigned char *empty;

  if (remote_port == NULL)
    remote_port = context->isakmp_context->default_port;

  empty = ssh_custr("");
  SSH_DEBUG(5, ("Start, remote_name = %s:%s, flags = %08lx",
                (remote_name == NULL ? empty : remote_name),
                remote_port, (unsigned long) connect_flags));

  /* Find isakmp sa */
  sa = ike_sa_find_ip_port(context->isakmp_context,
                           isakmp_sa_negotiation,
                           NULL, NULL,
                           remote_name, remote_port);
  if (sa == NULL && isakmp_sa_negotiation != NULL)
    return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND;
  if (connect_flags & SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA && sa == NULL)
    {
      SSH_DEBUG(3, ("No isakmp sa found and connect flags require it"));
      return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND;
    }
  if (connect_flags & SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA && !sa->phase_1_done)
    {
      SSH_DEBUG(3, ("Isakmp sa in progress and connect flags require it"));
      return SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS;
    }

  /* If no sa found, create fake SA */
  if (sa == NULL)
    {
      unsigned char n[64], p[6];

      sa = ike_sa_allocate_half(context, remote_name, remote_port, NULL);
      if (sa == NULL)
        return SSH_IKE_ERROR_OUT_OF_MEMORY;
      if (!ike_init_isakmp_sa(sa,
                              ike_ip_string(context->ip_address, n, sizeof(n)),
                              ike_port_string(context->normal_local_port,
                                              p, sizeof(p)),
                              remote_name, remote_port,
                              SSH_IKE_MAJOR_VERSION, SSH_IKE_MINOR_VERSION,
                              SSH_IKE_XCHG_TYPE_IP, TRUE,
                              (connect_flags &
                               SSH_IKE_FLAGS_USE_EXTENDED_TIMERS)
                              != 0))
        {
          ike_sa_delete(context->isakmp_context, sa);
          ssh_free(sa);
          return SSH_IKE_ERROR_OUT_OF_MEMORY;
        }
      sa_allocated = TRUE;

      /* Mark it so that we never send any notifications for this */
      sa->isakmp_negotiation->notification_state =
        SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
    }

  if (!ike_init_info_exchange(context, sa, &isakmp_packet_out,
                              &negotiation, &pl))
    {
      if (sa_allocated)
        ike_delete_negotiation(sa->isakmp_negotiation);
      return SSH_IKE_ERROR_OUT_OF_MEMORY;
    }

  SSH_DEBUG(5, ("SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                negotiation->negotiation_index));

  SSH_IKE_DEBUG(6, negotiation, ("Start notify negotiation"));

  /* Add n payload */
  isakmp_packet_out->first_n_payload = pl;
  pl->type = SSH_IKE_PAYLOAD_TYPE_N;
  pl->pl.n.doi = doi;
  pl->pl.n.protocol_id = protocol_id;
  pl->pl.n.spi_size = spi_size;
  pl->pl.n.notify_message_type = notify_message_type;
  pl->pl.n.spi = spi;
  pl->pl.n.notification_data_size = notification_data_size;
  pl->pl.n.notification_data = notification_data;

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    {
      ike_delete_negotiation(negotiation);
      if (sa_allocated)
        ike_delete_negotiation(sa->isakmp_negotiation);
      return SSH_IKE_ERROR_OUT_OF_MEMORY;
    }

  /* Encode response packet */
  ret = ike_encode_packet(context->isakmp_context,
                          isakmp_packet_out, sa, negotiation,
                          buffer);
  if (ret != 0)
    {
      SSH_DEBUG(3, ("ssh_isakmp_encode_packet failed : %d", ret));
      ike_delete_negotiation(negotiation);
      ssh_buffer_free(buffer);
      if (sa_allocated)
        ike_delete_negotiation(sa->isakmp_negotiation);
      return SSH_IKE_ERROR_INTERNAL;
    }
  SSH_DEBUG(6, ("Sending notification to %s:%s", remote_name, remote_port));

  ret = ike_send_packet(negotiation,
                        ssh_buffer_ptr(buffer),
                        ssh_buffer_len(buffer), FALSE, TRUE);

  /* Free packet */
  ike_free_packet(isakmp_packet_out, connect_flags);
  ssh_buffer_free(buffer);

  /* Send connected notification. */
  ike_call_callbacks(negotiation, SSH_IKE_NOTIFY_MESSAGE_CONNECTED);

  /* Delete info negotiation */
  ike_delete_negotiation(negotiation);

  if (sa_allocated)
    ike_delete_negotiation(sa->isakmp_negotiation);
  if (ret == 0)
    return SSH_IKE_ERROR_OK;
  else
    return SSH_IKE_ERROR_OUT_OF_MEMORY;
}

/*                                                              shade{0.9}
 * Create delete notify which can be send to the
 * other end. Returns error code if error occurs
 * when creating message. If there is a isakmp sa
 * established, use that to encrypt the message,
 * otherwise the message is created
 * unauthenticated.
 *
 * Flags can be any combination of the compat
 * flags (SSH_IKE_FLAGS_*) or'ed together. If the
 * connect_flags has
 * SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA set then
 * notify is always created using the existing isakmp
 * sa.
 *
 * If no isakmp sa is established and
 * connect_flags is
 * SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA then
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND is returned.
 *
 * If isakmp_sa_negotiation is given then it is
 * assumed to be ISAKMP SA negotiation pointer
 * returned by previous ssh_ike_connect call. If
 * that pointer is no longer valid
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
 * returned.
 *
 * If isakmp_sa_negotiation is NULL, then the
 * remote_name, and remote_port are used to find
 * matching isakmp SA.
 *
 * The doi, protocol_id, spi_size, number_of_spis,
 * and spis are used to create delete message.                  shade{1.0}
 */

SshIkeErrorCode
ssh_ike_create_delete_internal(SshBuffer buffer,
                               SshIkeServerContext context,
                               SshIkeNegotiation isakmp_sa_negotiation,
                               const unsigned char *remote_name,
                               const unsigned char *remote_port,
                               SshUInt32 connect_flags,
                               SshIkeDOI doi,
                               SshIkeProtocolIdentifiers protocol_id,
                               int number_of_spis,
                               unsigned char **spis,
                               size_t spi_size,
                               SshIkeNegotiation *neg_ret,
                               SshIkeSA *sa_ret)
{
  SshIkeSA sa;
  SshIkeNotifyMessageType ret;
  SshIkePacket isakmp_packet_out;
  SshIkeNegotiation negotiation;
  SshIkePayload pl;
  Boolean sa_allocated;
  const unsigned char *empty;
  unsigned char n[64], p[6];

  sa_allocated = FALSE;
  *neg_ret = NULL;
  *sa_ret = NULL;

  if (remote_port == NULL)
    remote_port = context->isakmp_context->default_port;

  empty = ssh_custr("");
  SSH_DEBUG(5, ("Start, remote_name = %s:%s, flags = %08lx",
                (remote_name == NULL ? empty : remote_name),
                remote_port, (unsigned long) connect_flags));

  /* Find isakmp sa */
  sa = ike_sa_find_ip_port(context->isakmp_context,
                           isakmp_sa_negotiation,
                           NULL, NULL,
                           remote_name, remote_port);

  if (sa == NULL && isakmp_sa_negotiation != NULL)
    return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND;
  if (connect_flags & SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA && sa == NULL)
    {
      SSH_DEBUG(3, ("No isakmp sa found and connect flags require it"));
      return SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND;
    }
  if (connect_flags & SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA && !sa->phase_1_done)
    {
      SSH_DEBUG(3, ("Isakmp sa in progress and connect flags require it"));
      return SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS;
    }

  /* If no sa found, create fake SA */
  if (sa == NULL)
    {
      sa = ike_sa_allocate_half(context, remote_name, remote_port, NULL);
      if (sa == NULL)
        return SSH_IKE_ERROR_OUT_OF_MEMORY;
      if (!ike_init_isakmp_sa(sa,
                              ike_ip_string(context->ip_address, n, sizeof(n)),
                              ike_port_string(context->normal_local_port,
                                              p, sizeof(p)),
                              remote_name, remote_port,
                              SSH_IKE_MAJOR_VERSION, SSH_IKE_MINOR_VERSION,
                              SSH_IKE_XCHG_TYPE_IP, TRUE,
                              (connect_flags &
                               SSH_IKE_FLAGS_USE_EXTENDED_TIMERS)
                              != 0))
        {
          ike_sa_delete(context->isakmp_context, sa);
          ssh_free(sa);
          return SSH_IKE_ERROR_OUT_OF_MEMORY;
        }
      sa_allocated = TRUE;

      /* Mark it so that we never send any notifications for this */
      sa->isakmp_negotiation->notification_state =
        SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT;
    }

  if (!ike_init_info_exchange(context, sa, &isakmp_packet_out,
                              &negotiation, &pl))
    {
      if (sa_allocated)
        ike_delete_negotiation(sa->isakmp_negotiation);
      return SSH_IKE_ERROR_OUT_OF_MEMORY;
    }

  /* Remove the mark, so that we do get notification for this */
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_NOT_SENT;

  SSH_DEBUG(5, ("SA = { %08lx %08lx - %08lx %08lx}, nego = %d",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                negotiation->negotiation_index));

  SSH_IKE_DEBUG(6, negotiation, ("Start delete negotiation"));

  /* Add d payload */
  isakmp_packet_out->first_d_payload = pl;
  pl->type = SSH_IKE_PAYLOAD_TYPE_D;
  pl->pl.d.doi = doi;
  pl->pl.d.protocol_id = protocol_id;
  pl->pl.d.spi_size = spi_size;
  pl->pl.d.number_of_spis = number_of_spis;
  pl->pl.d.spis = ssh_memdup(spis, sizeof(unsigned char *) * number_of_spis);
  if (pl->pl.d.spis == NULL)
    {
      ike_delete_negotiation(negotiation);
      if (sa_allocated)
        ike_delete_negotiation(sa->isakmp_negotiation);
      ike_free_packet(isakmp_packet_out, connect_flags);
      return SSH_IKE_ERROR_OUT_OF_MEMORY;
    }

  /* Encode response packet */
  ret = ike_encode_packet(context->isakmp_context,
                          isakmp_packet_out, sa, negotiation,
                          buffer);
  if (ret != 0)
    {
      SSH_DEBUG(3, ("ssh_isakmp_encode_packet failed : %d", ret));
      ike_delete_negotiation(negotiation);
      if (sa_allocated)
        ike_delete_negotiation(sa->isakmp_negotiation);
      return SSH_IKE_ERROR_INTERNAL;
    }

  *neg_ret = negotiation;
  if (sa_allocated)
    *sa_ret = sa;

  /* Free packet */
  ike_free_packet(isakmp_packet_out, connect_flags);
  return SSH_IKE_ERROR_OK;
}

/*                                                              shade{0.9}
 * Send delete notify to other end. Returns error
 * code if error occurs when sending message. If
 * there is a isakmp sa established, use that to
 * send the message, otherwise the message is sent
 * unauthenticated.
 *
 * Flags can be any combination of the compat
 * flags (SSH_IKE_FLAGS_*) or'ed together. If the
 * connect_flags has
 * SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA set then
 * notify is always sent using the existing isakmp
 * sa.
 *
 * If no isakmp sa is established and
 * connect_flags is
 * SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA then
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND is returned.
 *
 * If isakmp_sa_negotiation is given then it is
 * assumed to be ISAKMP SA negotiation pointer
 * returned by previous ssh_ike_connect call. If
 * that pointer is no longer valid
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
 * returned.
 *
 * If isakmp_sa_negotiation is NULL, then the
 * remote_name, and remote_port are used to find
 * matching isakmp SA.
 *
 * The doi, protocol_id, spi_size, number_of_spis,
 * and spis are used to create delete message.                  shade{1.0}
 */
SshIkeErrorCode ssh_ike_connect_delete(SshIkeServerContext context,
                                       SshIkeNegotiation isakmp_sa_negotiation,
                                       const unsigned char *remote_name,
                                       const unsigned char *remote_port,
                                       SshUInt32 connect_flags,
                                       SshIkeDOI doi,
                                       SshIkeProtocolIdentifiers protocol_id,
                                       int number_of_spis,
                                       unsigned char **spis,
                                       size_t spi_size)
{
  SshIkeNegotiation negotiation;
  SshIkeNotifyMessageType sendret;
  SshIkeErrorCode ret;
  SshBuffer buffer;
  SshIkeSA sa;
  const unsigned char *empty;

  empty = ssh_custr("");
  SSH_DEBUG(5, ("Start, remote_name = %s:%s, flags = %08lx",
                (remote_name == NULL ? empty : remote_name),
                (remote_port == NULL ? context->isakmp_context->default_port :
                 remote_port), (unsigned long) connect_flags));

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    return SSH_IKE_ERROR_OUT_OF_MEMORY;

  ret = ssh_ike_create_delete_internal(buffer, context, isakmp_sa_negotiation,
                                       remote_name, remote_port, connect_flags,
                                       doi, protocol_id, number_of_spis, spis,
                                       spi_size, &negotiation, &sa);
  if (ret != SSH_IKE_ERROR_OK)
    {
      ssh_buffer_free(buffer);
      return ret;
    }

  SSH_DEBUG(6, ("Sending delete to %s:%s", remote_name, remote_port));

  sendret = ike_send_packet(negotiation,
                            ssh_buffer_ptr(buffer),
                            ssh_buffer_len(buffer), FALSE, TRUE);

  ssh_buffer_free(buffer);

  /* Send connected notification. */
  ike_call_callbacks(negotiation, SSH_IKE_NOTIFY_MESSAGE_CONNECTED);

  /* Delete info negotiation */
  ike_delete_negotiation(negotiation);

  if (sa)
    ike_delete_negotiation(sa->isakmp_negotiation);

  if (sendret == 0)
    return SSH_IKE_ERROR_OK;
  else
    return SSH_IKE_ERROR_OUT_OF_MEMORY;
}

/*                                                              shade{0.9}
 * Create delete notify which can be send to the
 * other end. Returns error code if error occurs
 * when creating message. If there is a isakmp sa
 * established, use that to encrypt the message,
 * otherwise the message is created
 * unauthenticated.
 *
 * Flags can be any combination of the compat
 * flags (SSH_IKE_FLAGS_*) or'ed together. If the
 * connect_flags has
 * SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA set then
 * notify is always created using the existing isakmp
 * sa.
 *
 * If no isakmp sa is established and
 * connect_flags is
 * SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA then
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND is returned.
 *
 * If isakmp_sa_negotiation is given then it is
 * assumed to be ISAKMP SA negotiation pointer
 * returned by previous ssh_ike_connect call. If
 * that pointer is no longer valid
 * SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
 * returned.
 *
 * If isakmp_sa_negotiation is NULL, then the
 * remote_name, and remote_port are used to find
 * matching isakmp SA.
 *
 * The doi, protocol_id, spi_size, number_of_spis,
 * and spis are used to create delete message.                  shade{1.0}
 */
SshIkeErrorCode ssh_ike_create_delete(SshBuffer buffer,
                                      SshIkeServerContext context,
                                      SshIkeNegotiation isakmp_sa_negotiation,
                                      const unsigned char *remote_name,
                                      const unsigned char *remote_port,
                                      SshUInt32 connect_flags,
                                      SshIkeDOI doi,
                                      SshIkeProtocolIdentifiers protocol_id,
                                      int number_of_spis,
                                      unsigned char **spis,
                                      size_t spi_size)
{
  SshIkeNegotiation negotiation;
  SshIkeErrorCode ret;
  SshIkeSA sa;
  const unsigned char *empty;

  empty = ssh_custr("");
  SSH_DEBUG(5, ("Start, remote_name = %s:%s, flags = %08lx",
                (remote_name == NULL ? empty : remote_name),
                (remote_port == NULL ? context->isakmp_context->default_port :
                 remote_port), (unsigned long) connect_flags));

  ret = ssh_ike_create_delete_internal(buffer, context, isakmp_sa_negotiation,
                                       remote_name, remote_port, connect_flags,
                                       doi, protocol_id, number_of_spis, spis,
                                       spi_size, &negotiation, &sa);
  if (ret != SSH_IKE_ERROR_OK)
    {
      return ret;
    }

  /* Delete info negotiation */
  ike_delete_negotiation(negotiation);

  if (sa)
    ike_delete_negotiation(sa->isakmp_negotiation);

  return SSH_IKE_ERROR_OK;
}


/*                                                              shade{0.9}
 * Mark negotiation to be deleted. This does not
 * delete the negotiation immediately, but inserts
 * immediate timer to remove the negotiation. This
 * can be safely called anywhere.                               shade{1.0} */
SshIkeErrorCode ssh_ike_abort_negotiation(SshIkeNegotiation negotiation,
                                          SshUInt32 connect_flags)
{
  if (negotiation->negotiation_index == -1)
    {
      /* ISAKMP Sa negotiation, mark it deleted */
      negotiation->sa->lock_flags |= SSH_IKE_ISAKMP_LOCK_FLAG_DELETED;
    }
  ssh_xregister_timeout(0, 0, ike_remove_callback, negotiation);
  return SSH_IKE_ERROR_OK;
}


/*                                                              shade{0.9}
 * Mark ISAKMP SA of given negotiation to be
 * deleted. This does not delete the ISAKMP SA
 * immediately, but inserts immediate timer to
 * remove the negotiation, it also marks the SA
 * so that it will not be selected by
 * ssh_ike_connect_* routines anymore. This
 * can be safely called anywhere. If connect_flags
 * is SSH_IKE_REMOVE_FLAGS_SEND_DELETE then it will
 * send delete notification to remote end.                      shade{1.0} */
SshIkeErrorCode ssh_ike_remove_isakmp_sa(SshIkeNegotiation negotiation,
                                         SshUInt32 connect_flags)
{
  int t, t_usec;
  SshIkeSA sa;

  if (negotiation->ed != NULL &&
      negotiation->ed->current_state == SSH_IKE_ST_DELETED)
    return SSH_IKE_ERROR_OK;

  sa = negotiation->sa;

  t = 0;
  t_usec = 0;

  sa->lock_flags |= SSH_IKE_ISAKMP_LOCK_FLAG_DELETED;

  if (sa->number_of_negotiations != 0
      && !(connect_flags & SSH_IKE_REMOVE_FLAGS_FORCE_DELETE_NOW))
    {
      t = sa->retry_limit * sa->retry_timer_max +
        sa->retry_limit * sa->retry_timer_max_usec
        / 1000000;
      t_usec = (sa->retry_limit * sa->retry_timer_max_usec) % 1000000;
      if (t > sa->expire_timer ||
          (t == sa->expire_timer && t_usec > sa->expire_timer_usec))
        {
          t = sa->expire_timer;
          t_usec = sa->expire_timer_usec;
        }
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Scheduling IKEv1 SA %s after %d sec %d usec",
             (connect_flags & SSH_IKE_REMOVE_FLAGS_SEND_DELETE)
             ? "expiration" : "removal", t, t_usec));

  ssh_xregister_timeout(t, t_usec,
                       ((connect_flags & SSH_IKE_REMOVE_FLAGS_SEND_DELETE)
                        ? ike_expire_callback
                        : ike_remove_callback),
                        sa->isakmp_negotiation);
  return SSH_IKE_ERROR_OK;
}

/*                                                              shade{0.9}
 * Mark ISAKMP SA of given negotiation in given ip
 * address and port to be deleted. This does not
 * delete the ISAKMP SA immediately, but inserts
 * immediate timer to remove the negotiation, it
 * also marks the SA so that it will not be
 * selected by ssh_isakmp_connect_* routines
 * anymore. This can be safely called anywhere. If
 * ip address is NULL then it means all ip
 * addresses, and if port number is NULL then it
 * means all port addresses. If connect_flags
 * is SSH_IKE_REMOVE_FLAGS_SEND_DELETE then it will
 * send delete notification to remote end.                      shade{1.0} */
SshIkeErrorCode
ssh_ike_remove_isakmp_sa_by_address(SshIkeContext context,
                                    const unsigned char *local_name,
                                    const unsigned char *local_port,
                                    const unsigned char *remote_name,
                                    const unsigned char *remote_port,
                                    SshUInt32 connect_flags)
{
  SshIkeSA sa;
  do {
    sa = ike_sa_find_ip_port(context, NULL, local_name, local_port,
                             remote_name, remote_port);
    if (sa == NULL)
      break;

    sa->lock_flags |= SSH_IKE_ISAKMP_LOCK_FLAG_DELETED;

    ssh_xregister_timeout(0, 0,
                         ((connect_flags & SSH_IKE_REMOVE_FLAGS_SEND_DELETE)
                          ? ike_expire_callback
                          : ike_remove_callback),
                         sa->isakmp_negotiation);
  } while (1);
  return SSH_IKE_ERROR_OK;
}

/*                                                              shade{0.9}
 * Delete all other ISAKMP SA's than the given
 * ISAKMP SA connected to the same host. This
 * can be used by the policy code to clear out
 * old ISAKMP SA's when INITIAL CONTACT notification
 * is received. If connect_flags
 * is SSH_IKE_REMOVE_FLAGS_SEND_DELETE then it will
 * send delete notification to remote end.                      shade{1.0} */
SshIkeErrorCode ssh_ike_remove_other_isakmp_sas(SshIkeNegotiation negotiation,
                                                SshUInt32 connect_flags)
{
  SshIkeSA sa;

  if (connect_flags & SSH_IKE_REMOVE_FLAGS_MATCH_OTHER_BY_REMOTE_ID)
    {
      SshIkeContext context;
      SshADTHandle h;

      context = negotiation->sa->server_context->isakmp_context;

      for (h = ssh_adt_enumerate_start(context->isakmp_sa_mapping);
          h != SSH_ADT_INVALID;
          h = ssh_adt_enumerate_next(context->isakmp_sa_mapping, h))
        {
          sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);

          if (sa->lock_flags != 0)
            continue;

          if (sa->isakmp_negotiation == negotiation)
            continue;

          if (!sa->phase_1_done)
            continue;

          if (ssh_ike_id_compare(sa->isakmp_negotiation->ike_pm_info->
                                 remote_id,
                                 negotiation->ike_pm_info->remote_id))
            {
              sa->wired = 0;
              sa->lock_flags |= SSH_IKE_ISAKMP_LOCK_FLAG_DELETED;

              ssh_xregister_timeout(0, 0,
                                    ((connect_flags &
                                      SSH_IKE_REMOVE_FLAGS_SEND_DELETE)
                                     ? ike_expire_callback
                                     : ike_remove_callback),
                                    sa->isakmp_negotiation);
            }
        }
    }
  else
    {
      /* Mark the current sa, so that it must be kept, so ike_sa_find_ip_port
         will ignore it */
      negotiation->sa->lock_flags |= SSH_IKE_ISAKMP_LOCK_FLAG_KEEP_THIS;

      do {
        sa = ike_sa_find_ip_port(negotiation->sa->server_context->
                                 isakmp_context, NULL,
                                 NULL, NULL, /* Any local address */
                                 negotiation->sa->isakmp_negotiation->
                                 ike_pm_info->remote_ip,
                                 negotiation->sa->isakmp_negotiation->
                                 ike_pm_info->remote_port);
        if (sa == NULL)
          break;

        /* Do not delete negotiations in progress now. Note this works because
           ike_sa_find_ip_port always returns all valid established SAs first,
           then all IKE SAs that are otherwise valid, but which are about to
           expire, and only after that it will start returning partial SAs. */
        if (!sa->phase_1_done)
          break;

        sa->wired = 0;
        sa->lock_flags |= SSH_IKE_ISAKMP_LOCK_FLAG_DELETED;

        ssh_xregister_timeout(0, 0,
                              ((connect_flags &
                                SSH_IKE_REMOVE_FLAGS_SEND_DELETE)
                               ? ike_expire_callback
                               : ike_remove_callback),
                              sa->isakmp_negotiation);
      } while (1);

      /* Remove the mark from the lock flags, we added in the beginning of this
         function. */
      negotiation->sa->lock_flags &= ~(SSH_IKE_ISAKMP_LOCK_FLAG_KEEP_THIS);
    }
  return SSH_IKE_ERROR_OK;
}

/*                                                              shade{0.9}
 * Convert error code to string.                                shade{1.0} */
const char *ssh_ike_error_code_to_string(SshIkeNotifyMessageType code)
{
  const char *str;

  str = ssh_find_keyword_name(ssh_ike_status_keywords, code);
  if (str == NULL)
    str = "unknown";
  return str;
}

#ifdef DEBUG_LIGHT

void ssh_ike_debug(int level, const char *file, int line,
                   const char *func, SshIkeNegotiation negotiation,
                   unsigned char *description)
{
  Boolean this_end_is_initiator;
  unsigned const char *local_ip, *local_port, *remote_ip, *remote_port;
  unsigned char negotiation_index[SSH_IKE_STR_INT32_LEN];
  const char *initiator;
  const char *exchange_type;
  unsigned char message_id[SSH_IKE_STR_INT32_LEN];
  unsigned char cookies[SSH_IKE_COOKIE_LENGTH * 2 * 2 + 8];
  unsigned char local_ip_port[SSH_IKE_STR_IP_LEN + SSH_IKE_STR_INT32_LEN + 1],
    remote_ip_port[SSH_IKE_STR_IP_LEN + SSH_IKE_STR_INT32_LEN + 1];

  if (description == NULL)
    return;

  ssh_snprintf(negotiation_index, sizeof(negotiation_index), "unknown");
  initiator = "unknown";
  exchange_type = "unknown";
  ssh_snprintf(message_id, sizeof(message_id), "unknown");
  ssh_snprintf(cookies, sizeof(cookies), "unknown");
  ssh_snprintf(local_ip_port, sizeof(local_ip_port), "unknown");
  ssh_snprintf(remote_ip_port, sizeof(remote_ip_port), "unknown");

  if (negotiation != NULL)
    {
      ssh_snprintf(negotiation_index, sizeof(negotiation_index),
                   "%d", negotiation->negotiation_index);
      switch (negotiation->exchange_type)
        {
        case SSH_IKE_XCHG_TYPE_INFO:
          this_end_is_initiator =
            negotiation->info_pm_info->this_end_is_initiator;
          local_ip = negotiation->info_pm_info->local_ip;
          local_port = negotiation->info_pm_info->local_port;
          remote_ip = negotiation->info_pm_info->remote_ip;
          remote_port = negotiation->info_pm_info->remote_port;
          break;
        case SSH_IKE_XCHG_TYPE_NGM:
          this_end_is_initiator =
            negotiation->ngm_pm_info->this_end_is_initiator;
          local_ip = negotiation->ngm_pm_info->local_ip;
          local_port = negotiation->ngm_pm_info->local_port;
          remote_ip = negotiation->ngm_pm_info->remote_ip;
          remote_port = negotiation->ngm_pm_info->remote_port;
          break;
        case SSH_IKE_XCHG_TYPE_QM:
          this_end_is_initiator =
            negotiation->qm_pm_info->this_end_is_initiator;
          local_ip = negotiation->qm_pm_info->local_ip;
          local_port = negotiation->qm_pm_info->local_port;
          remote_ip = negotiation->qm_pm_info->remote_ip;
          remote_port = negotiation->qm_pm_info->remote_port;
          break;
        case SSH_IKE_XCHG_TYPE_AGGR:
        case SSH_IKE_XCHG_TYPE_IP:
          this_end_is_initiator =
            negotiation->ike_pm_info->this_end_is_initiator;
          local_ip = negotiation->ike_pm_info->local_ip;
          local_port = negotiation->ike_pm_info->local_port;
          remote_ip = negotiation->ike_pm_info->remote_ip;
          remote_port = negotiation->ike_pm_info->remote_port;
          break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
        case SSH_IKE_XCHG_TYPE_CFG:
          this_end_is_initiator =
            negotiation->cfg_pm_info->this_end_is_initiator;
          local_ip = negotiation->cfg_pm_info->local_ip;
          local_port = negotiation->cfg_pm_info->local_port;
          remote_ip = negotiation->cfg_pm_info->remote_ip;
          remote_port = negotiation->cfg_pm_info->remote_port;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
          break;
        default:
          this_end_is_initiator = FALSE;
          local_ip = NULL;
          local_port = NULL;
          remote_ip = NULL;
          remote_port = NULL;
          break;
        }
      if (this_end_is_initiator)
        initiator = "Initiator";
      else
        initiator = "Responder";

      exchange_type = ssh_find_keyword_name(ssh_ike_xchg_type_keywords,
                                            negotiation->exchange_type);
      if (negotiation->ed)
        ssh_snprintf(message_id, sizeof(message_id), "0x%08lx",
                     (unsigned long) negotiation->ed->message_id);

      if (negotiation->sa != NULL)
        {
          SshIkeSA sa;

          sa = negotiation->sa;
          ssh_snprintf(cookies, sizeof(cookies), "%08lx %08lx - %08lx %08lx",
                       (unsigned long)
                       SSH_IKE_GET32(sa->cookies.initiator_cookie),
                       (unsigned long)
                       SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                       (unsigned long)
                       SSH_IKE_GET32(sa->cookies.responder_cookie),
                       (unsigned long)
                       SSH_IKE_GET32(sa->cookies.responder_cookie + 4));
        }
      ssh_snprintf(local_ip_port, sizeof(local_ip_port), "%s%s%s",
                   (local_ip ? local_ip : ssh_custr("")),
                   (local_port ? ":" : ""),
                   (local_port ? local_port : ssh_custr("")));
      ssh_snprintf(remote_ip_port, sizeof(remote_ip_port), "%s%s%s",
                   (remote_ip ? remote_ip : ssh_custr("")),
                   (remote_port ? ":" : ""),
                   (remote_port ? remote_port : ssh_custr("")));
    }

  ssh_debug("%s (%s) <-> %s { %s [%s] / %s } %s; %s",
            local_ip_port, initiator, remote_ip_port, cookies,
            negotiation_index, message_id, exchange_type, description);
  ssh_free(description);
}

void ssh_ike_debug_buffer(int level, const char *file, int line,
                          const char *func, SshIkeNegotiation negotiation,
                          const char *string, size_t len,
                          const unsigned char *buffer)
{
  unsigned char *description, *p;
  int desc_len, i;
  Boolean truncated = FALSE;

  if (string == NULL)
    return;
  /* string[0..len] = 0xdeadbeaf 0000ffff */
  desc_len = strlen(string) + 4 + SSH_IKE_STR_INT32_LEN + 6 +
    len * 2 + len / 4 + 4;

  description = ssh_malloc(desc_len);
  if (description == NULL)
    return;
  if (len == 0)
    {
      ssh_snprintf(description, desc_len, "%s[%d]", string, len);
    }
  else
    {
      ssh_snprintf(description, desc_len, "%s[%d] = 0x", string, len);

      if (ssh_ike_logging_level - level + 1 < len / 20)
        {
          len = (ssh_ike_logging_level - level + 1) * 20;
          truncated = TRUE;
        }
      desc_len = desc_len - ssh_ustrlen(description);
      p = description + ssh_ustrlen(description);

      for (i = 0; i + 4 < len && desc_len > 0; i += 4)
        {
          ssh_snprintf(p, desc_len, "%08lx ", SSH_IKE_GET32(buffer + i));
          desc_len -= ssh_ustrlen(p);
          p += ssh_ustrlen(p);
        }

      for (; i < len && desc_len > 0; i++)
        {
          ssh_snprintf(p, desc_len, "%02x", SSH_IKE_GET8(buffer + i));
          desc_len -= ssh_ustrlen(p);
          p += ssh_ustrlen(p);
        }
      if (truncated)
        {
          ssh_snprintf(p, desc_len, "...");
        }
    }
  ssh_ike_debug(level, file, line, func, negotiation, description);
}

#endif /* DEBUG_LIGHT */


Boolean ssh_ike_attach_audit_context(SshIkeContext context,
                                     SshAuditContext audit)
{
  SshIkeAuditContext ike_audit;

  if (audit == NULL)
    return TRUE;

  SSH_DEBUG(5, ("Attaching a new audit context"));

  if ((ike_audit = ssh_calloc(1, sizeof(*ike_audit))) == NULL)
    return FALSE;

  ike_audit->audit = audit;

  /* Link the audit to the global list of audit contexts. */
  ike_audit->next = context->ike_audit_contexts;
  context->ike_audit_contexts = ike_audit;

  return TRUE;
}

void ssh_ike_audit_event(SshIkeContext isakmp_context,
                         SshAuditEvent event, ...)
{
  SshIkeAuditContext audit;
  va_list ap;

  audit = isakmp_context->ike_audit_contexts;
  while (audit)
    {
      va_start(ap, event);
      ssh_audit_event_va(audit->audit, event, ap);
      va_end(ap);

      audit = audit->next;
    }
}

/*                                                              shade{0.9}
 * Send audit event to audit log                                shade{1.0} */
void ssh_ike_audit(SshIkeNegotiation negotiation, SshAuditEvent event,
                   const char *txt)
{
  char spi[SSH_IKE_COOKIE_LENGTH * 2];
  unsigned char *local_ip = NULL, *remote_ip = NULL;

  if (negotiation == NULL ||
      negotiation->sa == NULL ||
      negotiation->sa->server_context == NULL ||
      negotiation->sa->server_context->isakmp_context == NULL)
    return;

  ike_debug_negotiation_error(negotiation, txt);

  switch (negotiation->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_INFO:
      local_ip = negotiation->info_pm_info->local_ip;
      remote_ip = negotiation->info_pm_info->remote_ip;
      break;
    case SSH_IKE_XCHG_TYPE_NGM:
      local_ip = negotiation->ngm_pm_info->local_ip;
      remote_ip = negotiation->ngm_pm_info->remote_ip;
      break;
    case SSH_IKE_XCHG_TYPE_QM:
      local_ip = negotiation->qm_pm_info->local_ip;
      remote_ip = negotiation->qm_pm_info->remote_ip;
      break;
    case SSH_IKE_XCHG_TYPE_AGGR:
    case SSH_IKE_XCHG_TYPE_IP:
      local_ip = negotiation->ike_pm_info->local_ip;
      remote_ip = negotiation->ike_pm_info->remote_ip;
      break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case SSH_IKE_XCHG_TYPE_CFG:
      local_ip = negotiation->cfg_pm_info->local_ip;
      remote_ip = negotiation->cfg_pm_info->remote_ip;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
      break;
    default:
      break;
    }

  memcpy(spi, negotiation->sa->cookies.initiator_cookie,
         SSH_IKE_COOKIE_LENGTH);
  memcpy(spi + SSH_IKE_COOKIE_LENGTH,
         negotiation->sa->cookies.responder_cookie,
         SSH_IKE_COOKIE_LENGTH);

  ssh_ike_audit_event(negotiation->sa->server_context->isakmp_context,
                      event,
                      SSH_AUDIT_SPI, spi, 2 * SSH_IKE_COOKIE_LENGTH,
                      SSH_AUDIT_SOURCE_ADDRESS_STR, local_ip,
                      SSH_AUDIT_DESTINATION_ADDRESS_STR, remote_ip,
                      SSH_AUDIT_TXT, txt,
                      SSH_AUDIT_ARGUMENT_END);
}


/* Sets private payload handlers for IKE SA, used in the negotiation. These
   handers will be inherited to all new negotiations for that SA. */
void ssh_ike_sa_private_payload_handlers(SshIkeNegotiation negotiation,
                                         SshIkePrivatePayloadPhaseICheck
                                         private_payload_phase_1_check,
                                         SshIkePrivatePayloadPhaseIIn
                                         private_payload_phase_1_in,
                                         SshIkePrivatePayloadPhaseIOut
                                         private_payload_phase_1_out,
                                         SshIkePrivatePayloadPhaseIICheck
                                         private_payload_phase_2_check,
                                         SshIkePrivatePayloadPhaseIIIn
                                         private_payload_phase_2_in,
                                         SshIkePrivatePayloadPhaseIIOut
                                         private_payload_phase_2_out,
                                         SshIkePrivatePayloadPhaseQmCheck
                                         private_payload_phase_qm_check,
                                         SshIkePrivatePayloadPhaseQmIn
                                         private_payload_phase_qm_in,
                                         SshIkePrivatePayloadPhaseQmOut
                                         private_payload_phase_qm_out,
                                         void *private_payload_context)
{
  negotiation->sa->private_payload_phase_1_check =
    private_payload_phase_1_check;
  negotiation->sa->private_payload_phase_1_input =
    private_payload_phase_1_in;
  negotiation->sa->private_payload_phase_1_output =
    private_payload_phase_1_out;

  negotiation->sa->private_payload_phase_2_check =
    private_payload_phase_2_check;
  negotiation->sa->private_payload_phase_2_input =
    private_payload_phase_2_in;
  negotiation->sa->private_payload_phase_2_output =
    private_payload_phase_2_out;

  negotiation->sa->private_payload_phase_qm_check =
    private_payload_phase_qm_check;
  negotiation->sa->private_payload_phase_qm_input =
    private_payload_phase_qm_in;
  negotiation->sa->private_payload_phase_qm_output =
    private_payload_phase_qm_out;

  negotiation->sa->private_payload_context = private_payload_context;
}

/* Sets private payload handlers for phase 1 negotiation. */
void ssh_ike_phase_i_private_payload_handlers(SshIkeNegotiation negotiation,
                                              SshIkePrivatePayloadPhaseICheck
                                              private_payload_phase_1_check,
                                              SshIkePrivatePayloadPhaseIIn
                                              private_payload_phase_1_in,
                                              SshIkePrivatePayloadPhaseIOut
                                              private_payload_phase_1_out,
                                              void *private_payload_context)
{
  switch (negotiation->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_AGGR:
    case SSH_IKE_XCHG_TYPE_IP:
      break;
    default:
      ssh_fatal("Ssh_ike_phase_i_private_payload_handlers called "
                "with non phase 1 negotiation");
    }

  negotiation->ed->private_payload_phase_1_check =
    private_payload_phase_1_check;
  negotiation->ed->private_payload_phase_1_input =
    private_payload_phase_1_in;
  negotiation->ed->private_payload_phase_1_output =
    private_payload_phase_1_out;

  negotiation->ed->private_payload_context = private_payload_context;
}


/* Sets private payload handlers for phase 2 negotiation. */
void ssh_ike_phase_ii_private_payload_handlers(SshIkeNegotiation negotiation,
                                               SshIkePrivatePayloadPhaseIICheck
                                               private_payload_phase_2_check,
                                               SshIkePrivatePayloadPhaseIIIn
                                               private_payload_phase_2_in,
                                               SshIkePrivatePayloadPhaseIIOut
                                               private_payload_phase_2_out,
                                               void *private_payload_context)
{
  switch (negotiation->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_INFO:
    case SSH_IKE_XCHG_TYPE_NGM:
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case SSH_IKE_XCHG_TYPE_CFG:
#endif /* SSHDIST_ISAKMP_CFG_MODE */
      break;
    default:
      ssh_fatal("Ssh_ike_phase_ii_private_payload_handlers called "
                "with non phase 2 negotiation");
    }

  negotiation->ed->private_payload_phase_2_check =
    private_payload_phase_2_check;
  negotiation->ed->private_payload_phase_2_input =
    private_payload_phase_2_in;
  negotiation->ed->private_payload_phase_2_output =
    private_payload_phase_2_out;

  negotiation->ed->private_payload_context = private_payload_context;
}

/* Sets private payload handlers for quick mode negotiation. */
void ssh_ike_qm_private_payload_handlers(SshIkeNegotiation negotiation,
                                         SshIkePrivatePayloadPhaseQmCheck
                                         private_payload_phase_qm_check,
                                         SshIkePrivatePayloadPhaseQmIn
                                         private_payload_phase_qm_in,
                                         SshIkePrivatePayloadPhaseQmOut
                                         private_payload_phase_qm_out,
                                         void *private_payload_context)
{
  switch (negotiation->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_QM:
      break;
    default:
      ssh_fatal("Ssh_ike_phase_i_private_payload_handlers called "
                "with non quick mode negotiation");
    }

  negotiation->ed->private_payload_phase_qm_check =
    private_payload_phase_qm_check;
  negotiation->ed->private_payload_phase_qm_input =
    private_payload_phase_qm_in;
  negotiation->ed->private_payload_phase_qm_output =
    private_payload_phase_qm_out;

  negotiation->ed->private_payload_context = private_payload_context;
}

#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
/* Register policy manager functions to the isakmp_library. This will take
   reference to the `functions' structure, and that structure must be valid
   as long as the ike server is in use (i.e until the ssh_ike_uninit function
   is called. This function must be called before the any ssh_ike_start_server
   functions are called. */
void ssh_ike_register_policy_functions(SshIkeContext ike_context,
                                       SshIkePolicyFunctions functions)
{
  ike_context->policy_functions = functions;
}
#endif /*  SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */

/* Change the SshIkeServer and destination ip and port numbers to new ones.
   This should be called when doing the NAT-T port floating etc. The
   SshIkeServer is used to select the listener when sending the packet out, i.e
   it selects the source port and address of the packet. Note, that this
   changes the SshIkeServerContext of the whole IKE SA, including all
   negotiation in progress, but the new_remote_ip and port are per negotiation,
   If new_remote_ip and port are NULL then do not change them.

   If you want to change the IKE SA remote ip and port use IKE SA negotiation
   pointer with this function. That pointer is can be found from
   pm_info->phase_i->negotiation.

   If change is successfull return TRUE otherwise return FALSE, and the
   negotiation is not modified. */
Boolean ssh_ike_sa_change_server(SshIkeNegotiation negotiation,
                                 SshIkeServerContext new_server,
                                 const unsigned char *new_remote_ip,
                                 const unsigned char *new_remote_port)
{
  unsigned char **remote_ipp, **remote_portp, *remote_ip, *remote_port;
  unsigned char **local_ipp, **local_portp, *local_ip, *local_port;
  unsigned char n[64];
#ifdef SSHDIST_IKEV2
  Boolean use_natt;
  SshUInt32 *server_flags;
  use_natt = 0;
#endif /* SSHDIST_IKEV2 */

  remote_ip = NULL;
  remote_port = NULL;
  local_ip = NULL;
  local_port = NULL;

  /* Server changed. */
  if (negotiation->sa->server_context != new_server)
    {
      /* Update the statistics, if this is complete IKE SA. */
      if (negotiation->sa->phase_1_done)
        {
          negotiation->sa->server_context->statistics->current_ike_sas--;
          if (negotiation->ike_pm_info->this_end_is_initiator)
            negotiation->sa->server_context->statistics->
              current_ike_sas_initiated--;
          else
            negotiation->sa->server_context->statistics->
              current_ike_sas_responded--;

          new_server->statistics->current_ike_sas++;
          if (negotiation->ike_pm_info->this_end_is_initiator)
            new_server->statistics->current_ike_sas_initiated++;
          else
            new_server->statistics->current_ike_sas_responded++;
        }
      negotiation->sa->server_context = new_server;
    }

  /* Update remote ip / port from PMINFO */
  if (negotiation->exchange_type == SSH_IKE_XCHG_TYPE_INFO)
    {
      remote_ipp = &negotiation->info_pm_info->remote_ip;
      remote_portp = &negotiation->info_pm_info->remote_port;
      local_ipp = &negotiation->info_pm_info->local_ip;
      local_portp = &negotiation->info_pm_info->local_port;
#ifdef SSHDIST_IKEV2
      server_flags = &negotiation->info_pm_info->server_flags;
#endif /* SSHDIST_IKEV2 */
    }
  else if (negotiation->exchange_type == SSH_IKE_XCHG_TYPE_NGM)
    {
      remote_ipp = &negotiation->ngm_pm_info->remote_ip;
      remote_portp = &negotiation->ngm_pm_info->remote_port;
      local_ipp = &negotiation->ngm_pm_info->local_ip;
      local_portp = &negotiation->ngm_pm_info->local_port;
#ifdef SSHDIST_IKEV2
      server_flags = &negotiation->ngm_pm_info->server_flags;
#endif /* SSHDIST_IKEV2 */
    }
  else if (negotiation->exchange_type == SSH_IKE_XCHG_TYPE_QM)
    {
      remote_ipp = &negotiation->qm_pm_info->remote_ip;
      remote_portp = &negotiation->qm_pm_info->remote_port;
      local_ipp = &negotiation->qm_pm_info->local_ip;
      local_portp = &negotiation->qm_pm_info->local_port;
#ifdef SSHDIST_IKEV2
      server_flags = &negotiation->qm_pm_info->server_flags;
#endif /* SSHDIST_IKEV2 */
    }
#ifdef SSHDIST_ISAKMP_CFG_MODE
  else if (negotiation->exchange_type == SSH_IKE_XCHG_TYPE_CFG)
    {
      remote_ipp = &negotiation->cfg_pm_info->remote_ip;
      remote_portp = &negotiation->cfg_pm_info->remote_port;
      local_ipp = &negotiation->cfg_pm_info->local_ip;
      local_portp = &negotiation->cfg_pm_info->local_port;
#ifdef SSHDIST_IKEV2
      server_flags = &negotiation->cfg_pm_info->server_flags;
#endif /* SSHDIST_IKEV2 */
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  else
    {
      remote_ipp = &negotiation->ike_pm_info->remote_ip;
      remote_portp = &negotiation->ike_pm_info->remote_port;
      local_ipp = &negotiation->ike_pm_info->local_ip;
      local_portp = &negotiation->ike_pm_info->local_port;
#ifdef SSHDIST_IKEV2
      server_flags = &negotiation->ike_pm_info->server_flags;
#endif /* SSHDIST_IKEV2 */
    }

  /* Update the local IP */
  if ((local_ip =
       ssh_strdup((const char *)
                  ike_ip_string(new_server->ip_address, n, sizeof(n))))
      == NULL)
    goto error;

  /* Update the local port. */
#ifdef SSHDIST_IKEV2
  if (*server_flags & SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT)
    use_natt = 1;
  *server_flags &= ~SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT;
  if (use_natt)
    {
      if ((local_port =
           ssh_strdup((const char *)
                      ike_port_string(new_server->nat_t_local_port,
                                      n, sizeof(n))))
          == NULL)
        goto error;
    }
  else
#endif /* SSHDIST_IKEV2 */
    {
      if ((local_port =
           ssh_strdup((const char *)
                      ike_port_string(new_server->normal_local_port,
                                      n, sizeof(n))))
          == NULL)
        goto error;
    }

  if (new_remote_ip)
    {
      remote_ip = ssh_strdup(new_remote_ip);
      if (remote_ip == NULL)
        goto error;
      ssh_free(*remote_ipp);
      *remote_ipp = remote_ip;
    }

  if (new_remote_port)
    {
      remote_port = ssh_strdup(new_remote_port);
      if (remote_port == NULL)
        goto error;
      ssh_free(*remote_portp);
      *remote_portp = remote_port;
    }

  if (local_ip)
    {
      ssh_free(*local_ipp);
      *local_ipp = local_ip;
    }

  if (local_port)
    {
      ssh_free(*local_portp);
      *local_portp = local_port;
    }

#ifdef SSHDIST_IKEV2
  /* Set the use_natt flag in SA */
  negotiation->sa->use_natt = use_natt;
#endif /* SSHDIST_IKEV2 */

  return TRUE;


  /* Error handling. */

 error:

  ssh_free(remote_ip);
  ssh_free(remote_port);
  ssh_free(local_ip);
  ssh_free(local_port);

  return FALSE;
}
