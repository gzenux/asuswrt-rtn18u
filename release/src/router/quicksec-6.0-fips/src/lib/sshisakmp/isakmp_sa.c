/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp sa hash functions.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshIkeSa"

/* Cookie full of zeros */

unsigned const char ssh_ike_half_cookie[SSH_IKE_COOKIE_LENGTH]
  = { 0,0,0,0,0,0,0,0 };

/*                                                              shade{0.9}
 * Find SA from the hash table by ip/port                       shade{1.0}
 */
SshIkeSA ike_sa_find_ip_port(SshIkeContext context,
                             SshIkeNegotiation isakmp_sa_negotiation,
                             const unsigned char *local_ip,
                             const unsigned char *local_port,
                             const unsigned char *remote_ip,
                             const unsigned char *remote_port)
{
  SshIkeSA sa, return_sa;
  SshTime current;
  SshADTHandle h;
  const unsigned char *all;

  all = ssh_custr("all");
  SSH_DEBUG(12, ("Start, remote = %s:%s",
                 remote_ip ? remote_ip : all,
                 remote_port ? remote_port : all));

  current = ssh_time();
  return_sa = NULL;

  for (h = ssh_adt_enumerate_start(context->isakmp_sa_mapping);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(context->isakmp_sa_mapping, h))
    {
      sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);

      if (sa->lock_flags != 0)
        continue;
      if (isakmp_sa_negotiation != NULL)
        {
          if (isakmp_sa_negotiation == sa->isakmp_negotiation)
            {
              SSH_DEBUG(5,
                        ("Remote = %s:%s, Found SA = "
                         "{ %08lx %08lx - %08lx %08lx}",
                         remote_ip ? remote_ip : all,
                         remote_port ? remote_port : all,
                         (unsigned long)
                         SSH_IKE_GET32(sa->cookies.initiator_cookie),
                         (unsigned long)
                         SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                         (unsigned long)
                         SSH_IKE_GET32(sa->cookies.responder_cookie),
                         (unsigned long)
                         SSH_IKE_GET32(sa->cookies.responder_cookie + 4)));
              sa->last_use_time = ssh_time();
              return sa;
            }
        }
      else if ((remote_ip == NULL ||
                sa->isakmp_negotiation->ike_pm_info->remote_ip == NULL ||
                ssh_inet_ip_address_compare(remote_ip,
                                            sa->isakmp_negotiation->
                                            ike_pm_info->remote_ip) == 0) &&
               (remote_port == NULL ||
                sa->isakmp_negotiation->ike_pm_info->remote_port == NULL ||
                ssh_inet_port_number_compare(remote_port,
                                             sa->isakmp_negotiation->
                                             ike_pm_info->remote_port,
                                             ssh_custr("udp")) == 0) &&
               (local_ip == NULL ||
                sa->isakmp_negotiation->ike_pm_info->local_ip == NULL ||
                ssh_inet_ip_address_compare(local_ip,
                                            sa->isakmp_negotiation->
                                            ike_pm_info->local_ip) == 0) &&
               (local_port == NULL ||
                sa->isakmp_negotiation->ike_pm_info->local_port == NULL ||
                ssh_inet_port_number_compare(local_port,
                                             sa->isakmp_negotiation->
                                             ike_pm_info->local_port,
                                             ssh_custr("udp")) == 0))
        {
          if (!sa->phase_1_done)
            {
              if (return_sa == NULL)
                return_sa = sa;
            }
          else
            {
              /* Do not select a version that is about to expire */
              if (current > sa->isakmp_negotiation->ike_pm_info->sa_expire_time
                  - sa->expire_timer)
                {
                  if (return_sa == NULL)
                    return_sa = sa;
                  else if (!return_sa->phase_1_done)
                    return_sa = sa;
                }
              else
                {
                  SSH_DEBUG(5,
                            ("Remote = %s:%s, "
                             "Found SA = { %08lx %08lx - %08lx %08lx}",
                             remote_ip ? remote_ip : all,
                             remote_port ? remote_port : all,
                             (unsigned long)
                             SSH_IKE_GET32(sa->cookies.initiator_cookie),
                             (unsigned long)
                             SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                             (unsigned long)
                             SSH_IKE_GET32(sa->cookies.responder_cookie),
                             (unsigned long)
                             SSH_IKE_GET32(sa->cookies.responder_cookie + 4)));
                  sa->last_use_time = ssh_time();
                  return sa;
                }
            }
        }
    }
  if (return_sa)
    {
      SSH_DEBUG(12, ("Partial found, remote = %s:%s",
                     remote_ip ? remote_ip : all,
                     remote_port ? remote_port : all));
      return return_sa;
    }
  SSH_DEBUG(12, ("Not found, remote = %s:%s",
                 remote_ip ? remote_ip : all,
                 remote_port ? remote_port : all));
  return NULL;
}


/*                                                              shade{0.9}
 * Find SA from the hash table                                  shade{1.0}
 */
SshIkeSA ike_sa_find(SshIkeContext context,
                     const unsigned char *initiator,
                     const unsigned char *responder)
{
  struct SshIkeCookiesRec c;
  SshADTHandle h;
  SshIkeSA sa;

  SSH_DEBUG(12, ("Start, SA = { %08lx %08lx - %08lx %08lx }",
                 (unsigned long)
                 SSH_IKE_GET32(initiator),
                 (unsigned long)
                 SSH_IKE_GET32(initiator + 4),
                 (unsigned long)
                 SSH_IKE_GET32(responder),
                 (unsigned long)
                 SSH_IKE_GET32(responder + 4)));

  memcpy(c.initiator_cookie, initiator, SSH_IKE_COOKIE_LENGTH);
  memcpy(c.responder_cookie, responder, SSH_IKE_COOKIE_LENGTH);

  h = ssh_adt_get_handle_to_equal(context->isakmp_sa_mapping, &c);

  if (h != SSH_ADT_INVALID)
    {
      sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);
      SSH_DEBUG(5, ("Found SA = { %08lx %08lx - %08lx %08lx }",
                    (unsigned long)
                    SSH_IKE_GET32(initiator),
                    (unsigned long)
                    SSH_IKE_GET32(initiator + 4),
                    (unsigned long)
                    SSH_IKE_GET32(responder),
                    (unsigned long)
                     SSH_IKE_GET32(responder + 4)));
      sa->last_use_time = ssh_time();
      return sa;
    }
  else
    {
      SSH_DEBUG(5, ("Not found SA = { %08lx %08lx - %08lx %08lx }",
                    (unsigned long)
                    SSH_IKE_GET32(initiator),
                    (unsigned long)
                    SSH_IKE_GET32(initiator + 4),
                    (unsigned long)
                    SSH_IKE_GET32(responder),
                    (unsigned long)
                    SSH_IKE_GET32(responder + 4)));
      return NULL;
    }
}

/*                                                              shade{0.9}
 * Find half SA.
 * Return new SA or NULL if error.                              shade{1.0}
 */
SshIkeSA ike_sa_find_half(SshIkeContext context,
                          const unsigned char *initiator)
{
  struct SshIkeCookiesRec c;
  SshADTHandle h;
  SshIkeSA sa;

  SSH_DEBUG(12, ("Start, SA = { %08lx %08lx - %08lx %08lx }",
                 (unsigned long)
                 SSH_IKE_GET32(initiator),
                 (unsigned long)
                 SSH_IKE_GET32(initiator + 4),
                 (unsigned long)
                 0,
                 (unsigned long)
                 0));

  memcpy(c.initiator_cookie, initiator, SSH_IKE_COOKIE_LENGTH);
  memset(c.responder_cookie, 0, SSH_IKE_COOKIE_LENGTH);

  h = ssh_adt_get_handle_to_equal(context->isakmp_sa_mapping, &c);

  if (h != SSH_ADT_INVALID)
    {
      sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);
      SSH_DEBUG(5, ("Found half SA = { %08lx %08lx - %08lx %08lx }",
                    (unsigned long)
                    SSH_IKE_GET32(initiator),
                    (unsigned long)
                    SSH_IKE_GET32(initiator + 4),
                    (unsigned long)
                    0,
                    (unsigned long)
                    0));
      sa->last_use_time = ssh_time();
      return sa;
    }
  else
    {
      SSH_DEBUG(5, ("Not found half SA = { %08lx %08lx - %08lx %08lx }",
                    (unsigned long)
                    SSH_IKE_GET32(initiator),
                    (unsigned long)
                    SSH_IKE_GET32(initiator + 4),
                    (unsigned long)
                    0,
                    (unsigned long)
                    0));
      return NULL;
    }
}

/*                                                              shade{0.9}
 * Delete SA.                                                   shade{1.0}
 */
void ike_sa_delete(SshIkeContext context, SshIkeSA sa)
{
  SshIkeSA removed_sa;
  SshADTHandle h;

  SSH_DEBUG(5, ("Start, SA = { %08lx %08lx - %08lx %08lx }",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4)));

  h = ssh_adt_get_handle_to_equal(context->isakmp_sa_mapping,
                                  &(sa->cookies));
  if (h != SSH_ADT_INVALID)
    {
      removed_sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);
      SSH_ASSERT(removed_sa == sa);
      ssh_adt_delete(context->isakmp_sa_mapping, h);
    }
  else
    {
      SSH_DEBUG(3, ("No isakmp_sa found in ssh_isakmp_sa_delete"));
    }

  h = ssh_adt_get_handle_to_equal(context->isakmp_cookie_mapping,
                                  &sa->cookies.initiator_cookie);
  if (h != SSH_ADT_INVALID)
    {
      removed_sa = ssh_adt_map_lookup(context->isakmp_cookie_mapping, h);
      SSH_ASSERT(removed_sa == sa);
      ssh_adt_delete(context->isakmp_cookie_mapping, h);
    }
  else
    {
      SSH_DEBUG(3, ("No isakmp_sa found in cookie mapping in "
                    "ssh_isakmp_sa_delete"));
    }
  context->isakmp_sa_count--;
  SSH_ASSERT(context->isakmp_sa_count != -1);
  return;
}

/*                                                              shade{0.9}
 * Upgrade half allocated SA to fully allocated SA using
 * responder cookie given, return new SA or NULL if error.      shade{1.0}
 */
SshIkeSA ike_sa_upgrade(SshIkeContext context, SshIkeSA sa,
                        const unsigned char *cookie)
{
  SshIkeSA removed_sa;
  SshADTHandle h;

  SSH_DEBUG(5, ("Start, SA = { %08lx %08lx - %08lx %08lx } -> "
                "{ ... - %08lx %08lx }",
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.initiator_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie),
                (unsigned long)
                SSH_IKE_GET32(sa->cookies.responder_cookie + 4),
                (unsigned long)
                SSH_IKE_GET32(cookie),
                (unsigned long)
                SSH_IKE_GET32(cookie + 4)));

  h = ssh_adt_get_handle_to_equal(context->isakmp_sa_mapping,
                                  &(sa->cookies));

  if (h == SSH_ADT_INVALID)
    ssh_fatal("No isakmp_sa found in ssh_isakmp_sa_upgrade");
  removed_sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);
  SSH_ASSERT(removed_sa == sa);
  ssh_adt_delete(context->isakmp_sa_mapping, h);

  memcpy(sa->cookies.responder_cookie, cookie, SSH_IKE_COOKIE_LENGTH);

  h = ssh_adt_get_handle_to_equal(context->isakmp_sa_mapping,
                                  &(sa->cookies));
  /* Check if such SA already found */
  if (h != SSH_ADT_INVALID)
    {
      SSH_DEBUG(3, ("Upgrade failed, SA already found!"));
      /* Free the SA, as it is already deleted from the isakmp_sa_mapping. */
      /* Before that we need to fix the cookie back to 0, so we do not remove
         the duplicate entry from isakmp_sa_mapping, but only the partial
         entry. */
      memset(sa->cookies.responder_cookie, 0, SSH_IKE_COOKIE_LENGTH);
      ike_remove_callback(sa->isakmp_negotiation);
      /* We need to decrement the isakmp_sa_count here. */
      context->isakmp_sa_count--;
      return NULL;
    }
  h = ssh_adt_put(context->isakmp_sa_mapping, &(sa->cookies));
  SSH_ASSERT(h != SSH_ADT_INVALID);
  ssh_adt_map_attach(context->isakmp_sa_mapping, h, sa);
  sa->last_use_time = ssh_time();
  return sa;
}


/*                                                              shade{0.9}
 * Remove 25% of entries in mapping table. Start from
 * entries that are old (> 75% lifetime gone) and
 * then entries that are not used lately.                       shade{1.0}
 */
void ike_clean_mapping(SshIkeContext context)
{
  int i, cnt, max_cnt, low;
  SshIkeSA *sa_table, sa;
  SshTime *time_table, t, current;
  SshIkeAttributeLifeDurationValues life;
  SshADTHandle h;

  SSH_DEBUG(5, ("Start"));
  cnt = 0;
  max_cnt = context->max_isakmp_sa_count / 4;
  sa_table = ssh_calloc(max_cnt, sizeof(SshIkeSA));
  time_table = ssh_calloc(max_cnt, sizeof(SshTime));
  if (sa_table == NULL || time_table == NULL)
    {
      /* Memory exhausted, remove all IKE SAs we can to make more room. */
      ssh_warning("Out of memory while cleaning IKE SAs, "
                  "removing all SAs we can");
      cnt = 0;
      for (h = ssh_adt_enumerate_start(context->isakmp_sa_mapping);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(context->isakmp_sa_mapping, h))
        {
          sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);
          /* Skip all unusual SA (deleted, not initialized etc */
          if (sa->wired || sa->lock_flags != 0)
            {
              cnt++;
              continue;
            }
          ssh_cancel_timeouts(SSH_ALL_CALLBACKS, sa->isakmp_negotiation);
          ike_expire_callback(sa->isakmp_negotiation);
        }
      if (cnt != 0)
        ssh_warning("Found %d negotiations we could not remove", cnt);

      ssh_free(sa_table);
      ssh_free(time_table);
      return;
    }

  current = ssh_time();

  /* Find old entries */
  for (h = ssh_adt_enumerate_start(context->isakmp_sa_mapping);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(context->isakmp_sa_mapping, h))
    {
      sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);

      /* Skip all unusual SA (deleted, not initialized etc */
      if (sa->wired || sa->lock_flags != 0)
        continue;

      /* Check if this is phase 1 negotiation, and we are responder, and to
         which we haven't received any packets but the first, and which have
         several retransmissions (== possible denial of service attack). */
      if (!sa->phase_1_done &&
          !sa->isakmp_negotiation->ike_pm_info->this_end_is_initiator &&
          sa->isakmp_negotiation->ed->number_of_packets_in == 1 &&
          sa->isakmp_negotiation->ed->retry_count <
          sa->isakmp_negotiation->ed->retry_limit / 2)
        {
          SSH_DEBUG(9, ("Found possible DoS attack, sa = %p", sa));
          time_table[cnt] = 0x7fffffff;
          sa_table[cnt++] = sa;
          sa->created_time = 0;
          if (cnt == max_cnt)
            break;
          continue;
        }

      /* Skip those who have been used quite recently */
      if (current - sa->last_use_time <=
          (sa->retry_timer_max * 2) + (sa->retry_timer_max_usec / 500000))
        continue;

      life = (SshUInt32) (sa->isakmp_negotiation->ike_pm_info->sa_expire_time -
                          sa->created_time);
      t = current - sa->created_time;
      if (t > life / 4 * 3)
        {
          SSH_DEBUG(9, ("Found old negotiation, age = %ld, sa = %p",
                        (unsigned long) t, sa));
          time_table[cnt] = 0x7fffffff;
          sa_table[cnt++] = sa;
          sa->created_time = 0;
          if (cnt == max_cnt)
            break;
        }
    }
  SSH_DEBUG(7, ("Found %d old negotiations", cnt));

  /* Find unused entries */
  if (cnt != max_cnt)
    {
      low = cnt;
      for (h = ssh_adt_enumerate_start(context->isakmp_sa_mapping);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(context->isakmp_sa_mapping, h))
        {
          sa = ssh_adt_map_lookup(context->isakmp_sa_mapping, h);

          /* Skip all unusual SA (deleted, not initialized etc */
          if (sa->wired || sa->lock_flags != 0)
            continue;

          /* Skip those already deleted */
          if (sa->created_time == 0)
            continue;

          /* Skip those who have been used quite recently */
          t = current - sa->last_use_time;

          i = cnt - 1;
          while (i >= low && t > time_table[i])
            i--;
          i++;
          if (i == cnt)
            {
              if (cnt < max_cnt)
                {
                  time_table[cnt] = t;
                  sa_table[cnt] = sa;
                  cnt++;
                }
            }
          else
            {
              if (cnt == max_cnt)
                {
                  memmove(&(time_table[i + 1]), &(time_table[i]),
                          (cnt - i - 1) * sizeof(SshTime));
                  memmove(&(sa_table[i + 1]), &(sa_table[i]),
                          (cnt - i - 1) * sizeof(SshIkeSA));
                }
              else
                {
                  memmove(&(time_table[i + 1]), &(time_table[i]),
                          (cnt - i) * sizeof(SshTime));
                  memmove(&(sa_table[i + 1]), &(sa_table[i]),
                          (cnt - i) * sizeof(SshIkeSA));
                  cnt++;
                }
              time_table[i] = t;
              sa_table[i] = sa;
            }
        }
    }

  for (i = 0; i < cnt; i++)
    {
      SSH_DEBUG(7, ("Expiring negotiation age = %ld, sa = %p",
                    (unsigned long) time_table[i], sa_table[i]));
      ssh_cancel_timeouts(SSH_ALL_CALLBACKS,
                          sa_table[i]->isakmp_negotiation);
      ike_expire_callback(sa_table[i]->isakmp_negotiation);
    }

  ssh_free(time_table);
  ssh_free(sa_table);
}




/*                                                              shade{0.9}
 * Allocate new SA. Return new SA or NULL if error.             shade{1.0}
 */
SshIkeSA ike_sa_allocate(SshIkeServerContext context,
                         const unsigned char *initiator,
                         const unsigned char *responder)
{
  SshIkeSA sa;
  SshADTHandle h;

  sa = ssh_calloc(1, sizeof(*sa));
  if (sa == NULL)
    return NULL;

  SSH_DEBUG(5, ("Start, SA = { %08lx %08lx - %08lx %08lx }",
                (unsigned long)
                SSH_IKE_GET32(initiator),
                (unsigned long)
                SSH_IKE_GET32(initiator + 4),
                (unsigned long)
                SSH_IKE_GET32(responder),
                (unsigned long)
                SSH_IKE_GET32(responder + 4)));

  memcpy(sa->cookies.initiator_cookie, initiator, SSH_IKE_COOKIE_LENGTH);
  memcpy(sa->cookies.responder_cookie, responder, SSH_IKE_COOKIE_LENGTH);
  sa->lock_flags = SSH_IKE_ISAKMP_LOCK_FLAG_UNINITIALIZED;
  sa->server_context = context;

  h = ssh_adt_get_handle_to_equal(context->isakmp_context->isakmp_sa_mapping,
                                  &(sa->cookies));

  /* Check if such SA already found */
  if (h != SSH_ADT_INVALID)
    {
      ssh_free(sa);
      SSH_DEBUG(3, ("Allocate failed, SA already found"));
      return NULL;
    }
  h = ssh_adt_put(context->isakmp_context->isakmp_sa_mapping, &(sa->cookies));
  SSH_ASSERT(h != SSH_ADT_INVALID);
  ssh_adt_map_attach(context->isakmp_context->isakmp_sa_mapping, h, sa);

  sa->last_use_time = ssh_time();
  context->isakmp_context->isakmp_sa_count++;
  if (context->isakmp_context->isakmp_sa_count >
      context->isakmp_context->max_isakmp_sa_count)
    {
      SSH_DEBUG(4, ("Resourse limit reached, deleting old isakmp_sa entries"));
      ike_clean_mapping(context->isakmp_context);
    }
  return sa;
}


/*                                                              shade{0.9}
 * Allocate new half SA. Return new SA or NULL if error.        shade{1.0}
 */
SshIkeSA ike_sa_allocate_half(SshIkeServerContext context,
                              const unsigned char *remote_ip,
                              const unsigned char *remote_port,
                              const unsigned char *cookie_in)
{
  unsigned char cookie[SSH_IKE_COOKIE_LENGTH];
  SshIkeSA isakmp_sa_return;
  SshADTHandle h;

  SSH_DEBUG(12, ("Start"));

  if (cookie_in == NULL)
    ike_cookie_create(context->isakmp_context, cookie);
  else
    memcpy(cookie, cookie_in, SSH_IKE_COOKIE_LENGTH);

  h = ssh_adt_get_handle_to_equal(context->isakmp_context->
                                  isakmp_cookie_mapping, cookie);

  if (h != SSH_ADT_INVALID)
    {
      ssh_warning("Duplicate initiator cookie in ike_sa_allocate_half");
      return NULL;
    }

  isakmp_sa_return = ike_sa_allocate(context, cookie, ssh_ike_half_cookie);
  if (isakmp_sa_return)
    {
      h = ssh_adt_put(context->isakmp_context->isakmp_cookie_mapping,
                      isakmp_sa_return->cookies.initiator_cookie);
      SSH_ASSERT(h != SSH_ADT_INVALID);
      ssh_adt_map_attach(context->isakmp_context->isakmp_cookie_mapping,
                         h, isakmp_sa_return);
    }
  return isakmp_sa_return;
}

/*                                                              shade{0.9}
 * Get SA of isakmp exchange, either allocate new one or
 * find the existing one, return notify message number
 * in case of error or 0 for success.                           shade{1.0}
 */
SshIkeNotifyMessageType ike_get_sa(SshIkeServerContext context,
                                   const unsigned char *remote_ip,
                                   const unsigned char *remote_port,
                                   SshIkeSA *isakmp_sa_return,
                                   SshIkeExchangeType *exchange_type,
                                   SshUInt32 *message_id,
                                   int *major_version,
                                   int *minor_version,
                                   SshBuffer buffer)
{
  size_t len;
  unsigned char *p;
  SshADTHandle h;
  unsigned char n[64];

  *isakmp_sa_return = NULL;

  len = ssh_buffer_len(buffer);
  if (len < SSH_IKE_PACKET_GENERIC_HEADER_LEN)
    {
      SSH_DEBUG(3, ("ssh_isakmp_find_sa got short packet: %ld",
                    (unsigned long) len));

      ike_ip_string(context->ip_address, n, sizeof(n));
      ssh_ike_audit_event(context->isakmp_context,
                          SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS,
                          SSH_AUDIT_SOURCE_ADDRESS_STR, n,
                          SSH_AUDIT_DESTINATION_ADDRESS_STR, remote_ip,
                          SSH_AUDIT_TXT, "UDP packet does not contain enough "
                          "data for generic ISAKMP packet header",
                          SSH_AUDIT_ARGUMENT_END);
      return SSH_IKE_NOTIFY_MESSAGE_UNEQUAL_PAYLOAD_LENGTHS;
    }

  p = ssh_buffer_ptr(buffer);

  *exchange_type = SSH_IKE_GET8(p + 18);
  *message_id = SSH_IKE_GET32(p + 20);
  *major_version = SSH_IKE_GET4L(p + 17);
  *minor_version = SSH_IKE_GET4R(p + 17);

  SSH_DEBUG(5, ("Start, SA = { %08lx %08lx - %08lx %08lx } / %08lx, "
                "remote = %s:%s",
                (unsigned long)
                SSH_IKE_GET32(p),
                (unsigned long)
                SSH_IKE_GET32(p + 4),
                (unsigned long)
                SSH_IKE_GET32(p + 8),
                (unsigned long)
                SSH_IKE_GET32(p + 12),
                (unsigned long)
                *message_id, remote_ip, remote_port));

  /* Check if this is the first packet from the initiator to us, i.e
     if the responder cookie is all zeros. */
  if (memcmp(p + SSH_IKE_COOKIE_LENGTH, ssh_ike_half_cookie,
             SSH_IKE_COOKIE_LENGTH) == 0)
    {
      /* This must be first packet from initiator to us, create cookie,
         allocate sa */
      unsigned char cookie[SSH_IKE_COOKIE_LENGTH];

      /* Set the exchange type to a known value for IKEv2 packets, since
         the value parsed above will not correspond to a known IKE1
         exchange type. */
      if (*major_version != 1)
        *exchange_type = SSH_IKE_XCHG_TYPE_IP;

      if (*major_version == 1
          && *exchange_type != SSH_IKE_XCHG_TYPE_AGGR
#ifdef SSHDIST_ISAKMP_CFG_MODE
          && *exchange_type != SSH_IKE_XCHG_TYPE_CFG
#endif /* SSHDIST_ISAKMP_CFG_MODE */
          && *exchange_type != SSH_IKE_XCHG_TYPE_IP
          && *exchange_type != SSH_IKE_XCHG_TYPE_INFO)
        {
          SSH_DEBUG(7, ("We are responder and this is initiators first packet,"
                        "but exchange type is not IP, AGGR, or INFO. "
                        "Packet ignored"));
          ssh_ike_audit_event(context->isakmp_context,
                          SSH_AUDIT_IKE_INVALID_EXCHANGE_TYPE,
                          SSH_AUDIT_SOURCE_ADDRESS_STR,
                              ike_ip_string(context->ip_address, n, sizeof(n)),
                          SSH_AUDIT_DESTINATION_ADDRESS_STR, remote_ip,
                          SSH_AUDIT_TXT,
                          "Invalid exchange type for the first packet",
                          SSH_AUDIT_ARGUMENT_END);
          return SSH_IKE_NOTIFY_MESSAGE_INVALID_EXCHANGE_TYPE;
        }

      /* Search if we have already seen the initiator cookie. */
      h = ssh_adt_get_handle_to_equal(context->isakmp_context->
                                      isakmp_cookie_mapping, p);

      if (h != SSH_ADT_INVALID)
        {
          /* Yes, use that SA. */
          *isakmp_sa_return =
            ssh_adt_map_lookup(context->isakmp_context->
                               isakmp_cookie_mapping, h);
          SSH_DEBUG(7,
                    ("We are the responder and the initiator resent "
                     "its first packet"));
          return 0;
        }
      /* This is new exchange. */
      SSH_DEBUG(7, ("We are responder and this is initiators first packet"));
      ike_cookie_create(context->isakmp_context, cookie);
      /* Allocate new SA, it will be in uninitialized state. */
      *isakmp_sa_return = ike_sa_allocate(context, p, cookie);
      if (*isakmp_sa_return)
        {
          /* Insert the initiator cookie to the initiator mapping, so that if
             the initiator resends its first packet we will find the proper SA
             for it too. */
          h = ssh_adt_put(context->isakmp_context->isakmp_cookie_mapping,
                          (*isakmp_sa_return)->cookies.initiator_cookie);
          SSH_ASSERT(h != SSH_ADT_INVALID);
          ssh_adt_map_attach(context->isakmp_context->
                             isakmp_cookie_mapping, h,
                             *isakmp_sa_return);
          return 0;
        }
      SSH_DEBUG(3, ("ike_sa_allocate failed"));
      return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
    }

  /* Then search for the IKE sa from the based on the cookie. */

  *isakmp_sa_return = ike_sa_find(context->isakmp_context, p,
                                  p + SSH_IKE_COOKIE_LENGTH);

  /* Was it valid IKE SA? */
  if (*isakmp_sa_return != NULL)
    /* Yes, return it. */
    return 0;

  /* We didn't find the SA by searching the cookies. */

  /* Perhaps we are the initiator and this is the first reply packet from the
     responder to us, i.e we have only half cookie SA for this. Search
     for that. */

  *isakmp_sa_return = ike_sa_find_half(context->isakmp_context, p);
  if (*isakmp_sa_return != NULL)
    {
      /* Yes, this was half SA upgrade it to full sa */
      SSH_DEBUG(7, ("We are intiator, first response packet"));
      *isakmp_sa_return = ike_sa_upgrade(context->isakmp_context,
                                         *isakmp_sa_return,
                                         p + SSH_IKE_COOKIE_LENGTH);
      return 0;
    }

  SSH_DEBUG(3, ("Invalid cookie, no sa found, "
                "SA = { %08lx %08lx - %08lx %08lx } / %08lx, remote = %s:%s",
                (unsigned long)
                SSH_IKE_GET32(p),
                (unsigned long)
                SSH_IKE_GET32(p + 4),
                (unsigned long)
                SSH_IKE_GET32(p + 8),
                (unsigned long)
                SSH_IKE_GET32(p + 12),
                (unsigned long)
                *message_id, remote_ip, remote_port));
  ssh_ike_audit_event(context->isakmp_context,
                      SSH_AUDIT_IKE_INVALID_COOKIE,
                      SSH_AUDIT_SOURCE_ADDRESS_STR,
                      ike_ip_string(context->ip_address, n, sizeof(n)),
                      SSH_AUDIT_DESTINATION_ADDRESS_STR, remote_ip,
                      SSH_AUDIT_ARGUMENT_END);
  return SSH_IKE_NOTIFY_MESSAGE_INVALID_COOKIE;
}

void ssh_ike_wire_negotiation(SshIkeNegotiation negotiation)
{
  if (negotiation->sa->isakmp_negotiation == negotiation)
    negotiation->sa->wired = 1;
}

void ssh_ike_unwire_negotiation(SshIkeNegotiation negotiation)
{
  if (negotiation->sa->isakmp_negotiation == negotiation)
    negotiation->sa->wired = 0;
}


Boolean
ssh_isakmp_update_responder_cookie(SshIkeNegotiation negotiation,
                                   const unsigned char *ike_spi_r)
{
  SshIkeServerContext context;
  SshIkeSA removed_sa;
  SshIkeSA sa;
  SshIkeContext isakmp_context;
  SshADTHandle h;

  /* Check if negotiation has been deleted and ignore this call. */
  if (negotiation->ed == NULL
      || negotiation->ed->current_state == SSH_IKE_ST_DELETED)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Negotiation has been deleted"));
      return FALSE;
    }

  sa = negotiation->sa;
  context = sa->server_context;
  isakmp_context = context->isakmp_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Updating responder IKE cookie"));
  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("Original IKE cookie"),
                    sa->cookies.responder_cookie,
                    SSH_IKE_COOKIE_LENGTH);
  SSH_DEBUG_HEXDUMP(SSH_D_MIDOK, ("New IKE cookie"),
                     ike_spi_r, SSH_IKE_COOKIE_LENGTH);

  h = ssh_adt_get_handle_to_equal(isakmp_context->isakmp_sa_mapping,
                                  &(sa->cookies));
  if (h != SSH_ADT_INVALID)
    {
      removed_sa = ssh_adt_map_lookup(isakmp_context->isakmp_sa_mapping, h);
      SSH_ASSERT(removed_sa == sa);
      ssh_adt_delete(isakmp_context->isakmp_sa_mapping, h);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("No isakmp_sa found"));
      return FALSE;
    }

  memcpy(sa->cookies.responder_cookie, ike_spi_r, SSH_IKE_COOKIE_LENGTH);

  h = ssh_adt_get_handle_to_equal(isakmp_context->isakmp_sa_mapping,
                                  &(sa->cookies));

  /* Check if such SA already found */
  if (h != SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Update failed, SPI already in use"));
      ike_sa_delete(isakmp_context, sa);
      return FALSE;
    }
  h = ssh_adt_put(isakmp_context->isakmp_sa_mapping, &(sa->cookies));
  SSH_ASSERT(h != SSH_ADT_INVALID);
  ssh_adt_map_attach(isakmp_context->isakmp_sa_mapping, h, sa);
  return TRUE;
}
