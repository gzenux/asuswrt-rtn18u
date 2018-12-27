/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code to handle Ikev1 NAT-Traversal.

   References:

    RFC3947                            Negotiation of NAT-Traversal in the IKE
    draft-ietf-ipsec-nat-t-ike-02      Negotiation of NAT-Traversal in the IKE
    draft-ietf-ipsec-nat-t-ike-03      Negotiation of NAT-Traversal in the IKE

   These specifications are not supported:

    draft-stenberg-ipsec-nat-traversal-{01-02} IPsec NAT-Traversal
       - Old SSH NAT-T draft

    draft-ietf-ipsec-nat-t-ike-01      Negotiation of NAT-Traversal in the IKE
       - No port floating

    draft-ietf-ipsec-nat-t-ike-{04-08} Negotiation of NAT-Traversal in the IKE
       - No vendor ID hash defined
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "isakmp_internal.h"
#include "ikev2-fb.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIkev2Fallback"

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL

/* Constants for the `Negotiation of NAT-Traversal in the IKE' drafts. */

#define SSH_IKEV2_FB_PRIVATE_PAYLOAD_TYPE_UNIFIED_NAT_D       130
#define SSH_IKEV2_FB_PRIVATE_PAYLOAD_TYPE_UNIFIED_NAT_OA      131

#define SSH_IKEV2_FB_NAT_ID_HASH_CONTENT_LENGTH         \
  (2 * SSH_IKE_COOKIE_LENGTH + SSH_IPH6_ADDRLEN + 2)

/* Constants for RFC3947 are in isakmp_doi.h */

/* Mask for all NAT-T method flags */
#define SSH_IKEV2_FB_IKE_NAT_T_VID_MASK \
  (SSH_IKEV2_FB_IKE_NAT_T_RFC3947 | SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)


/******************** Utility functions *************************************/

void
ikev2_fb_ike_float_free(SshIkev2FbNatTInfo ike_float)
{
  if (ike_float)
    ssh_free(ike_float);
}

/******************** Handling NAT-T VIDs ***********************************/

struct SshIkev2FbNatTVendorIdRec
{
  const char *description;
  const char *vendor_id;
  size_t vendor_id_len;
  SshUInt32 flag_value;
};

/* From util_compat.c */
const
static struct SshIkev2FbNatTVendorIdRec nat_t_vids[] =
{
  { "RFC 3947",
    "\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f",
    16, SSH_IKEV2_FB_IKE_NAT_T_RFC3947 },

  { "draft-ietf-ipsec-nat-t-ike-03",
    "\x7d\x94\x19\xa6\x53\x10\xca\x6f\x2c\x17\x9d\x92\x15\x52\x9d\x56",
    16, SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT },

  { "draft-ietf-ipsec-nat-t-ike-02",
    "\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f",
    16, SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT },

  { "draft-ietf-ipsec-nat-t-ike-02",
    "\xcd\x60\x46\x43\x35\xdf\x21\xf8\x7c\xfd\xb2\xfc\x68\xb6\xa4\x48",
    16, SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT }
};

static SshUInt32
ikev2_fb_check_natt_vendor_id(const unsigned char *vendor_id,
                              size_t vendor_id_len)
{
  int i;

  for (i = 0; i < (sizeof(nat_t_vids) / sizeof(nat_t_vids[0])); i++)
    {
      if (vendor_id_len == nat_t_vids[i].vendor_id_len &&
          memcmp(nat_t_vids[i].vendor_id, vendor_id, vendor_id_len) == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("NAT-T vendor id [%s]",
                     nat_t_vids[i].description));
          return nat_t_vids[i].flag_value;
        }
    }

  return 0;
}

/* Check received Ikev1 NAT-T vendor IDs.
   Called from ikev2_fb_isakmp_vendor_id */
void ikev2_fb_check_recvd_natt_vendor_id(SshIkev2FbNegotiation neg,
                                         const unsigned char *vendor_id,
                                         size_t vendor_id_len)
{
  SshUInt32 recvd_vid;
  int i;

  /* Nothing to do for responder */
  if ((neg->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0)
    return;

  /* Parse and store received NATT vendor id's */
  recvd_vid = ikev2_fb_check_natt_vendor_id(vendor_id, vendor_id_len);
  if (recvd_vid == 0)
    return;

  /* Check that the selected NATT vendor id was in the set of proposed
     vendor id's */
  for (i = 0; i < neg->num_vendor_ids; i++)
    {
      if (vendor_id_len == neg->vendor_id_lens[i]
          && memcmp(vendor_id, neg->vendor_ids[i], vendor_id_len) == 0)
        {
          neg->ike_sa->flags |= recvd_vid;
          break;
        }
    }
  if (i == neg->num_vendor_ids)
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Responder sent a NATT vendor id that was not proposed by "
                 "the initiator"));
      return;
    }

  /* Prefer _RFC3947 over _IETF_DRAFT */
  if ((neg->ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_RFC3947) != 0
      && (neg->ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_VID_MASK)
      != SSH_IKEV2_FB_IKE_NAT_T_RFC3947)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Multiple NAT-T vendor id's selected, "
                 "preferring RFC3947"));
      neg->ike_sa->flags &= ~SSH_IKEV2_FB_IKE_NAT_T_VID_MASK;
      neg->ike_sa->flags |= SSH_IKEV2_FB_IKE_NAT_T_RFC3947;
    }
}

/* Check sent Ikev1 NAT-T vendor IDs.
   Called from ikev2_fb_isakmp_vendor_id */
void ikev2_fb_check_sent_natt_vendor_ids(SshIkev2FbNegotiation neg)
{
  int i;
  SshUInt32 sent_vid;

  /* Nothing to do for initiator */
  if ((neg->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) != 0)
    return;

  /* On responder, check what NATT vids were sent back to initiator,
     that is check what NATT vid was selected. */
  neg->ike_sa->flags &= ~SSH_IKEV2_FB_IKE_NAT_T_VID_MASK;
  for (i = 0; i < neg->num_vendor_ids; i++)
    {
      sent_vid = ikev2_fb_check_natt_vendor_id(neg->vendor_ids[i],
                                               neg->vendor_id_lens[i]);
      if (sent_vid != 0)
        neg->ike_sa->flags |= sent_vid;
    }

  /* Prefer _RFC3947 over _IETF_DRAFT */
  if ((neg->ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_RFC3947) != 0
      && (neg->ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_VID_MASK)
      != SSH_IKEV2_FB_IKE_NAT_T_RFC3947)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Multiple NAT-T vendor id's selected, "
                 "preferring RFC3947"));
      neg->ike_sa->flags &= ~SSH_IKEV2_FB_IKE_NAT_T_VID_MASK;
      neg->ike_sa->flags |= SSH_IKEV2_FB_IKE_NAT_T_RFC3947;
    }
}


/******************** Handling pending NAT-T operations *********************/

static void
ikev2_fb_change_ike_server(SshIkev2Sa ike_sa,
                           SshIkev2ExchangeData ed,
                           SshIkev2FbNatTInfo ike_float)
{
  SshIkeNegotiation negotiation;
  unsigned char *remote_ip;
  unsigned char *remote_port;
  unsigned char new_remote_ip[SSH_IP_ADDR_STRING_SIZE];
  unsigned char new_remote_port[6];
  SshUInt32 *server_flags;

  negotiation = ike_sa->v1_sa;

  SSH_DEBUG(SSH_D_LOWSTART, ("Start ike_sa %p negotiation %p",
                             ike_sa, negotiation));

  /* Sanity checks */

  SSH_ASSERT(ike_float != NULL && ike_float->server != NULL);

  /* Check if peer supports NAT-T */
  if ((ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_VID_MASK) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Peer does not support NAT-T"));
      goto out;
    }

  /* Get pointers to server flags, and old remote address and port */
  switch (negotiation->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_INFO:
      remote_ip = negotiation->info_pm_info->remote_ip;
      remote_port = negotiation->info_pm_info->remote_port;
      server_flags = &negotiation->info_pm_info->server_flags;
      break;

    case SSH_IKE_XCHG_TYPE_NGM:
      remote_ip = negotiation->ngm_pm_info->remote_ip;
      remote_port = negotiation->ngm_pm_info->remote_port;
      server_flags = &negotiation->ngm_pm_info->server_flags;
      break;

#ifdef SSHDIST_ISAKMP_CFG_MODE
    case SSH_IKE_XCHG_TYPE_CFG:
      remote_ip = negotiation->cfg_pm_info->remote_ip;
      remote_port = negotiation->cfg_pm_info->remote_port;
      server_flags = &negotiation->cfg_pm_info->server_flags;
      break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

    case SSH_IKE_XCHG_TYPE_QM:
      remote_ip = negotiation->qm_pm_info->remote_ip;
      remote_port = negotiation->qm_pm_info->remote_port;
      server_flags = &negotiation->qm_pm_info->server_flags;
      break;

    case SSH_IKE_XCHG_TYPE_IP:
    case SSH_IKE_XCHG_TYPE_AGGR:
      remote_ip = negotiation->ike_pm_info->remote_ip;
      remote_port = negotiation->ike_pm_info->remote_port;
      server_flags = &negotiation->ike_pm_info->server_flags;
      break;

    default:
      ssh_fatal("Internal error: Unknown exchange type in the "
                "negotiation->exchange_type.");
      SSH_NOTREACHED;
      return;
    }

  /* Convert new address and port to string format */
  ssh_ipaddr_print(&ike_float->remote_ip, new_remote_ip,
                   sizeof(new_remote_ip));
  ssh_snprintf(ssh_sstr(new_remote_port), sizeof(new_remote_port),
               "%d", ike_float->remote_port);

#ifdef DEBUG_LIGHT
  /* Debug */
  {
    char options[256];
    char who[32];
    int i;

    options[0] = '\0';
    for (i = 0; i < (sizeof(nat_t_vids) / sizeof(nat_t_vids[0])); i++)
      {
        if (ike_sa->flags & nat_t_vids[i].flag_value)
          {
            strncat(options, nat_t_vids[i].description, 255);
            break;
          }
      }

    who[0] = '\0';
    strcat(who, "neither end");
    if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
      {
        who[0] = '\0';
        strcat(who, "remote");
        if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
          strcat(who, " and local");
      }
    else if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
      {
        who[0] = '\0';
        strcat(who, "local");
      }

    SSH_DEBUG(SSH_D_LOWOK, ("Using %s: %s behind NAT",
                            options, who));
  }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Floating IKE port: local %@:%d->%@:%d, remote %s:%s->%s:%s",

             ssh_ipaddr_render, &ike_sa->server->ip_address,
             negotiation->sa->use_natt ?
             negotiation->sa->server_context->nat_t_local_port :
             negotiation->sa->server_context->normal_local_port,

             ssh_ipaddr_render, &ike_float->server->ip_address,
             ike_float->use_natt ?
             ike_float->server->nat_t_local_port :
             ike_float->server->normal_local_port,

             remote_ip, remote_port,

             new_remote_ip, new_remote_port));
#endif /* DEBUG_LIGHT */

  /* Float IKE SA's ports, but only if new ones differ from the old ones */
  if (negotiation->sa->server_context != ike_float->server ||
      (negotiation->sa->use_natt != ike_float->use_natt) ||
      ssh_inet_ip_address_compare(remote_ip, new_remote_ip) != 0 ||
      ssh_inet_port_number_compare(remote_port, new_remote_port,
                                   ssh_custr("udp")) != 0)
    {
      *server_flags &= ~SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT;
      if (ike_float->use_natt)
        *server_flags |= SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT;

      if (!ssh_ike_sa_change_server(negotiation,
                                    ike_float->server,
                                    new_remote_ip,
                                    new_remote_port))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IKE port floating failed"));
          goto out;
        }

      /* Update IKEv1 SA info also */
      server_flags =
        &negotiation->sa->isakmp_negotiation->ike_pm_info->server_flags;
      *server_flags &= ~SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT;
      if (ike_float->use_natt)
        *server_flags |= SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT;

      if (!ssh_ike_sa_change_server(negotiation->sa->isakmp_negotiation,
                                    ike_float->server,
                                    new_remote_ip,
                                    new_remote_port))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IKE SA port floating failed"));
          goto out;
        }
    }

  /* Update float info to IKEv2 SA */
  /* Update server info here */
  if (ike_float->use_natt)
    ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE;

  ike_sa->server = (SshIkev2Server) ike_float->server;

  /* Check if the source ip or port has changed and either 1) port float is
     done and one end is behind NAT or 2) IKE SA is using TCP encapsulation. */
  if (((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) &&
       (ike_sa->flags & (SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT |
                         SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)))
      || (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP))
    {
      if (ike_sa->remote_port != ike_float->remote_port ||
          SSH_IP_CMP(ike_sa->remote_ip, &ike_float->remote_ip) != 0)
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("FB; Calling v2 policy function ipsec_sa_update"));
          (*ike_sa->server->sad_interface->ipsec_sa_update)
            (ike_sa->server->sad_handle,
             ed,
             &ike_float->remote_ip,
             ike_float->remote_port);
        }
    }

 out:
  /* Clear float info */
  ike_float->server = NULL;
}


void
ikev2_fb_phase1_pending_natt_operations(SshIkev2FbNegotiation neg)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Processing pending NAT-T operations"));

  /* Check if NAT has been detected */
  if (neg->ike_float.server == NULL)
    return; /* Not detected, all done */

  ikev2_fb_change_ike_server(neg->ike_sa, neg->ed, &neg->ike_float);
}


void
ikev2_fb_qm_pending_natt_operations(SshIkev2FbNegotiation neg)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Processing pending NAT-T operations"));

  /* Check if NAT has been detected */
  if (neg->ike_float.server == NULL)
    return; /* Not detected, all done */

  /* Check if the other peer has floated its port. */
  ikev2_fb_change_ike_server(neg->ike_sa, neg->ed, &neg->ike_float);
}

void
ikev2_fb_phase_ii_pending_natt_operations(SshIkev2Sa ike_sa,
                                          SshIkev2ExchangeData ed,
                                          SshIkev2FbNatTInfo ike_float)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Processing pending NAT-T operations"));

  /* Check if NAT has been detected */
  if (!ike_float || !ike_float->server)
    return;

  /* Check if the other peer has floated its port. */
  ikev2_fb_change_ike_server(ike_sa, ed, ike_float);
}

/***************** Private payload handlers for IKE Phase-1 *****************/

static Boolean
ikev2_fb_private_p_1_check(SshIkePMPhaseI pm_info,
                           int private_payload_id,
                           void *private_payload_context)
{
  SSH_DEBUG(SSH_D_LOWSTART,
            ("New Phase-I private payload: private_payload_id %d",
             private_payload_id));

  /* Check that this is a known private payload ID. */
  switch (private_payload_id)
    {
    case SSH_IKE_PRIVATE_PAYLOAD_TYPE_NAT_D:
      SSH_DEBUG(SSH_D_LOWOK, ("RFC 3947 NAT-D payload"));
      break;

    case SSH_IKEV2_FB_PRIVATE_PAYLOAD_TYPE_UNIFIED_NAT_D:
      SSH_DEBUG(SSH_D_LOWOK, ("Unified NAT-T draft NAT-D payload"));
      break;

    default:
      SSH_DEBUG(SSH_D_LOWOK, ("Unknown payload ID"));
      return FALSE;
    }

  return TRUE;
}

/* Create payload which has the specific IP address + port encoded
   within using the Phase I specified (to obtain cookies).

   The 'encoding' is HASH(CKY-I | CKY-R | IP | Port).

   Input: PMPhaseI, IP address, and port to be hashed
   Output: (in *result) hashed string, length of hashed part (in
           result_len_return)
   The function returns a boolean success status. */
static Boolean
ikev2_fb_id_as_hashed_string(SshIkePMPhaseI pm_info, SshIpAddr ip,
                             SshUInt16 port, unsigned char *result,
                             size_t *result_len_return)
{
  unsigned char buf[SSH_IKEV2_FB_NAT_ID_HASH_CONTENT_LENGTH];
  size_t len = 0;
  SshIkeStatisticsStruct statistics;
  SshHash hash;

  SSH_DEBUG(SSH_D_LOWSTART, ("Start ip = %@ port = %d",
                          ssh_ipaddr_render, ip, port));

  /* Add cookies to the hash source. */

  memcpy(buf + len, pm_info->cookies->initiator_cookie, SSH_IKE_COOKIE_LENGTH);
  len += SSH_IKE_COOKIE_LENGTH;

  memcpy(buf + len, pm_info->cookies->responder_cookie, SSH_IKE_COOKIE_LENGTH);
  len += SSH_IKE_COOKIE_LENGTH;

  /* Add address. */
  if (SSH_IP_IS4(ip))
    SSH_IP4_ENCODE(ip, buf + len);
  else
    SSH_IP6_ENCODE(ip, buf + len);
  len += SSH_IP_ADDR_LEN(ip);

  /* Add port number. */
  SSH_PUT_16BIT(buf + len, port);
  len += 2;

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Hash input:"), buf, len);

  /* Get IKE hash algorithm. */
  if (ssh_ike_isakmp_sa_statistics(pm_info->negotiation, &statistics)
      != SSH_IKE_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not get IKE statistics"));
      return FALSE;
    }
  /* NOTE: temporary casts until library API is changed */
  if (ssh_hash_allocate(ssh_csstr(statistics.hash_algorithm_name), &hash)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate hash algorithm `%s'",
                              statistics.hash_algorithm_name));
      return FALSE;
    }

  ssh_hash_reset(hash);
  ssh_hash_update(hash, buf, len);
  ssh_hash_final(hash, result);
  /* NOTE: temporary casts until library API is changed */
  *result_len_return =
    ssh_hash_digest_length(ssh_csstr(statistics.hash_algorithm_name));

  ssh_hash_free(hash);
  SSH_ASSERT(*result_len_return <= SSH_MAX_HASH_DIGEST_LENGTH);

  return TRUE;
}

/* Detect whether there is NAT in the path between initiator and
   responder.  The function updates the information into the SshIkev2Sa
   of the negotiation `neg'. */
static void
ikev2_fb_natt_hash_choice(SshIkev2FbNegotiation neg,
                          unsigned char *data,
                          size_t data_len)
{
  SshIkev2Sa ike_sa;
  SshIpAddrStruct addr;
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t buf_len;
  SshIpAddrStruct remote_ip;
  SshUInt16 remote_port;
  SshUInt16 local_port;

  ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_LOWSTART, ("Start ike_sa %p (neg %p)", ike_sa, neg));

  /* Resolve remote IP and port number and local IKE port. */
  if (neg->ike_float.server)
    {
      /* IKE server has floated. */

      /* Remote IP and port. */
      remote_ip = neg->ike_float.remote_ip;
      remote_port = neg->ike_float.remote_port;

      /* Resolve local port. */
      if (neg->ike_float.server->forced_nat_t_enabled == TRUE)
        local_port = 0;
      else if (neg->ike_float.use_natt)
        local_port = neg->ike_float.server->nat_t_local_port;
      else
        local_port = neg->ike_float.server->normal_local_port;
    }
  else
    {
      /* IKE server has not floated. */

      SSH_VERIFY(ssh_ipaddr_parse(&remote_ip, neg->p1_info->remote_ip));
      remote_port = (SshUInt16) ssh_uatoi(neg->p1_info->remote_port);

      /* Resolve local port. */
      if (ike_sa->server->forced_nat_t_enabled == TRUE)
        local_port = 0;
      else
        local_port = (SshUInt16) ssh_uatoi(neg->p1_info->local_port);
    }

  /* Find out if there is a NAT between us and the remote party by
     comparing the addresses. */

  if (neg->nat_d_state == SSH_IKEV2_FB_NAT_D_STATE_LOCAL)
    {
      /* The first payload. */
      SSH_DEBUG(SSH_D_LOWOK, ("First payload: checking local ID"));

      /* Init everything for detecting the NAT. */
      neg->nat_d_state = SSH_IKEV2_FB_NAT_D_STATE_REMOTE;
      ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT;
      ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT;

      /* If the hash is not hash of a local address, we have our
         answer. */
      SSH_VERIFY(ssh_ipaddr_parse(&addr, neg->p1_info->local_ip));

      if (!ikev2_fb_id_as_hashed_string(neg->p1_info, &addr, local_port,
                                        buf, &buf_len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not compute ID hash"));
        }
      else
        {
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("ID hash:"), buf, buf_len);
          if (buf_len != data_len)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Different lengths"));
            }
          else
            {
            if (memcmp(data, buf, buf_len) == 0)
              {
                ike_sa->flags &= ~SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT;
              }
            }

          if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
            SSH_DEBUG(SSH_D_LOWOK, ("Local end behind NAT"));
          else
            SSH_DEBUG(SSH_D_LOWOK, ("Local end not behind NAT"));
        }
    }
  else
    {
      /* Nth payload. */
      SSH_DEBUG(SSH_D_LOWOK, ("Not first payload: checking remote ID"));

      /* Get remote identity hash */
      if (!ikev2_fb_id_as_hashed_string(neg->p1_info, &remote_ip, remote_port,
                                        buf, &buf_len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not compute ID hash"));
        }
      else
        {
          SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("ID hash:"), buf, buf_len);
          if (buf_len != data_len)
            SSH_DEBUG(SSH_D_FAIL, ("Different lengths"));
          else
            {
              if (memcmp(data, buf, data_len) == 0)
                {
                  ike_sa->flags
                    &= ~SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT;
                }
            }

          if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
            SSH_DEBUG(SSH_D_LOWOK, ("Remote end behind NAT"));
          else
            SSH_DEBUG(SSH_D_LOWOK, ("Remote end not behind NAT"));
        }
    }
}

static void
ikev2_fb_private_p_1_in(SshIkePMPhaseI pm_info,
                        int packet_number,
                        int private_payload_id,
                        unsigned char *data,
                        size_t data_len,
                        void *private_payload_context)
{
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa;
  SshUInt32 nat_d_type;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    return;

  ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Phase-I input: packet_number %d ike_sa %p (neg %p)",
             packet_number, ike_sa, neg));

  /* This is only done in main/aggressive mode. */
  if (pm_info->exchange_type != SSH_IKE_XCHG_TYPE_IP
      && pm_info->exchange_type != SSH_IKE_XCHG_TYPE_AGGR)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("NAT traversal only supported on main and aggressive modes"));
      return;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("New payload: packet_number=%d, private_payload_id=%d:",
                     packet_number, private_payload_id),
                    data, data_len);

  /* Both parties need to be consenting in order for the packets to be
     sent. We are consenting by default (i.e. if policy allows it),
     and the remote party consents iff we have received vendor ID
     payload from them. */
  if ((ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_VID_MASK) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("The remote peer does not support NAT-T"));
      return;
    }
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("NAT traversal disabled by policy"));
      return;
    }

  /* Verify that the remote peer is using correct numbers for the NAT-T. */
  if (ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_RFC3947)
    nat_d_type = SSH_IKE_PRIVATE_PAYLOAD_TYPE_NAT_D;
  else if (ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)
    nat_d_type = SSH_IKEV2_FB_PRIVATE_PAYLOAD_TYPE_UNIFIED_NAT_D;
  else
    nat_d_type = private_payload_id + 1; /* Just make sure they dont match */

  if (private_payload_id != nat_d_type)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid NAT-D type: expected %u, got %u",
                             (unsigned int) nat_d_type, private_payload_id));
      return;
    }

  /* Check what we should do with the NAT traversal. */
  if (pm_info->exchange_type == SSH_IKE_XCHG_TYPE_AGGR)
    {
      /* Check if the NAT traversal is needed. */
      switch (packet_number)
        {
        case 2: /* Client */
        case 3: /* Server */
          ikev2_fb_natt_hash_choice(neg, data, data_len);
          break;
        }
    }
  else
    {
      /* Check if the NAT traversal is needed. */
      switch (packet_number)
        {
        case 3:                 /* Server. */
        case 4:                 /* Client. */
          ikev2_fb_natt_hash_choice(neg, data, data_len);
          break;
        }
    }
}


/* Do the IKE port floating as an IKE SA initiator. */
static void
ikev2_fb_initiator_float_ike_server(SshIkev2FbNegotiation neg)
{
  SshIkev2Sa ike_sa;
  unsigned char remote_port[8];

  ike_sa = neg->ike_sa;

  SSH_ASSERT(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR);

  if ((ike_sa->flags & (SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT
                        | SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT))
      && (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) == 0)
    {
      SshIkeServerContext server = (SshIkeServerContext) neg->ike_sa->server;
      SSH_DEBUG(SSH_D_LOWOK, ("Floating IKE ports"));
      ssh_snprintf(ssh_sstr(remote_port), sizeof(remote_port),
                   "%d", server->nat_t_remote_port);
      neg->p1_info->server_flags |= SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT;
      if (!ssh_ike_sa_change_server(neg->p1_info->negotiation,
                                    server,
                                    neg->p1_info->remote_ip,
                                    remote_port))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IKE port floating failed"));
          return;
        }

      /* Update port float to IKEv2 SA */
      ike_sa->remote_port = server->nat_t_remote_port;
      ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE;
    }
}

/* Send NAT-D private payloads. */
static void
ikev2_fb_handle_send_hash_id(SshIkev2FbNegotiation neg,
                             SshPolicyPrivatePayloadOutCB policy_callback,
                             void *policy_context)
{
  SshIkev2Sa ike_sa;
  SshIpAddrStruct addr;
  unsigned char buf[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t buf_len;
  int nat_d_type;
  SshUInt16 local_port;

  ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_LOWSTART, ("Adding NAT-D payloads: ike_sa %p (neg %p)",
                             ike_sa, neg));

  /* Resolve the type of the NAT-D payload. */
  if (ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_RFC3947)
    nat_d_type = SSH_IKE_PRIVATE_PAYLOAD_TYPE_NAT_D;
  else if (ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)
    nat_d_type = SSH_IKEV2_FB_PRIVATE_PAYLOAD_TYPE_UNIFIED_NAT_D;
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown NAT-T method"));
      return;
    }

  /* First, append the remote identity. */
  SSH_VERIFY(ssh_ipaddr_parse(&addr, neg->p1_info->remote_ip));
  if (!ikev2_fb_id_as_hashed_string(neg->p1_info, &addr,
                                    (SshUInt16)
                                    ssh_uatoi(neg->p1_info->remote_port),
                                    buf, &buf_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not compute ID hash"));
      return;
    }
  (*policy_callback)(nat_d_type, buf, buf_len, policy_context);

  /* Resolve local port. */
  if (ike_sa->server->forced_nat_t_enabled == TRUE)
    local_port = 0;
  else
    local_port = (SshUInt16) ssh_uatoi(neg->p1_info->local_port);

  /* Then, append local identity. */
  SSH_VERIFY(ssh_ipaddr_parse(&addr, neg->p1_info->local_ip));
  if (!ikev2_fb_id_as_hashed_string(neg->p1_info, &addr,
                                    local_port,
                                    buf, &buf_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not compute ID hash"));
      return;
    }
  (*policy_callback)(nat_d_type, buf, buf_len, policy_context);
}

static void
ikev2_fb_private_p_1_out(SshIkePMPhaseI pm_info,
                         int packet_number,
                         SshPolicyPrivatePayloadOutCB policy_callback,
                         void *policy_context,
                         void *private_payload_context)
{
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    return;

  ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Phase-I output: packet_number %d ike_sa %p (neg %p)",
             packet_number, ike_sa, neg));

  /* Handle pending Phase-1 NAT-T operations. */
  ikev2_fb_phase1_pending_natt_operations(neg);

  /* Both parties need to be consenting in order for the packets to be
     sent. We are consenting by default (i.e. if policy allows it),
     and the remote party consents iff we have received vendor ID
     payload from them. */
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("NAT traversal disabled by policy"));
      goto out;
    }
  if ((ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_VID_MASK) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Remote end does not support NAT-T "
                              "(or Vendor IDs not received yet)"));
      goto out;
    }

  /* This is only done in main/aggressive mode. */
  if (!(pm_info->exchange_type == SSH_IKE_XCHG_TYPE_IP
        || pm_info->exchange_type == SSH_IKE_XCHG_TYPE_AGGR))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown exchange type %d",
                             pm_info->exchange_type));
      goto out;
    }

  switch (pm_info->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_AGGR:
      switch (packet_number)
        {
        case 3:             /* Initiator -> responder, last packet. */
          /* Initiator floats its IKE port for the last packet of the
             aggressive mode.  Do it now. */
          ikev2_fb_initiator_float_ike_server(neg);

          /* And send the hash IDs. */
          /* FALLTHROUGH */

        case 2:             /* Responder -> initiator, last packet. */
          ikev2_fb_handle_send_hash_id(neg, policy_callback, policy_context);
          break;
        }
      break;

    case SSH_IKE_XCHG_TYPE_IP:
      switch (packet_number)
        {
        case 3:                 /* Initiator -> responder. */
        case 4:                 /* Responder -> initiator. */
          ikev2_fb_handle_send_hash_id(neg, policy_callback, policy_context);
          break;

        case 5:                 /* Initiator -> responder. */

          /* Initiator floats its IKE port for its last packet of the
             main mode.  Do it now. */
          ikev2_fb_initiator_float_ike_server(neg);
          break;

        }
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

 out:
  /* A callback with zero ID terminates the list. */
  (*policy_callback)(0, NULL, 0, policy_context);
}

/*************** Private payload handlers for IKE Phase 2 *******************/

static Boolean
ikev2_fb_private_p_ii_check(SshIkePMPhaseII pm_info,
                            int private_payload_id,
                            void *private_payload_context)
{
  SSH_DEBUG(SSH_D_LOWSTART,
            ("Phase-II check: payload_id %d (neg %p)",
             private_payload_id, pm_info->policy_manager_data));

  return TRUE;
}

static void
ikev2_fb_private_p_ii_in(SshIkePMPhaseII pm_info,
                         int packet_number,
                         int private_payload_id,
                         unsigned char *data,
                         size_t data_len,
                         void *private_payload_context)
{
  SSH_DEBUG(SSH_D_LOWSTART,
            ("Phase-II input: packet_number %d (neg %p)",
             packet_number, pm_info->policy_manager_data));
}

static void
ikev2_fb_private_p_ii_out(SshIkePMPhaseII pm_info,
                          int packet_number,
                          SshPolicyPrivatePayloadOutCB policy_callback,
                          void *policy_context,
                          void *private_payload_context)
{
  SshIkev2FbNegotiation neg =
    (SshIkev2FbNegotiation) pm_info->policy_manager_data;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Phase-II output: packet_number %d (neg %p)",
             packet_number, neg));

  if (neg == NULL || neg->aborted)
    goto out;

  /* NOTE: Call phase 1 function, since it does the same thing as
     phase_ii_pending_natt_operations, but takes suitable parameters. */
  ikev2_fb_phase1_pending_natt_operations(neg);

 out:
  (*policy_callback)(0, NULL, 0, policy_context);
}

/*************** Private payload handlers for IKE Quick-Mode ****************/

static Boolean
ikev2_fb_private_p_qm_check(SshIkePMPhaseQm pm_info,
                            int private_payload_id,
                            void *private_payload_context)
{
  SshIkev2Sa ike_sa;
  SshIkev2FbNegotiation neg;

  neg = SSH_IKEV2_FB_QM_GET_P1_NEGOTIATION(pm_info);
  if (neg == NULL)
    return FALSE;

  ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Phase-QM check: payload_id %d ike_sa %p (neg %p)",
             private_payload_id, ike_sa, neg));

  /* Check that this is a known private payload ID. */
  switch (private_payload_id)
    {
    case SSH_IKE_PRIVATE_PAYLOAD_TYPE_NAT_OA:
      SSH_DEBUG(SSH_D_LOWOK, ("RFC 3947 NAT-OA payload"));
      break;

    case SSH_IKEV2_FB_PRIVATE_PAYLOAD_TYPE_UNIFIED_NAT_OA:
      SSH_DEBUG(SSH_D_LOWOK, ("Unified NAT-T draft NAT-OA payload"));
      break;

    default:
      SSH_DEBUG(SSH_D_LOWOK, ("Unknown payload ID"));
      return FALSE;
    }

  if ((ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_VID_MASK) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("NAT-T not agreed, NAT-OA rejected"));
      return FALSE;
    }

  return TRUE;
}

static void
ikev2_fb_private_p_qm_in(SshIkePMPhaseQm pm_info,
                         int packet_number,
                         int private_payload_id,
                         unsigned char *data,
                         size_t data_len,
                         void *private_payload_context)
{
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa;
  SshIpAddrStruct ip;
  SshIpAddr natt_oa_i, natt_oa_r;
#ifdef DEBUG_LIGHT
  char *what = "";
#endif /* DEBUG_LIGHT */

  neg = SSH_IKEV2_FB_QM_GET_P1_NEGOTIATION(pm_info);
  if (neg == NULL)
    return;

  ike_sa = neg->ike_sa;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Phase-QM input: packet_number %d ike_sa %p (neg %p)",
             packet_number, ike_sa, neg));

  /* Decode payload. */
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                    ("New payload: packet_number=%d, private_payload_id=%d:",
                     packet_number, private_payload_id),
                    data, data_len);

  data_len -= 4;
  data += 4;
  if (data_len == 4)
    {
      SSH_IP4_DECODE(&ip, data);
    }
  else if (data_len == 16)
    {
      SSH_IP6_DECODE(&ip, data);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid NAT-OA length %d", data_len));
      return;
    }

  /* Check that the negotiation contains a valid ipsec_ed. */
  if (neg->ed == NULL || neg->ed->ipsec_ed == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Negotiation does not have a valid ipsec_ed"));
      return;
    }

  /* Check what this address is. */
  if (ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_RFC3947)
    {
      /* RFC3947 implementations send NAT-OA payloads for both local and
         remote addresses, the first NAT-OA payload is the initiator's
         original address and the second the responder's original address.
         Store both addresses (if available). */

      if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          natt_oa_i = &neg->ed->ipsec_ed->natt_oa_l;
          natt_oa_r = &neg->ed->ipsec_ed->natt_oa_r;
        }
      else
        {
          natt_oa_i = &neg->ed->ipsec_ed->natt_oa_r;
          natt_oa_r = &neg->ed->ipsec_ed->natt_oa_l;
        }

      if (!SSH_IP_DEFINED(natt_oa_i))
        {
          *natt_oa_i = ip;
#ifdef DEBUG_LIGHT
          what = "i";
#endif /* DEBUG_LIGHT */
        }
      else if (!SSH_IP_DEFINED(natt_oa_r))
        {
          *natt_oa_r = ip;
#ifdef DEBUG_LIGHT
          what = "r";
#endif /* DEBUG_LIGHT */
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("NAT-OA{i,r} already received"));
          SSH_DEBUG(SSH_D_LOWOK, ("NAT-OAi %@ NAT-OAr %@ NAT-OA received %@",
                                  ssh_ipaddr_render, natt_oa_i,
                                  ssh_ipaddr_render, natt_oa_r,
                                  ssh_ipaddr_render, &ip));
          return;
        }
    }

  else if (ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)
    {
      /* IETF IKEv1 NAT-T draft implementations send only the local
         address as NAT-OA. Store the NAT-OA if the local end is not
         behind NAT, otherwise leave natt_oa_r undefined to indicate
         that incremental checksum updating cannot be used with the
         IPsec SA negotiated here. */
#ifdef DEBUG_LIGHT
      if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        what = "r";
      else
        what = "i";
#endif /* DEBUG_LIGHT */

      if (SSH_IP_DEFINED(&neg->ed->ipsec_ed->natt_oa_r))
        {
          SSH_DEBUG(SSH_D_FAIL, ("NAT-OA%s already received", what));
          SSH_DEBUG(SSH_D_LOWOK,
                    ("NAT-OA%s NAT-OA received %@",
                     what,
                     ssh_ipaddr_render, &neg->ed->ipsec_ed->natt_oa_r,
                     ssh_ipaddr_render, &ip));
          return;
        }

      if (neg->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Local end is behind NAT, ignoring received NAT-OA %@",
                     ssh_ipaddr_render, &ip));
          return;
        }

      neg->ed->ipsec_ed->natt_oa_r = ip;
    }

  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("NAT-T not agreed, NAT-OA %@ ignored",
                              ssh_ipaddr_render, &ip));
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Received NAT-OA%s `%@'",
                          what, ssh_ipaddr_render, &ip));
}

static void
ikev2_fb_handle_send_oa_ip(SshIkev2Sa ike_sa,
                           SshPolicyPrivatePayloadOutCB policy_callback,
                           void *policy_context,
                           const unsigned char *ip,
                           const unsigned char *what)
{
  SshIpAddrStruct addr;
  unsigned char buf[SSH_IP_ADDR_SIZE + 4]; /* IP address + 4 bytes of type. */
  size_t len;
  SshIkeIpsecIdentificationType type;
  int nat_oa_type;

  /* Build the NAT-OA payload. */
  memset(buf, 0, sizeof(buf));
  SSH_VERIFY(ssh_ipaddr_parse(&addr, ip));

  if (SSH_IP_IS4(&addr))
    {
      SSH_IP4_ENCODE(&addr, buf + 4);
      type = IPSEC_ID_IPV4_ADDR;
      len = 4 + 4;
    }
  else
    {
      SSH_IP6_ENCODE(&addr, buf + 4);
      type = IPSEC_ID_IPV6_ADDR;
      len = 4 + 16;
    }

  buf[0] = (unsigned char) type;

  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Sending NAT-OA%s `%@':",
                                   what,
                                   ssh_ipaddr_render, &addr),
                    buf, len);

  if (ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_RFC3947)
    nat_oa_type = SSH_IKE_PRIVATE_PAYLOAD_TYPE_NAT_OA;
  else if (ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)
    nat_oa_type = SSH_IKEV2_FB_PRIVATE_PAYLOAD_TYPE_UNIFIED_NAT_OA;
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown NAT-T method"));
      return;
    }

  (*policy_callback)(nat_oa_type, buf, len, policy_context);
}


static void
ikev2_fb_handle_send_oa(SshIkev2FbNegotiation neg,
                        SshPolicyPrivatePayloadOutCB policy_callback,
                        void *policy_context)
{
  if (neg->ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_RFC3947)
    {
      /* The initiator IP is sent first, followed by the responder IP. */
      if (neg->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          ikev2_fb_handle_send_oa_ip(neg->ike_sa,
                                     policy_callback, policy_context,
                                     neg->qm_info->local_ip, ssh_custr("i"));
          ikev2_fb_handle_send_oa_ip(neg->ike_sa,
                                     policy_callback, policy_context,
                                     neg->qm_info->remote_ip, ssh_custr("r"));
        }
      else
        {
          ikev2_fb_handle_send_oa_ip(neg->ike_sa,
                                     policy_callback, policy_context,
                                     neg->qm_info->remote_ip, ssh_custr("i"));
          ikev2_fb_handle_send_oa_ip(neg->ike_sa,
                                     policy_callback, policy_context,
                                     neg->qm_info->local_ip, ssh_custr("r"));
        }
    }
  else if (neg->ike_sa->flags & SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT)
    {
      /* Send local IP. */
      ikev2_fb_handle_send_oa_ip(neg->ike_sa, policy_callback, policy_context,
                                 neg->qm_info->local_ip,
                                 (neg->ike_sa->flags &
                                  SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
                                 ssh_custr("i") : ssh_custr("r"));
    }
}


static void
ikev2_fb_private_p_qm_out(SshIkePMPhaseQm pm_info,
                          int packet_number,
                          SshPolicyPrivatePayloadOutCB policy_callback,
                          void *policy_context,
                          void *private_payload_context)
{
  SshIkev2FbNegotiation neg;
  SshIkev2Sa ike_sa;

  neg = SSH_IKEV2_FB_QM_GET_P1_NEGOTIATION(pm_info);
  if (neg == NULL)
    goto end;

  ike_sa = neg->ike_sa;

  /* For the initiator neg->qm_info is not yet set as the first packet is
     processed synchronously inside ssh_ike_connect_ipsec(). */
  if (neg->qm_info == NULL)
    neg->qm_info = pm_info;
  SSH_ASSERT(neg->qm_info == pm_info);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Phase-QM output: packet_number %d ike_sa %p (neg %p)",
             packet_number, ike_sa, neg));

  /* Handle pending Quick-Mode NAT-T operations. */
  ikev2_fb_qm_pending_natt_operations(neg);

  /* Do not send an OA notify payload if NAT-T is not present between the
     IKE peers. */
  if ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No NAT present"));
      goto end;
    }

  /* In new mode, we send OA iff transport is in use. */
  if (neg->encapsulation == IPSEC_VALUES_ENCAPSULATION_MODE_UDP_TRANSPORT
      || neg->encapsulation ==
      IPSEC_VALUES_ENCAPSULATION_MODE_UDP_DRAFT_TRANSPORT)
    {
      switch (packet_number)
        {
        case 1:                 /* Initiator -> responder. */
        case 2:                 /* Responder -> intiator. */
          SSH_DEBUG(SSH_D_LOWOK, ("Sending NAT-OA"));
          ikev2_fb_handle_send_oa(neg, policy_callback, policy_context);
          break;
        }
    }
#ifdef DEBUG_LIGHT
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No need for NAT-OA in tunnel mode"));
    }
#endif /* DEBUG_LIGHT */

 end:
  (*policy_callback)(0, NULL, 0, policy_context);
}


/************************ Initializing NAT-T for IKE ************************/

void
ikev2_fb_natt_set_private_payload_handlers(SshIkeParams ike_params)
{
  /* Verify that no payload handlers are installed yet. */
  SSH_ASSERT(ike_params->private_payload_phase_1_check == NULL_FNPTR);
  SSH_ASSERT(ike_params->private_payload_phase_1_input == NULL_FNPTR);
  SSH_ASSERT(ike_params->private_payload_phase_1_output == NULL_FNPTR);

  /* Set up the phase 1 private payload handlers. */
  ike_params->private_payload_phase_1_check = ikev2_fb_private_p_1_check;
  ike_params->private_payload_phase_1_input = ikev2_fb_private_p_1_in;
  ike_params->private_payload_phase_1_output = ikev2_fb_private_p_1_out;

  /* Verify that no payload handlers are installed yet. */
  SSH_ASSERT(ike_params->private_payload_phase_2_check == NULL_FNPTR);
  SSH_ASSERT(ike_params->private_payload_phase_2_input == NULL_FNPTR);
  SSH_ASSERT(ike_params->private_payload_phase_2_output == NULL_FNPTR);

  /* Set up the Phase II private payload handlers. */
  ike_params->private_payload_phase_2_check = ikev2_fb_private_p_ii_check;
  ike_params->private_payload_phase_2_input = ikev2_fb_private_p_ii_in;
  ike_params->private_payload_phase_2_output = ikev2_fb_private_p_ii_out;

  /* Verify that no payload handlers are installed yet. */
  SSH_ASSERT(ike_params->private_payload_phase_qm_check == NULL_FNPTR);
  SSH_ASSERT(ike_params->private_payload_phase_qm_input == NULL_FNPTR);
  SSH_ASSERT(ike_params->private_payload_phase_qm_output == NULL_FNPTR);

  /* Set up the Quick Mode private payload handlers. */
  ike_params->private_payload_phase_qm_check = ikev2_fb_private_p_qm_check;
  ike_params->private_payload_phase_qm_input = ikev2_fb_private_p_qm_in;
  ike_params->private_payload_phase_qm_output = ikev2_fb_private_p_qm_out;
}


/****************** Server changed notification callbacks *******************/

/* Update information about a floated IKE server */
static void
ikev2_fb_server_changed(SshIkev2Sa ike_sa,
                        SshIkev2FbNatTInfo ike_float,
                        SshIkeServerContext new_server_context,
                        Boolean new_use_natt,
                        const unsigned char *new_remote_ip,
                        const unsigned char *new_remote_port)
{
  SshIpAddrStruct new_ip = { 0 };
  SshUInt16 new_port;
  Boolean use_natt;

  use_natt = ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) != 0);

  SSH_DEBUG(SSH_D_LOWSTART, ("Start ike_sa %p", ike_sa));

  /* Initialize float info */
  ike_float->server = NULL;
  ike_float->use_natt = FALSE;
  SSH_IP_UNDEFINE(&ike_float->remote_ip);
  ike_float->remote_port = 0;

  /* Parse address and port */
  SSH_IP_UNDEFINE(&new_ip);
  new_port = 0;
  if (new_remote_ip)
    ssh_ipaddr_parse(&new_ip, new_remote_ip);
  if (new_remote_port)
    new_port = ssh_uatoi(new_remote_port);

  /* Do not allow floating back to normal IKE port. */
  if (use_natt && !new_use_natt)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Ignoring server change back to normal IKE port"));
      return;
    }

  /* Check if any endpoint has changed */
  if (new_server_context != (SshIkeServerContext) ike_sa->server ||
      (!use_natt && new_use_natt) ||
      (SSH_IP_DEFINED(&new_ip) &&
       SSH_IP_CMP(ike_sa->remote_ip, &new_ip) != 0) ||
      (new_port != 0 && ike_sa->remote_port != new_port))
    {

      SSH_DEBUG(SSH_D_LOWOK,
                ("Server changed: local %@:%d->%@:%d, remote %@:%d->%@:%d",

                 ssh_ipaddr_render, &ike_sa->server->ip_address,
                 use_natt ?
                 ike_sa->server->nat_t_local_port :
                 ike_sa->server->normal_local_port ,

                 ssh_ipaddr_render, &new_server_context->ip_address,
                 new_use_natt ?
                 new_server_context->nat_t_local_port :
                 new_server_context->normal_local_port ,

                 ssh_ipaddr_render, &ike_sa->remote_ip,
                 ike_sa->remote_port,

                 ssh_ipaddr_render, &new_ip,
                 new_port));

      /* Store new server to float info */
      ike_float->server = new_server_context;
      ike_float->use_natt = new_use_natt;
      ike_float->remote_port = new_port;
      ike_float->remote_ip = new_ip;
    }
}


void
ikev2_fb_phase_i_server_changed(SshIkePMPhaseI pm_info,
                                SshIkeServerContext new_server,
                                const unsigned char *new_remote_ip,
                                const unsigned char *new_remote_port)
{
  SshIkev2FbNegotiation neg;
  Boolean use_natt;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);

  if (neg == NULL)
    {
      /* This is some garbage to already completed negotiation.  Just
         ignore the changed notification. */
      SSH_DEBUG(SSH_D_NETGARB,
                ("Phase-1 server changed for a completed negotiation: "
                 "ignoring notification"));
    }
  else
    {
      use_natt = FALSE;
      if (pm_info->server_flags & SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT)
        use_natt = TRUE;

      ikev2_fb_server_changed(neg->ike_sa,
                              &neg->ike_float,
                              new_server, use_natt,
                              new_remote_ip, new_remote_port);
    }
}


void
ikev2_fb_phase_qm_server_changed(SshIkePMPhaseQm pm_info,
                                 SshIkeServerContext new_server,
                                 const unsigned char *new_remote_ip,
                                 const unsigned char *new_remote_port)
{
  SshIkev2FbNegotiation neg;
  Boolean use_natt;

  neg = SSH_IKEV2_FB_QM_GET_P1_NEGOTIATION(pm_info);
  if (neg == NULL)
    {
      /* This is some garbage to already completed negotiation.  Just
         ignore the changed notification. */
      SSH_DEBUG(SSH_D_NETGARB,
                ("Qm server changed for a completed negotiation: "
                 "ignoring notification"));
    }
  else
    {
      use_natt = FALSE;
      if (pm_info->server_flags & SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT)
        use_natt = TRUE;

      ikev2_fb_server_changed(neg->ike_sa,
                              &neg->ike_float,
                              new_server, use_natt,
                              new_remote_ip, new_remote_port);
    }
}


void
ikev2_fb_phase_ii_server_changed(SshIkePMPhaseII pm_info,
                                 SshIkeServerContext new_server,
                                 const unsigned char *new_remote_ip,
                                 const unsigned char *new_remote_port)
{
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SshIkev2FbNegotiation neg;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  SshIkev2Sa ike_sa;
  Boolean use_natt;
  SshIkev2FbNatTInfo ike_float = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Start"));

  switch (pm_info->exchange_type)
    {
    case SSH_IKE_XCHG_TYPE_INFO:
      SSH_ASSERT(pm_info->policy_manager_data == NULL);
      ike_float = ssh_calloc(1, sizeof(*ike_float));
      if (!ike_float)
        return;
      pm_info->policy_manager_data = ike_float;
      break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    case SSH_IKE_XCHG_TYPE_CFG:
      SSH_ASSERT(pm_info->policy_manager_data != NULL);
      neg = (SshIkev2FbNegotiation) pm_info->policy_manager_data;
      ike_float = &neg->ike_float;
      break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

    default:
      SSH_DEBUG(SSH_D_LOWOK,
                ("Ignoring phase_ii_server_changed notification "
                 "for exchange_type %d", pm_info->exchange_type));
      return;
    }

  SSH_ASSERT(pm_info->phase_i != NULL);
  ike_sa = (SshIkev2Sa) pm_info->phase_i->policy_manager_data;

  use_natt = FALSE;
  if (pm_info->server_flags & SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT)
    use_natt = TRUE;

  ikev2_fb_server_changed(ike_sa,
                          ike_float,
                          new_server, use_natt,
                          new_remote_ip, new_remote_port);
}

#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IKEV1 */
