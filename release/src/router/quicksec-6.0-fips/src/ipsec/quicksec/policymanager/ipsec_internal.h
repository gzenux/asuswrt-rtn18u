/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for the QuickSec IPsec Policy Manager.
*/

#ifndef IPSEC_INTERNAL_H
#define IPSEC_INTERNAL_H

#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "sad_ike.h"
#ifdef SSHDIST_IKEV1
#include "sshikev2-fallback.h"
#endif /* SSHDIST_IKEV1 */

#ifdef SSHDIST_L2TP
#include "sshl2tp.h"
#include "sshppp.h"
#endif /* SSHDIST_L2TP */

#ifdef SSHDIST_RADIUS
#include "pad_auth_radius.h"
#endif /* SSHDIST_RADIUS */
#include "pad_auth_passwd.h"
#include "pad_auth_domain.h"

#include "util_algorithms_internal.h"

#ifdef SSHDIST_CERT
#include "sshpkcs1.h"
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_IKE_CERT_AUTH
#include "util_cm.h"
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#include "ras_internal.h"
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#include "rac_virtual_ip_internal.h"
#include "util_connection.h"
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSHDIST_IPSEC_NAT
#include "nat_internal.h"
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_MSCAPI
#include "util_mscapi.h"
#endif /* SSHDIST_MSCAPI */

#ifdef SSH_IPSEC_TCPENCAP
#include "util_tcpencap.h"
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSHDIST_IKE_EAP_AUTH
#include "ssheap.h"
#endif /* SSHDIST_IKE_EAP_AUTH */

/* Assert the validity of different functional components. */

#ifdef SSHDIST_IKE_ID_LIST
#ifdef SSHDIST_IKEV1
#else /* SSHDIST_IKEV1 */
#error "SSHDIST_IKE_ID_LIST requires SSHDIST_IKE"
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IKE_ID_LIST */

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#else  /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#error "SSHDIST_ISAKMP_CFG_MODE_RULES requires " \
  "SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT"
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

#ifdef SSHDIST_IPSEC_XAUTH_CLIENT
#ifdef SSHDIST_IKE_XAUTH
#else /* SSHDIST_IKE_XAUTH */
#error "SSHDIST_IPSEC_XAUTH_CLIENT requires SSHDIST_IKE_XAUTH"
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IPSEC_XAUTH_CLIENT */

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
#ifdef SSHDIST_IKE_XAUTH
#else /* SSHDIST_IKE_XAUTH */
#error "SSHDIST_IPSEC_XAUTH_SERVER requires SSHDIST_IKE_XAUTH"
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

#ifdef SSHDIST_IKE_XAUTH
#ifdef SSHDIST_IKEV1
#else /* SSHDIST_IKEV1 */
#error "SSHDIST_IKE_XAUTH requires SSHDIST_IKE"
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IKE_XAUTH */

#ifdef SSHDIST_IKE_XAUTH
#ifdef SSHDIST_ISAKMP_CFG_MODE
#else /* SSHDIST_ISAKMP_CFG_MODE */
#error "SSHDIST_IKE_XAUTH requires SSHDIST_ISAKMP_CFG_MODE"
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IKE_XAUTH */

#ifdef SSHDIST_EAP_SIM
#ifdef SSHDIST_SIM
#else /* SSHDIST_SIM */
#error "SSHDIST_EAP_SIM requires SSHDIST_SIM"
#endif /* SSHDIST_SIM */
#endif /* SSHDIST_EAP_SIM */

#ifdef SSHDIST_EAP_AKA
#ifdef SSHDIST_SIM
#else /* SSHDIST_SIM */
#error "SSHDIST_EAP_AKA requires SSHDIST_SIM"
#endif /* SSHDIST_SIM */
#endif /* SSHDIST_EAP_AKA */

#include "spd_ike_blacklist.h"
#include "spd_ike_blacklist_internal.h"

/* ************************* Types and definitions ***************************/


/** Magic value used in debug builds to check that the context
    structures are of correct type. */
#define SSH_PM_MAGIC_P1 0xfee17031

/** Magic value used in debug builds to check that the context
    structures are of correct type. */
#define SSH_PM_MAGIC_QM 0xfee1716d

/* Macros to check validity of context structures. */
#define SSH_PM_ASSERT_P1(p1) SSH_ASSERT((p1) && (p1)->magic == SSH_PM_MAGIC_P1)
#define SSH_PM_ASSERT_QM(qm) SSH_ASSERT((qm) && (qm)->magic == SSH_PM_MAGIC_QM)
#define SSH_PM_ASSERT_P1N(p1) \
  SSH_ASSERT((p1) && (p1)->magic == SSH_PM_MAGIC_P1 && (p1)->n)
#define SSH_PM_ASSERT_ED(ed)  \
  SSH_ASSERT((ed) && (ed)->magic == SSH_IKEV2_ED_MAGIC)

/* Compatibility flags. */
#define SSH_PM_COMPAT_OUR_ID_IKEV1                      0x00000001
#define SSH_PM_COMPAT_OUR_ID_IKEV2                      0x00000002
#define SSH_PM_COMPAT_32BIT_CPI                         0x00000004
#define SSH_PM_COMPAT_XAUTH_BEAULIEU_00                 0x00000008
#define SSH_PM_COMPAT_NO_IPSEC_DELETE_NOTIFICATIONS     0x00000010
#define SSH_PM_COMPAT_NAT_T                             0x00000020
#define SSH_PM_COMPAT_NAT_T_AGGR_MODE                   0x00000040
#define SSH_PM_COMPAT_NAT_T_IETF                        0x00000080
#define SSH_PM_COMPAT_NAT_T_PORT_FLOAT                  0x00000100
#define SSH_PM_COMPAT_NAT_T_RFC                         0x00000200
#define SSH_PM_COMPAT_NAT_T_FQDN_PROXY_ID               0x00000400
#define SSH_PM_COMPAT_REMOTE_DPD                        0x00000800
#define SSH_PM_COMPAT_CISCO_UNITY                       0x00001000
#define SSH_PM_COMPAT_NO_CERT_CHAINS                    0x00002000
#define SSH_PM_COMPAT_SET_ACK_CFG                       0x00004000
#define SSH_PM_COMPAT_DONT_INITIATE                     0x00008000
#ifdef SSH_IPSEC_TCPENCAP
#define SSH_PM_COMPAT_TCPENCAP                          0x00010000
#endif /* SSH_IPSEC_TCPENCAP */
#define SSH_PM_COMPAT_NAT_T_DRAFT_02                    0x00020000
#define SSH_PM_COMPAT_NAT_T_DRAFT_03                    0x00040000
#define SSH_PM_COMPAT_FORCE_NAT_T_DRAFT_02              0x00080000

/* Indexes to arrays of SPI values. These are used for conviniency inside
   policymanager. */
#define SSH_PM_SPI_NEW   0
#define SSH_PM_SPI_OLD   1

/* A predicate to check whether the tunnel 'tunnel' is a virtual IP
   tunnel. */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#define SSH_PM_TUNNEL_IS_VIRTUAL_IP(tunnel)     \
  ((tunnel)->flags & (SSH_PM_TI_CFGMODE | SSH_PM_TI_L2TP))
#else  /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#define SSH_PM_TUNNEL_IS_VIRTUAL_IP(tunnel)   FALSE
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

/** A predicate to check whether the tunnel 'tunnel' is valid and can
    be used in IKE negotiations. */
#define SSH_PM_TUNNEL_IS_IKE(tunnel) ((tunnel) && (tunnel)->ike_tn)

/** Check if 'p1' deletion is ongoing. */
#define SSH_PM_P1_DELETED(p1) \
  ((p1)->ike_sa->waiting_for_delete != NULL \
   || (p1)->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] != NULL)

/** Check if 'p1' is ready. */
#define SSH_PM_P1_READY(p1) \
  ((p1)->done && !(p1)->failed && !(p1)->unusable && !SSH_PM_P1_DELETED(p1))

/** Check if 'p1' is usable. */
#define SSH_PM_P1_USABLE(p1) \
  (!(p1)->failed && !(p1)->unusable && !SSH_PM_P1_DELETED(p1))

/** Hash the IKE peer 'ip' into a hash value, suitable to be
    used with the PM's 'ike_sa_hash' table. */
#define SSH_PM_IKE_PEER_HASH(ip)  \
  (SSH_IP_HASH((ip)) % SSH_PM_IKE_SA_HASH_TABLE_SIZE)

/** Hash the IKE id 'id'  into a hash value, suitable to be
    used with the PM's 'ike_sa_id_hash' table. */
#define SSH_PM_IKE_ID_HASH(id)  \
  (ssh_ikev2_payload_id_hash(id) % SSH_PM_IKE_SA_HASH_TABLE_SIZE)

/** The size of the hash table for tunnel endpoints. */
#define SSH_PM_TUNNEL_HASH_TABLE_SIZE SSH_PM_IKE_SA_HASH_TABLE_SIZE

/** The size of the hash table for outbound SPI mappings. */
#define SSH_PM_SPI_OUT_HASH_TABLE_SIZE SSH_PM_IKE_SA_HASH_TABLE_SIZE

/** A macro for converting key bit lengths to the Attribute value used
    in IKE. */
#define SSH_PM_IKE_KEY_LENGTH_ATTRIBUTE(__bits) \
 ((__bits == 0) ? 0 : ((0x800e << 16) | (__bits)))


/** Default IKE encryption algorithms. */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#ifdef SSH_PM_CRYPT_DES
#define SSH_PM_IKE_DEFAULT_CRYPT (SSH_PM_CRYPT_3DES | SSH_PM_CRYPT_AES)
#else  /* SSHDIST_CRYPT_DES */
#define SSH_PM_IKE_DEFAULT_CRYPT SSH_PM_CRYPT_AES
#endif /* SSHDIST_CRYPT_DES */
#else /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSH_PM_CRYPT_DES
#define SSH_PM_IKE_DEFAULT_CRYPT SSH_PM_CRYPT_3DES
#else /* SSHDIST_CRYPTO_DES */
#error "No suitable crypto algorithms for IKE!"
#endif /* SSHDIST_CRYPT_DES */
#endif /* SSHDIST_CRYPT_RIJNDAEL */


/** Default IKE hash algorithms. */
#ifndef HAVE_FIPSLIB
#define SSH_PM_IKE_DEFAULT_MAC \
  (SSH_PM_MAC_HMAC_MD5 | SSH_PM_MAC_HMAC_SHA1 | SSH_PM_MAC_HMAC_SHA2)
#else /* !HAVE_FIPSLIB */
#define SSH_PM_IKE_DEFAULT_MAC \
  (SSH_PM_MAC_HMAC_SHA1 | SSH_PM_MAC_HMAC_SHA2)
#endif /* !HAVE_FIPSLIB */

/** Mask bits for selecting the IKE encryption algorithms from the
    'SSH_PM_CRYPT_*' bitmask values. */
#define SSH_PM_IKE_CRYPT_MASK (SSH_PM_CRYPT_MASK & ~SSH_PM_CRYPT_NULL)

#define SSH_PM_MAX_SPIS (9 * SSH_ENGINE_MAX_TUNNELS + 10)
#define SSH_PM_MAX_UNKNOWN_SPIS 10

/** This macro returns the index of the 'p1' object. Additionaly if
    the IKE SA is of version 1, the topmost bit of the returned index
    is set to one. This bit is used in Engine to determine if an
    IKE SA handle is of version one or two. */
#ifdef SSHDIST_IKEV1
#define SSH_PM_IKE_SA_INDEX(p1) ((p1)->index |                         \
     (((p1)->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) ?   \
     (1 << 31) : 0))
#else /* SSHDIST_IKEV1 */
#define SSH_PM_IKE_SA_INDEX(p1) ((p1)->index)
#endif /* SSHDIST_IKEV1 */

/** Peer information database internal hash table: handle. */
#define SSH_PM_PEER_HANDLE_HASH_TABLE_SIZE SSH_PM_IKE_SA_HASH_TABLE_SIZE

/** Peer information database internal hash table: IKE SA. */
#define SSH_PM_PEER_IKE_SA_HASH_TABLE_SIZE SSH_PM_IKE_SA_HASH_TABLE_SIZE

/** Peer information database internal hash table: Address. */
#define SSH_PM_PEER_ADDR_HASH_TABLE_SIZE 255

/* Magic constants. */

/** Retry limit. */
#define SSH_PM_IKE_RETRY_LIMIT                  7

/** Expire timer (seconds). */
#define SSH_PM_IKE_EXPIRE_TIMER_SECONDS         60

/** Default IKE SA lifetime (seconds). */
#define SSH_PM_DEFAULT_IKE_SA_LIFE_SECONDS      (8 * 60 * 60)

/** Default Diffie-Hellman groups. */
#define SSH_PM_DEFAULT_DH_GROUPS                (SSH_PM_DH_GROUP_2 \
                                                 | SSH_PM_DH_GROUP_5)

/** Default IPsec SA lifetime in seconds. According to RFC 2407, the
    default IPsec SA lifetime is assumed to be 8 hours. */
#define SSH_PM_DEFAULT_IPSEC_SA_LIFE_SECONDS    (8 * 60 * 60)

/** Default IPsec SA lifetime in kilobytes. */
#define SSH_PM_DEFAULT_IPSEC_SA_LIFE_KB         (0)

/* The maximum number of IKE SA's which are checked for rekey or deletion
   during any single call to pm_ike_sa_timer */
#define SSH_PM_IKE_MAX_TO_CHECK         \
  ((SSH_PM_MAX_IKE_SAS < 10000) ? 200 : (SSH_PM_MAX_IKE_SAS / 50))

/* The maximum number of IKE SA's we start to rekey or delete during
   any single call to pm_ike_sa_timer */
#define SSH_PM_IKE_MAX_TO_PROCESS                                       \
  ((SSH_PM_IKE_MAX_TO_CHECK / 10) >                                     \
   ((SSH_PM_MAX_IKE_SA_NEGOTIATIONS * 2) / 3) ?                         \
   ((SSH_PM_MAX_IKE_SA_NEGOTIATIONS * 2) / 3) :                         \
   (SSH_PM_IKE_MAX_TO_CHECK / 10))

/* The interval in seconds for which the IKE SA timer is called. */
#define SSH_PM_IKE_TIMER_INTERVAL 1

/* Soft expire time for IKE SA rekey. IKE SA rekey is started when 1/100 of
   the IKE SA lifetime is left, unless it is limited by the following settings.
   This must be greater than the time it takes to iterate through the whole
   IKE SA table. This setting also affects the minimum usable IKE SA lifetime,
   which is twice the minimum soft expire time. */
#define SSH_PM_IKE_SA_SOFT_GRACE_TIME                        \
  ((SSH_PM_MAX_IKE_SAS < (5 * SSH_PM_IKE_MAX_TO_CHECK) ?     \
    10 : (2 * SSH_PM_MAX_IKE_SAS / SSH_PM_IKE_MAX_TO_CHECK)) \
   * SSH_PM_IKE_TIMER_INTERVAL)

/* Minimum lifetime for IKE SA. IKE SA lifetime must be at least twice
   the SSH_PM_IKE_SA_SOFT_GRACE_TIME, which is dependent on the maximum
   IKE SAs in the system. If the grace time is lower than 60 seconds,
   enforce the minimum lifetime of a IKE SA to be 60. */
#define SSH_PM_IKE_SA_MIN_LIFETIME                           \
  (((2 * SSH_PM_IKE_SA_SOFT_GRACE_TIME) > 60) ?              \
   (2 * SSH_PM_IKE_SA_SOFT_GRACE_TIME) :                     \
   60)

#define SSH_PM_IKE_SA_SOFT_GRACE_TIME_MAX   600 /* seconds */

/* Lifetime for half-open IKE SA on the responder (that is an IKE SA that
   has received the first packet, but nothing after that) */
#define SSH_PM_IKE_HALF_OPEN_LIFETIME   32 /* seconds */

/* Maximum lifetime for IKE SA negotiation on the responder. */
#define SSH_PM_IKE_SA_RESPONDER_MAX_NEGOTIATION_TIME   180 /* seconds */

/* Lifetime of an IKE SA after it has been deleted. Pending IKE SA delete
   operation is aborted after this much time has gone since the IKE SA
   was deleted. */
#define SSH_PM_IKE_SA_DELETE_TIMEOUT    30 /* seconds */

/* Initial expiry time for an IKE SA. This will be updated to a real
   one later in the negotiation. */
#define SSH_PM_IKE_SA_INITIAL_EXPIRY_TIME 5 /* seconds */

/** Delay how long the Policy Manager waits after an successful
    initiator Quick-Mode negotation until it resends the triggered
    packet. */
#define SSH_PM_TRIGGER_REPROCESS_DELAY          250000

/** Delay how long the Policy Manager waits between inbound and
    outbound SA rekey.  When we are the initiator of an IKEv1 IPsec SA
    negotiation we give this much time for our peer to update its inbound SA
    before we start using it. */
#define SSH_PM_REKEY_OUTBOUND_DELAY             150000

#ifdef SSHDIST_ISAKMP_CFG_MODE
/** Hash table size for active configuration mode clients. */
#define SSH_PM_CFGMODE_CLIENT_HASH_TABLE_SIZE \
((SSH_PM_MAX_CONFIG_MODE_CLIENTS / 10) + 1)
#endif /*  SSHDIST_ISAKMP_CFG_MODE */

/** A "random" non-zero SPI value that is never used as a valid SPI. This
    value is returned to the IKE library SPI allocate policy call on error
    cases. The reason is that the IKE library needs to get a non-zero SPI
    in order call the IPSec done policy call function (which the Policy
    Manager wants to get even in error cases). */
#define SSH_IPSEC_SPI_IKE_ERROR_RESERVED 0x10

/*  Default values for IKE connection rate limiting. */

/** Hard limit on the number of available p1 structs.
    If this value is reached, then the new connection is dropped.
    Currently 90% of p1 structs. */
#ifndef SSH_PM_MAX_IKE_NEW_CONNECTION
#define SSH_PM_MAX_IKE_NEW_CONNECTION \
(SSH_PM_MAX_IKE_SA_NEGOTIATIONS - \
(1 * SSH_PM_MAX_IKE_SA_NEGOTIATIONS / 10) - 1)
#endif /* SSH_PM_MAX_IKE_NEW_CONNECTION */

/** Soft limit on the number of available p1 structs.
    If this value is reached, then a cookie is requested,
    or the new connection is dropped (if hard rate limit is reached).
    Currently 70% of p1 structs. */
#ifndef SSH_PM_IKE_NEW_CONNECTION_SOFT_LIMIT
#define SSH_PM_IKE_NEW_CONNECTION_SOFT_LIMIT \
(SSH_PM_MAX_IKE_SA_NEGOTIATIONS - \
((3 * SSH_PM_MAX_IKE_SA_NEGOTIATIONS) / 10) - 1)
#endif /* SSH_PM_IKE_NEW_CONNECTION_SOFT_LIMIT */

/** Hard limit on the connection rate, connections per second.
    If this value is reached, then the new connections is dropped
    (if soft limit on number of p1s is reached), or a cookie is
    requested. Currently 50% of p1 structs (per second). */
#ifndef SSH_PM_MAX_IKE_NEW_CONNECTION_RATE
#define SSH_PM_MAX_IKE_NEW_CONNECTION_RATE \
(SSH_PM_MAX_IKE_SA_NEGOTIATIONS - \
((5 * SSH_PM_MAX_IKE_SA_NEGOTIATIONS) / 10) - 1)
#endif /* SSH_PM_MAX_IKE_NEW_CONNECTION_RATE */

/** Soft limit on the connection rate, connections per second.
    If this value is reached, then a cookie is requested.
    Currently 30% of p1 structs (per second). */
#ifndef SSH_PM_IKE_NEW_CONNECTION_RATE_SOFT_LIMIT
#define SSH_PM_IKE_NEW_CONNECTION_RATE_SOFT_LIMIT \
(SSH_PM_MAX_IKE_SA_NEGOTIATIONS - \
((7 * SSH_PM_MAX_IKE_SA_NEGOTIATIONS) / 10) - 1)
#endif /* SSH_PM_IKE_NEW_CONNECTION_RATE_SOFT_LIMIT */

/** Decay parameter for the average new connection rate counter.
    This parameter is the percentage of the current counter value used
    in the calculation of decaying average. */
#define SSH_PM_IKE_CONNECTION_RATE_DECAY 50

/** Macro to get tunnel used for IKE negotiations from tunnel in the nested
    tunneling case. */
#define SSH_PM_TUNNEL_GET_P1_TUNNEL(_p1_tunnel,_tunnel)                      \
do {                                                                         \
  (_p1_tunnel) = (_tunnel);                                                  \
  while ((_p1_tunnel))                                                       \
    {                                                                        \
      if ((_p1_tunnel)->outer_tunnel && (_p1_tunnel)->outer_tunnel_ike_sa)   \
        (_p1_tunnel) = (_p1_tunnel)->outer_tunnel;                           \
      else                                                                   \
        break;                                                               \
    }                                                                        \
}                                                                            \
while (0)

/** Macro to set qm->p1_tunnel. */
#define SSH_PM_QM_SET_P1_TUNNEL(qm)                             \
do                                                              \
  {                                                             \
    SSH_ASSERT((qm)->p1_tunnel == NULL);                        \
    SSH_PM_TUNNEL_GET_P1_TUNNEL((qm)->p1_tunnel, (qm)->tunnel); \
  }                                                             \
while (0)


/** Macro for grabbing references to SshIkev2Sa. */
#define SSH_PM_IKE_SA_TAKE_REF(_ike_sa)                                     \
do                                                                          \
  {                                                                         \
    SshIkev2Sa __sa = (_ike_sa);                                            \
    SSH_ASSERT(__sa != NULL);                                               \
    SSH_DEBUG(SSH_D_LOWOK, ("Taking reference to IKE SA %p to ref count %d",\
                            __sa, __sa->ref_cnt + 1));                      \
    __sa->ref_cnt++;                                                        \
  }                                                                         \
while (0)

/** Internal function for releasing SshIkev2Sa
*/
void pm_ike_sa_free_ref(SshSADHandle sad_handle, SshIkev2Sa ike_sa);


/** Internal macro for releasing references to SshIkev2Sa. */
#define SSH_PM_IKE_SA_FREE_REF(_sad_handle, _ike_sa)                         \
do                                                                           \
  {                                                                          \
    SshIkev2Sa __sa = (_ike_sa);                                             \
    SSH_ASSERT(__sa != NULL);                                                \
    SSH_ASSERT(__sa->ref_cnt > 0);                                           \
    SSH_DEBUG(SSH_D_LOWOK, ("Freeing reference to IKE SA %p to ref count %d",\
                            __sa, __sa->ref_cnt - 1));                       \
    pm_ike_sa_free_ref((_sad_handle), __sa);                                 \
  }                                                                          \
while (0)

/** Macro for grabbing references to SshPmTunnel. The references are always
    released using SSH_PM_TUNNEL_DESTROY(). */
#define SSH_PM_TUNNEL_TAKE_REF(_tunnel)                                     \
do                                                                          \
  {                                                                         \
    SSH_ASSERT((_tunnel) != NULL);                                          \
    SSH_DEBUG(SSH_D_LOWOK,                                                  \
              ("Taking reference to tunnel '%s' (id %d), to ref count %d",  \
               (_tunnel)->tunnel_name, (_tunnel)->tunnel_id,                \
              (_tunnel)->refcount + 1));                                    \
    (_tunnel)->refcount++;                                                  \
  }                                                                         \
while (0)


















/** Macro for releasing references to SshPmTunnel. This should be used instead
    of directly calling ssh_pm_tunnel_destroy(). */
#define SSH_PM_TUNNEL_DESTROY(_pm, _tunnel)                                   \
do                                                                            \
  {                                                                           \
    SSH_PM_ASSERT_PM(_pm);                                                    \
    SSH_ASSERT(_tunnel != NULL);                                              \
    SSH_DEBUG(SSH_D_LOWOK,                                                    \
              ("Releasing reference to tunnel '%s' (id %d), to ref count %d", \
               (_tunnel)->tunnel_name, (_tunnel)->tunnel_id,                  \
               (_tunnel)->refcount - 1));                                     \
    ssh_pm_tunnel_destroy(_pm, _tunnel);                                      \
  }                                                                           \
while (0)

/** Macro for attaching a tunnel to a rule. This macro only increments
    tunnel->referring_rule_count. */
#define SSH_PM_TUNNEL_ATTACH_RULE(_tunnel, _rule, _to_tunnel)                 \
do                                                                            \
  {                                                                           \
    SSH_ASSERT(_tunnel != NULL);                                              \
    SSH_DEBUG(SSH_D_LOWOK,                                                    \
              ("Attaching tunnel '%s' (id %d) to %s-tunnel rule '%@', "       \
               "referring rules %d",                                          \
               (_tunnel)->tunnel_name, (_tunnel)->tunnel_id,                  \
               ((_to_tunnel) ? "to" : "from"), ssh_pm_rule_render, (_rule),   \
               (_tunnel)->referring_rule_count + 1));                         \
    (_tunnel)->referring_rule_count++;                                        \
  }                                                                           \
while (0)

/** Macro for detaching a tunnel from a rule. This macro only decrements
    tunnel->referring_rule_count. */
#define SSH_PM_TUNNEL_DETACH_RULE(_tunnel, _rule, _to_tunnel)                 \
do                                                                            \
  {                                                                           \
    SSH_ASSERT(_tunnel != NULL);                                              \
    SSH_DEBUG(SSH_D_LOWOK,                                                    \
              ("Detaching tunnel '%s' (id %d) from %s-tunnel rule '%@', "     \
               "referring rules %d",                                          \
               (_tunnel)->tunnel_name, (_tunnel)->tunnel_id,                  \
               ((_to_tunnel) ? "to" : "from"), ssh_pm_rule_render, (_rule),   \
               (_tunnel)->referring_rule_count - 1));                         \
    SSH_ASSERT((_tunnel)->referring_rule_count > 0);                          \
    (_tunnel)->referring_rule_count--;                                        \
  }                                                                           \
while (0)

/** Forward declarations for some Policy Manager data structures. */

/** A Phase-1 IKE SA negotiation context data. */
typedef struct SshPmP1NegotiationRec *SshPmP1Negotiation;

#ifdef SSHDIST_IKE_XAUTH
/** Extended authentication types. */
typedef enum
{
  /** No XAUTH done. */
  SSH_PM_XAUTH_NONE,

  /** XAUTH with a static user-name - password list; the
      'xauth_attributes' must have the value NULL. */
  SSH_PM_XAUTH_PASSWORD,

  /** XAUTH with RADIUS; the 'xauth_attributes' is of type
      SshRadiusClientRequest. */
  SSH_PM_XAUTH_RADIUS







} SshPmXauthType;
#endif /* SSHDIST_IKE_XAUTH */

/** A server as known by the Policy Manager. */
typedef struct SshPmServerRec SshPmServerStruct;

/** A server as known by the Policy Manager. */
typedef struct SshPmServerRec *SshPmServer;

struct SshPmServerRec
{
  SshADTBagHeaderStruct adt_header;

  /** Back pointer to Policy Manager. */
  SshPm pm;

  /* Flags. */
  unsigned int valid : 1;           /** Address is valid local interface. */
  unsigned int delete_pending : 1;  /** Server is pending deletion */

  SshVriId routing_instance_id;

  /** Expire time in seconds since epoch. */
  SshTime delete_time;

  /** The address the servers are listening to. */
  SshIpAddrStruct address;

  /** The interface number of the address and the MTU of the
      interface. */
  SshUInt32 ifnum;
  size_t iface_mtu;

  /** The array (and its size) of IKE servers bound to different ports
      on this address */
  SshUInt16 num_ike_servers;
  SshIkev2Server *ike_servers;

#ifdef SSHDIST_L2TP
  /** L2TP server. */
  SshL2tpServer l2tp_server;
#endif /* SSHDIST_L2TP */
};

/** An IKE pre-shared key. */
struct SshPmPskRec
{
  SshUInt32 flags;
  unsigned char *secret;
  size_t secret_len;
};

typedef struct SshPmPskRec SshPmPskStruct;
typedef struct SshPmPskRec *SshPmPsk;

/** An externalkey key object. */
struct SshPmEkRec
{
  /** ADT header for externalkey key storage. */
  SshADTBagHeaderStruct adt_header;

  /* Flags. */
  unsigned int certs_fetched : 1; /** Certificates fetched. */
  unsigned int key_fetched : 1;   /** Private key fetched. */
  unsigned int rsa_key : 1;       /** Key is an RSA key. */
  unsigned int dsa_key : 1;       /** DSA Key. */
#ifdef SSHDIST_CRYPT_ECP
  unsigned int ecdsa_key : 1;
#endif /* SSHDIST_CRYPT_ECP */
  unsigned int deleted : 1;       /** Key unavailable and to be deleted. */

  /** A unique key ID. */
  SshUInt32 key_id;

  /** Flags as given by externalkey. */
  SshUInt32 flags;

  /** Externalkey keypath. */
  char *keypath;

  /** Number of references using this key. */
  SshUInt32 refcount;

  /** Private key for this externalkey.  This can have the value NULL
      even if the 'key_fetched' flag is set.  That means that the
      system could not fetch private key. */
  SshPrivateKey private_key;

  /** The accelerated version of the 'private_key'. It is NULL
      if 'private_key' cannot be accelerated. */
  SshPrivateKey accel_private_key;

  /** Public key, derived from a certificate. This can be NULL even if
      'certs_fetched' is set. That means that the keypath did not
      specify any certificates, or the certificates did not contain
      public key, or we run out of memory. */
  SshPublicKey public_key;

  /** BER-encoded certificate of the key. This is needed to refresh the
      authentication domains certificate stores. */
  unsigned char *ber_cert;
  size_t ber_cert_len;

  /** MD5 hash of public key (aka key identifier, set only when
      'public_key' is set) */
  unsigned char key_hash[16];

  /** Array of IKE ID's that can be used with the key.  This is taken
      from the key's certificate with the first ID being the
      certificate's SubjectName and subsequent ID's the certificate's
      alternative SubjectNames. */
  SshIkev2PayloadID *ids;
  SshUInt32 num_ids;
};

typedef struct SshPmEkRec SshPmEkStruct;
typedef struct SshPmEkRec *SshPmEk;


/** Outbound IPsec SPIs. */
typedef struct SshPmSpiOutRec SshPmSpiOutStruct;
/** Outbound IPsec SPIs. */
typedef struct SshPmSpiOutRec *SshPmSpiOut;

struct SshPmSpiOutRec {

  /** Link field for the outbound SPI hash by SPI table: next. */
  SshPmSpiOut hash_spi_next;

  /** Link field for the outbound SPI by peer linked list. */
  SshPmSpiOut peer_spi_next;

  /** Transform index. */
  SshUInt32 trd_index;

  /** The inbound SPI value used with this outbound SPI. */
  SshUInt32 inbound_spi;

  /** Outbound SPI value. */
  SshUInt32 outbound_spi;

  /* Handle to peer. */
  SshUInt32 peer_handle;

  /** IP protocol of the SA (ESP or AH). */
  SshUInt8 ipproto;

  /* Flags */

  /** Has this outbound spi been rekeyed? */
  unsigned int rekeyed : 1;

  /** Is there an active negotiation for this SPI? */
  unsigned int neg_in_progress : 1;

  /** Do not generate SA events for this SPI. */
  unsigned int disable_sa_events : 1;
};

/** Inbound IPsec SPIs, allocated by the Policy Manager. */
struct SshPmSpiInRec {

  SshADTBagHeaderStruct adt_header;

  /** The inbound SPI. */
  SshUInt32 spi;

  /** Have we received an IPsec SPI delete notification for this SPI. */
  unsigned int delete_received : 1;
};

typedef struct SshPmSpiInRec SshPmSpiInStruct;
typedef struct SshPmSpiInRec *SshPmSpiIn;


/** Information about either an unknown inbound SPI or about an
    outbound SPI for which INVALID_SPI notifications have been
    received. **/
struct SshPmSpiUnknownRec {

  SshADTBagHeaderStruct adt_header;

  /** True if this entry has been acted on or cancelled. The entry
      will exist for a while in this state and absorb any additional
      errors related to the same SPI. */
  Boolean done;

  /* The type of this entry. */
  enum {
    SSH_PM_UNKNOWN_SPI_INBOUND,         /** ESP/AH packet with unknown SPI. */
    SSH_PM_UNKNOWN_SPI_OUTBOUND,        /** Received INVALID_SPI notify. */
    SSH_PM_UNKNOWN_SPI_PEER_ERROR_COUNT /** Per-peer SPI fault count. */
  } type;

  /** Timer ticks since creating this entry. */
  SshUInt32 age;

  /** Age at which this entry will be removed. */
  SshUInt32 lifetime;

  /** Number of events seen. */
  SshUInt32 count;

  /** Local IKE address or tunnel local end. */
  SshIpAddrStruct local_ip;

  /** IKE peer or tunnel remote end. */
  SshIpAddrStruct remote_ip;

  /** IKE peer port. */
  SshUInt16 remote_port;

  /** IPsec protocol (ESP or AH). */
  SshUInt8 ipproto;

  /** Unknown ESP/AH SPI, or outbound SPI from a received INVALID_SPI notify.*/
  SshUInt32 spi;

  /** IKE SA handle. */
  SshUInt32 ike_sa_handle;

  /** Received ESP/AH packet waiting for the SA to come up, NULL if none. */
  unsigned char *packet;
  /** The length of the packet. */
  size_t packet_len;

  /* Information for reprocessing the reveived packet. */
  /** Tunnel ID. */
  SshUInt32 tunnel_id;
  /** Protocol. */
  SshInterceptorProtocol protocol;
  /** Interface number. */
  SshUInt32 ifnum;
  /** Flags. */
  SshUInt32 flags;
  /** Previous tranform index. */
  SshUInt32 prev_transform_index;

  /** VRF routing instance id */
  SshVriId routing_instance_id;
};

typedef struct SshPmSpiUnknownRec SshPmSpiUnknownStruct;
typedef struct SshPmSpiUnknownRec *SshPmSpiUnknown;

/* Temporary context for sending delayed IPsec SPI delete notifications. This
   structure is used for storing the SPI and IP protocol of the deleted IPsec
   SPI to the SshPmP1. The sending of delete notification is delayed during
   policy reconfiguration (otherwise engine would drop the notification),
   if the IKE SA window is full or in SA handler error cases. The delayed
   delete notifications are sent as soon as possible. The delete notifications
   may be sent in a single informational exchanges. */
typedef struct SshPmIPsecDeleteNotificationRequestRec
*SshPmIPsecDeleteNotificationRequest;
typedef struct SshPmIPsecDeleteNotificationRequestRec
SshPmIPsecDeleteNotificationStruct;

struct SshPmIPsecDeleteNotificationRequestRec
{
  SshUInt32 ike_sa_handle;
  SshInetIPProtocolID ipproto;
  SshUInt32 spi;
  SshPmIPsecDeleteNotificationRequest next;
};

#ifdef SSHDIST_IKE_EAP_AUTH
/** An EAP protocol object. */
struct SshPmEapProtocolRec
{
  SshUInt8 eap_type;
  SshUInt8 preference;
  SshUInt32 transform;
};

typedef struct SshPmEapProtocolRec SshPmEapProtocolStruct;
typedef struct SshPmEapProtocolRec *SshPmEapProtocol;
#endif /* SSHDIST_IKE_EAP_AUTH */

/** A tunnel local IP list element. */
typedef struct SshPmTunnelLocalIpRec *SshPmTunnelLocalIp;
struct SshPmTunnelLocalIpRec
{
  SshUInt8 static_ip : 1;       /** Statically configured. */
  SshUInt8 unavailable : 1;     /** IP is unavailable. */
  SshPmTunnelLocalIp next;      /** Next. */
  SshUInt32 precedence;         /** Precedence. */
  SshIpAddrStruct ip;           /** IP. */
};

#ifdef SSHDIST_IPSEC_DNSPOLICY
/** A tunnel local DNS address list element. */
typedef struct SshPmTunnelLocalDnsAddressRec *SshPmTunnelLocalDnsAddress;
struct SshPmTunnelLocalDnsAddressRec
{
  SshPmTunnelLocalDnsAddress next;
  SshUInt32 precedence;
  SshPmDnsReference ref;
  char *name;
  /** Pointer to local IP address chain in 'tunnel->local_ip' list.  */
  SshPmTunnelLocalIp ip;
  /** Number of local IP address elements in the chain. */
  SshUInt32 num_ips;
};
#define SSH_PM_TUNNEL_NUM_LOCAL_DNS_ADDRS(tunnel) \
((tunnel)->num_local_dns_addresses)
#else /* SSHDIST_IPSEC_DNSPOLICY */
#define SSH_PM_TUNNEL_NUM_LOCAL_DNS_ADDRS(tunnel) 0
#endif /* SSHDIST_IPSEC_DNSPOLICY */

/** A tunnel local interface list element. */
typedef struct SshPmTunnelLocalInterfaceRec *SshPmTunnelLocalInterface;
struct SshPmTunnelLocalInterfaceRec
{
  SshPmTunnelLocalInterface next;
  SshUInt32 precedence;
  char *name;
  /** Pointer to local IP address chain in 'tunnel->local_ip' list.  */
  SshPmTunnelLocalIp ip;
  /** Number of local IP address elements in the chain. */
  SshUInt32 num_ips;
};
#define SSH_PM_TUNNEL_NUM_LOCAL_IFACES(tunnel) \
((tunnel)->num_local_interfaces)

/** Macro to count the total number of configured local IP addresses, local
    DNS addresses, and local interfaces. */
#define SSH_PM_TUNNEL_NUM_LOCAL_ADDRS(tunnel) \
((tunnel)->num_local_ips \
+ SSH_PM_TUNNEL_NUM_LOCAL_DNS_ADDRS(tunnel) \
+ SSH_PM_TUNNEL_NUM_LOCAL_IFACES(tunnel))

/** Address pool ID type. */
typedef SshUInt32 SshPmAddressPoolId;

#ifdef SSHDIST_IPSEC_DNSPOLICY
typedef struct
{
  SshPmDnsReference ref;
  SshUInt32 peer_index;
  SshUInt32 num_peers;
} SshPmDnsPeerStruct, *SshPmDnsPeer;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

/** A tunnel object. */
struct SshPmTunnelRec
{
  /** ADT header for Tunnel store by tunnel id. */
  SshADTBagHeaderStruct adt_header;

  /** Back-pointer to our Policy Manager. */
  SshPm pm;

  /** Human-readable string representing name of tunnel for use in
      audit events. */
  char *tunnel_name;

  /** Unique tunnel ID for this tunnel.  All packets exiting this
      tunnel will be restarted with this tunnel ID. */
  SshUInt32 tunnel_id;

  /** Number of references to this tunnel. */
  SshUInt32 refcount;

  /** Number of rules referring to this tunnel. This is used for detecting if
      a tunnel is part of the active policy. */
  SshUInt32 referring_rule_count;

  /** The outer tunnel in nested tunneling. */
  SshPmTunnel outer_tunnel;

  /** Transformation parameters. */
  SshPmTransform transform;

  /** Transformation flags. */
  SshUInt32 flags;

  /** IKE window size. */
  SshUInt32 ike_window_size;

  /** Optional properties for the tunnel's algorithms. */
  SshPmAlgorithmProperties algorithm_properties;

  /** An optional local port to be used with the tunnel. */
  SshUInt16 local_port;

  /** Number of optional local IP addresses. */
  SshUInt32 num_local_ips;

  /** List of optional local IP addresses to be used with the tunnel. */
  SshPmTunnelLocalIp local_ip;

#ifdef SSHDIST_IPSEC_MOBIKE
  /** Status of local IP addresses. */
  Boolean local_ip_changed;
#endif /* SSHDIST_IPSEC_MOBIKE  */

  /** Number of optional local interfaces. */
  SshUInt32 num_local_interfaces;

  /** List of optional local interfaces to be used with the tunnel. */
  SshPmTunnelLocalInterface local_interface;

#ifdef SSHDIST_IPSEC_DNSPOLICY
  /** Number of configured local DNS addresses. */
  SshUInt32 num_local_dns_addresses;

  /** List of optional local DNS addresses to be used with the tunnel. */
  SshPmTunnelLocalDnsAddress local_dns_address;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  /** The IP addresses of the gateways at the other end of the
      tunnel. It is assumed that all gateways correspond to a single
      entity, in particular that each gateway is authenticated using
      the same mechanisms. */
  SshUInt16 num_peers;

  /** Array of tunnel peers. */
  SshIpAddr peers;

  SshUInt16 last_attempted_peer;

#ifdef SSHDIST_IPSEC_DNSPOLICY
  SshUInt16 num_dns_peers;
  SshPmDnsPeer dns_peer_ip_ref_array;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  /** Optional identity for the local and remote ends of the tunnel.
      The remote end identity is only applicable when acting as IKE
      initiator. If set, then this identity will be used in IKEv2
      Phase-I for requesting the remote identity it wishes to speak
      with. */
  SshIkev2PayloadID local_identity;
  SshIkev2PayloadID remote_identity;
  /* A constraint on the identity type to use, this is used to select
     the IKE identity when multiple identities are present in a certificate. */
  SshPmIdentityType id_type;

  /** Authentication domains for this tunnel. */
  char *auth_domain_name;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /* Second local identity for the tunnel. */
  SshIkev2PayloadID second_local_identity;
  SshPmIdentityType second_id_type;

  /* Second auth domain to be used in the second IKE authentication round. */
  char *second_auth_domain_name;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


  /** List of tunnels changed during DNS name reconfiguration. */
  SshPmTunnel next;

  /* Internal tunnel flags. */
  unsigned int outer_tunnel_ike_sa : 1; /** Use outer tunnel for IKE SA neg. */
  unsigned int as_active : 1;   /** Auto-start active for this tunnel. */
  unsigned int as_rule_pending : 1; /** Rule waiting for auto-start up.*/
  unsigned int ike_tn : 1;      /** IKE keyed tunnel. */
  unsigned int manual_tn : 1;   /** Manually keyed tunnel. */
  unsigned int enforce_local_id : 1;   /** Enforce local identity. */
  unsigned int enforce_remote_id : 1;   /** Enforce remote identity. */
  unsigned int ike_dhgroup_modified : 1; /** Global IKE DH group preferences
                                            modified */
  unsigned int pfs_dhgroup_modified : 1; /** Global PFS DH group preferences
                                            modified. */

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 extension[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /** Virtual adapter context. */
  SshPmVip vip;
  /** Virtual adapter name. */
  unsigned char vip_name[SSH_INTERCEPTOR_IFNAME_SIZE];
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSH_IPSEC_TCPENCAP
  /** IPsec over TCP configuration. */
  struct
  {
    SshUInt16 local_port;
    SshUInt16 peer_port;
  } tcp_encaps_config;
#endif /* SSH_IPSEC_TCPENCAP */

  /** Type dependent parameters. */
  union
  {
    /** IKE keyed tunnels. */
    struct
    {
      /** Algorithms for IKE SAs. */
      SshUInt32 algorithms;

      /** Diffie-Hellman groups and properties for IKE; the preferences
          of these groups are taken from the global default values. */
      SshUInt32 ike_groups;

      /** Diffie-Hellman groups and properties for PFS; the preferences
          of these groups are taken from the global default values. */
      SshUInt32 pfs_groups;

      /** Diffie-Hellman groups for IKE whose preferences differ from the
          global defaults, only relevant when tunnel->ike_dhgroup_modified
          is set; in this case the tunnel has its own copies of the
          SshPmDHGroup objects. */

      SshUInt32 num_tunnel_ike_groups;
      /** Diffie-Hellman groups for IKE whose preferences differ from the
          global defaults, only relevant when tunnel->ike_dhgroup_modified
          is set; in this case the tunnel has its own copies of the
          SshPmDHGroup objects. */
      SshPmDHGroup tunnel_ike_groups;

      /** Diffie-Hellman groups for PFS whose preferences differ from the
          global defaults, only relevant when tunnel->pfs_dhgroup_modified
          is set; in this case the tunnel has its own copies of the
          SshPmDHGroup objects. */
      SshUInt32 num_tunnel_pfs_groups;

      /** Diffie-Hellman groups for PFS whose preferences differ from the
          global defaults, only relevant when tunnel->pfs_dhgroup_modified
          is set; in this case the tunnel has its own copies of the
          SshPmDHGroup objects. */
      SshPmDHGroup tunnel_pfs_groups;

      /** SA lifetime in seconds. */
      SshUInt32 life_seconds;

      /** SA lifetime in kilobytes. */
      SshUInt32 life_kb;

      /** IKE SA lifetime in seconds. */
      SshUInt32 ike_sa_life_seconds;

#ifdef SSHDIST_IKE_CERT_AUTH
      /** Manually configured local certificate, the key identifier is
          stored here. It is in CM format. */
      unsigned char *local_cert_kid;
      size_t local_cert_kid_len;
#endif /* SSHDIST_IKE_CERT_AUTH */

      /** IKE pre-shared secrets. */
      SshUInt32 num_secrets;

      /** IKE pre-shared secrets. */
      SshPmPsk secrets;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      /** Attribute allocation callback for remote access servers. */
      SshPmRemoteAccessAttrsAllocCB remote_access_alloc_cb;
      /** Attribute free callback for remote access servers. */
      SshPmRemoteAccessAttrsFreeCB remote_access_free_cb;
      void *remote_access_cb_context;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      /** The address(es) to request when doing IKE config mode. */
      SshUInt8 num_irac_addresses;
      SshIpAddrStruct irac_address[SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES];
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      SshUInt8 versions;
    } ike;

    /** Manually keyed tunnels. */
    struct
    {
      /** Inbound and outbound SPIs for ESP. */
      SshUInt32 esp_spi_in;
      SshUInt32 esp_spi_out;

      /** Inbound and outbound SPIs for AH. */
      SshUInt32 ah_spi_in;
      SshUInt32 ah_spi_out;

      /** Inbound and outbound CPIs for IPComp. */
      SshUInt16 ipcomp_cpi_in;
      SshUInt16 ipcomp_cpi_out;

      /** Raw key material. */
      unsigned char *key;
      size_t key_len;

      /** Transform implementing this tunnel; since we do not have to
          worry about proxy IDs, this transform is shared for all rules
          using the same tunnel. */
      SshUInt32 trd_index;

      /** IP protocol version or the transform. All rules referring to
          a manually keyed tunnel must have the same IP protocol version. */
      SshInterceptorProtocol trd_inner_protocol;
    } manual;
  } u;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /* Address pool id. */
  SshPmAddressPoolId address_pool_ids[SSH_PM_TUNNEL_MAX_ADDRESS_POOLS];
  SshUInt32 num_address_pool_ids;
#endif /*SSHDIST_IPSEC_REMOTE_ACCESS_SERVER*/

#ifdef SSHDIST_IPSEC_SA_EXPORT
  /** Application specific identifier. */
  unsigned char *application_identifier;
  size_t application_identifier_len;
#endif /* SSHDIST_IPSEC_SA_EXPORT */

  /** VRF routing instance identifier and name */
  SshVriId routing_instance_id;
  char routing_instance_name[SSH_INTERCEPTOR_VRI_NAMESIZE];

#ifdef SSHDIST_IKE_REDIRECT
  /** IKE redirect */
  SshIpAddrStruct ike_redirect_addr[1];
#endif /* SSHDIST_IKE_REDIRECT */
};

typedef struct SshPmTunnelRec SshPmTunnelStruct;


/** An authentication domain object. */
struct SshPmAuthDomainRec
{
  /** ADT header for authentication domain store. */
  SshADTBagHeaderStruct adt_header;

  /** Policy Manager. */
  SshPm pm;

  /** Human-readable name of the authentication domain. */
  char *auth_domain_name;
  SshUInt32 reference_count;

  /** Generation of the authentication domain. This number is stored
      to externalkey providers in order to track the correct default
      authentication domain in case of authentication domain reset. */
  SshUInt32 generation;

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  /* CMi functionality. */
  SshCMContext cm;

  SshPmCmStopCB cm_stop_callback;
  void *cm_stop_callback_context;
  Boolean cm_stopped;
#endif /* SSHDIST_CERT */

  SshADTContainer ca_container;
  SshPmCa *cas;
  SshUInt32 num_cas;
#endif /* SSHDIST_IKE_CERT_AUTH */

  SshPrivateKey private_key;
  SshPublicKey public_key;

  /* PSK functionality */

  /** An ADT bag containing remote IKE preshared keys. */
  SshADTContainer ike_preshared_keys;


#ifdef SSHDIST_IKE_EAP_AUTH
  /* EAP functionality */

  /** Static EAP and EAP with radius backed configuration. The
      callbacks on configuration are set by appropriate backends.  */
  SshEapConfiguration eap_config;

  /** Configured EAP protocols for this tunnel. */
  SshUInt32 num_eap_protocols;
  SshPmEapProtocol eap_protocols;
#endif /* SSHDIST_IKE_EAP_AUTH */


  /* RADIUS functionality */
#ifdef SSHDIST_RADIUS
  /** Authentication with RADIUS. */
  SshRadiusClient radius_client;
  SshRadiusClientServerInfo radius_server_info;

  /** XAUTH RADIUS handle. */
  SshPmAuthRadius radius_auth;
#endif /* SSHDIST_RADIUS */

  /** Passwords. */
  SshPmAuthPasswd passwd_auth;
};

typedef struct SshPmAuthDomainRec SshPmAuthDomainStruct;

/** Authentication data. */
struct SshPmAuthDataRec
{
  SshPm pm;

  /** Phase-1 SA. */
  SshPmP1 p1;

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
  /** XAUTH credentials. */
  SshPmXauthType xauth_type;
  void *xauth_attributes;
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */
  SshIkev2ExchangeData ed;

};

typedef struct SshPmAuthDataRec SshPmAuthDataStruct;

struct SshPmSaCallbacksRec
{
  union {
    SshIkev2SpdFillSACB fill_sa_cb;
    SshIkev2SpdSelectSACB select_sa_cb;
    SshIkev2SpdNarrowCB narrow_cb;
    SshIkev2SpdNotifyCB notify_cb;

    SshIkev2SadIkeSaAllocateCB ike_sa_allocate_cb;
    SshIkev2SadIPsecSpiAllocateCB ipsec_spi_allocate_cb;
    SshIkev2SadDeleteCB delete_cb;
    SshIkev2SadDeleteReceivedCB delete_received_cb;
    SshIkev2SadRekeyedCB rekeyed_cb;
    SshIkev2SadIkeSaGetCB ike_sa_get_cb;
    SshIkev2SadIkeSaEnumerateCB ike_sa_enumerate_cb;
    SshIkev2SadIPsecSaInstallCB ipsec_sa_install_cb;

    SshIkev2PadNewConnectionCB new_connection_cb;
#ifdef SSHDIST_IKE_REDIRECT
    SshIkev2PadIkeRedirectCB ike_redirect_cb;
#endif /* SSHDIST_IKE_REDIRECT */
    SshIkev2PadIDCB id_cb;
#ifdef SSHDIST_IKE_CERT_AUTH
    SshIkev2PadGetCAsCB get_cas_cb;
    SshIkev2PadGetCertificatesCB get_certificates_cb;
    SshIkev2PadPublicKeyCB public_key_cb;
#endif /* SSHDIST_IKE_CERT_AUTH */
    SshIkev2PadSharedKeyCB pre_shared_key_cb;
#ifdef SSHDIST_IKE_EAP_AUTH
    SshIkev2PadEapRequestCB eap_request_cb;
#endif /* SSHDIST_IKE_EAP_AUTH */
    SshIkev2PadConfCB conf_cb;
    SshIkev2PadAddVendorIDCB add_vendor_id_cb;
    void *unused;
  } u;
  void *callback_context;
  SshOperationHandleStruct operation[1];
  Boolean aborted;
};

typedef struct SshPmSaCallbacksRec *SshPmSaCallbacks;
typedef struct SshPmSaCallbacksRec  SshPmSaCallbacksStruct;


#ifdef SSHDIST_IKE_EAP_AUTH
/** EAP state. */
typedef struct SshPmEapStateRec {

  SshEap eap;
  SshEapConnection connection;
  SshEapConfiguration config;

  SshPmP1 p1;
  SshPm pm;

  SshUInt8 eap_type;
  SshUInt8 eap_try;

#ifdef SSHDIST_RADIUS
  SshEapRadiusConfigurationStruct radius_config;
#endif /* SSHDIST_RADIUS */

#ifdef SSHDIST_RADIUS
  unsigned int radius_enabled : 1;  /** Using RADIUS. */
#endif /* SSHDIST_RADIUS */
  unsigned int protocol_done : 1;   /** EAP protocol has completed. */
  unsigned int client : 1;          /** Client or server? */
  unsigned int peer_ok : 1;         /** Client has authenticated. */
  unsigned int auth_ok : 1;         /** Server has authenticated. */
  unsigned int request_pending : 1; /** Has the IKE layer requested a packet.*/
  unsigned int packet_ready : 1;    /** Is there a packet ready for IKE? */
  unsigned int user_required : 1;   /** Username required from LA-CB. */
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  unsigned int second_auth : 1;     /** Running second IKE authentication. */
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  /** Linearized EAP packet. */
  unsigned char *packet; size_t packet_len;

  /** Length of user. */
  unsigned char *user; size_t user_len;
  /** Length of salt. */
  unsigned char *salt; size_t salt_len;
  /** Length of secret. */
  unsigned char *secret; size_t secret_len;
  /** Length of passcode. */
  unsigned char *passcode; size_t passcode_len;
  /** Length of next PIN. */
  unsigned char *nextpin; size_t nextpin_len;
  /** Length of answer. */
  unsigned char *answer; size_t answer_len;
  /** Input buffer. */
  unsigned char *auth_input_buf;
  /** Length of input buffer. */
  size_t auth_input_len;
  /** Input position. */
  size_t auth_input_pos;
  /** Output buffer. */
  unsigned char *auth_output_buf;
  /** Length of output buffer. */
  size_t auth_output_len;

#ifdef SSHDIST_SIM
  /** SIM/USIM card context. */
  void *sim;
#endif /* SSHDIST_SIM */

#ifdef SSHDIST_EAP_TLS
  /** In EAP-TLS id for private key may need to be stored here. */
  unsigned char *key_id;
#endif /* SSHDIST_EAP_TLS */

  /** Sent to peer for verbose identification request. */
  Boolean request_identity;
  /** Identification request string. */
  unsigned char *identity_req_string;
  /** Length of the identification request string. */
  size_t identity_req_string_len;

  /** Delayed callbacks. */
  SshPmSaCallbacksStruct callbacks;

  SshTimeoutStruct timeout;

} *SshPmEapState;
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IPSEC_MOBIKE
/** A callback function of this type is used to notify completion of a
    MobIKE operation. */
typedef void (*SshPmMobikeStatusCB)(SshPm pm,
                                    SshPmP1 p1,
                                    Boolean status,
                                    void *context);

/** The maximum times that an address update can be restarted. */
#define SSH_PM_MOBIKE_ADDRESS_UPDATE_MAX_RETRY_COUNT 10

typedef struct SshPmMobikeRec
{
  /* Abort flags. */
  SshUInt8 aborted : 1;             /** Address update is aborted. */
  SshUInt8 non_abortable : 1;       /** Non-abortable sub-operation ongoing. */

  /* Fields used in address update. */
  SshUInt8 multiple_addresses_used : 1; /** Multiple addresses used. */
  SshUInt8 ipsec_sa_updated : 1;        /** IPsec SA updated. */
#ifdef SSH_IPSEC_TCPENCAP
  /* Old TCP encapsulation IKE SA flag value. */
  SshUInt8 old_use_tcp_encaps : 1;
#endif /* SSH_IPSEC_TCPENCAP */

  /** Address update retry count. */
  SshUInt8 retry_count;

  /** Flags. */
  SshUInt32 flags;
  /** RRC policy. */
  SshUInt32 rrc_policy;

  /** Thread. */
  SshFSMThreadStruct thread[1];
  /** Operation. */
  SshOperationHandleStruct op[1];

  /** IKEv2 error. */
  SshIkev2Error error;
  /** p1. */
  SshPmP1 p1;
  /** Tunnel. */
  SshPmTunnel tunnel;

  /* Current / new addresses. */
  SshIpAddrStruct remote_ip[1]; /** Current/new remote IP address. */
  SshIpAddrStruct local_ip[1];  /** Current/new local IP address. */
  SshUInt16 remote_port;        /** Current/new remote port. */
  SshUInt16 local_port;         /** Current/new local port. */
  SshUInt32 natt_flags;         /** Current/new NAT-T flags. */

  /* Old addresses. */
  SshIpAddrStruct old_remote_ip[1];     /** Old remote IP address. */
  SshIpAddrStruct old_local_ip[1];      /** Old local IP address. */
  SshUInt16 old_remote_port;            /** Old remote port. */
  SshUInt16 old_local_port;             /** Old local port. */
  SshUInt32 old_natt_flags;             /** Old NAT-T flags. */

  /** Current index into the IKE SA's array of additional addresses;
      used by MobIKE responders during forced address update when searching
      for a remote address to send the additional address exchange notify,
      and by MobIKE initiator when restarting after UNEXPECTED_NAT_DETECTED. */
  int address_index;

  /* Common fields used in address update and sending additional addresses. */
  SshPm pm;
  SshPmMobikeStatusCB callback;
  void *context;
} SshPmMobikeStruct, *SshPmMobike;

typedef enum {
 /* Operation not suspended. Keep as zero. */
  SSH_PM_MOBIKE_OP_NOT_SUSPENDED = 0,

  /* Operation for updating the list of additional addresses */
  SSH_PM_MOBIKE_OP_ADDITIONAL_ADDRESSES = 1,

 /* Operation for address update */
  SSH_PM_MOBIKE_OP_INITIATOR_ADDRESS_UPDATE = 2,

  /* Responder operation for updating the list of additional
     addresses when its currently in-use address disappears. The
     name of 'responder address update' is a mistake since MOBIKE
     responders never do address update as specified in RFC 4555. */
  SSH_PM_MOBIKE_OP_RESPONDER_ADDRESS_UPDATE = 3
} SshPmMobikeSuspendedOperationType;

#endif /* SSHDIST_IPSEC_MOBIKE */

#define SSH_PM_IKE_SA_LOCAL_PORT(ike_sa)                                  \
   ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) ?           \
     ike_sa->server->nat_t_local_port : ike_sa->server->normal_local_port)

#define SSH_PM_IKE_SA_REMOTE_PORT(ike_sa)                                  \
   ((ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) ?           \
     ike_sa->server->nat_t_remote_port : ike_sa->server->normal_remote_port)


/** Policy manager data for IKE Phase-1 SAs. */
struct SshPmP1Rec
{
  /** Keep this as the first element. */
  SshIkev2SaStruct ike_sa[1];

  /** Index of this P1 on ssh_pm_p1 array, used as ike_sa_handle at
      the PM and Engine control. */
  SshUInt32 index;

  /** Pointer to the policy manager. This is used e.g. in timeouts. */
  SshPm pm;

#ifdef DEBUG_LIGHT
  SshUInt32 magic;
#endif /* DEBUG_LIGHT */

  /** Link fields for the hash of completed IKE SAs. */

  /** Remote IP hash. */
  SshPmP1 hash_next;
  SshPmP1 hash_prev;

  /** Remote ID hash. */
  SshPmP1 hash_id_next;
  SshPmP1 hash_id_prev;

  /** Resume queue */
  SshPmP1 resume_queue_next;

  /** Expiry time of this IKE SA (when it should be rekeyed). The expiry
      time is also used for reaping half-open IKE SA's before the IKE
      negotiation is completed. */
  SshTime expire_time;

  /** Lifetime of this IKE SA. */
  SshTime lifetime;

  /** IKE SA rekey attempt counter. */
  SshUInt8 rekey_attempt;

  /* Flags. */
  unsigned int done : 1;         /** IKE SA done (terminal). */
  unsigned int failed : 1;       /** IKE SA negotiation failed (terminal).*/
  unsigned int received_1contact : 1; /** Received INITIAL-CONTACT from peer */
  unsigned int unusable : 1;     /** The SA cannot be used for new negotiations
                                     (it is deleted/rekeyed or currently
                                     being rekeyed/deleted). */
  unsigned int enable_sa_events : 1; /** SA events are enabled for this SA. */
  unsigned int rekey_notified : 1; /** The rekey policy call has been called */
  unsigned int rekeyed : 1;      /** The SA has been rekeyed */
  unsigned int rekey_pending : 1; /** The SA has to be rekeyed once all
                                      ongoing negotiations are finished. */

  /** Explicitly request child SA deletion.  For IKEv1 if this is
      set, then all IPsec SAs negotiated using this IKE SA will be
      deleted when deleting this IKE SA.  Currently this is used to force
      IPsec SA deletion on DPD failure and when deleting SAs by peer. */
  unsigned int delete_child_sas : 1;
  unsigned int delete_child_sas_started : 1; /** Deletion is ongoing. */
  unsigned int delete_child_sas_done : 1;  /** Deletion is completed. */

  /** When deleting IPsec SA's, delete this IKE SA if it is childless with
      no pending IPsec SA deletions. */
  unsigned int delete_childless_sa : 1;
  unsigned int delete_with_negotiation : 1; /** Delete p1 when p1->n is
                                                freed (for certain errors) */
  unsigned int auth_group_ids_set : 1;      /** Authorization groups are set */
  unsigned int in_resume_queue : 1;         /** IKE SA is in resume_queue. */

#ifdef SSHDIST_IKE_EAP_AUTH
  /** This negotiation uses EAP only authentication */
  unsigned int eap_only_auth : 1;
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_PM_BLACKLIST_ENABLED
  unsigned int enable_blacklist_check : 1; /** Do blacklist check for this
                                               IKE SA.*/
#endif /* SSH_PM_BLACKLIST_ENABLED */

#ifdef SSHDIST_IPSEC_MOBIKE
  unsigned int address_update_pending : 1; /** Mobike address update pending.*/
  unsigned int rrc_pending : 1;            /** Mobike rrc pending.*/

  /** MobIKE operation has been suspended because of window full and must
      be continued when IKE window has space again. */
  SshPmMobike mobike_suspended_operation;
  SshPmMobikeSuspendedOperationType mobike_suspended_op_type;
#endif /* SSHDIST_IPSEC_MOBIKE */

  /** Diffie-Hellman group used for this Phase-1. */
  SshUInt16 dh_group;

  /** The authentication domain used in this negotiation. */
  SshPmAuthDomain auth_domain;

  /** Authentication information. */
  SshPmAuthMethod local_auth_method;
  SshPmAuthMethod remote_auth_method;

  SshIkev2PayloadID local_id;
  SshIkev2PayloadID remote_id;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /** Second authentication information. */
  SshPmAuthMethod second_local_auth_method;
  SshPmAuthMethod second_remote_auth_method;

  SshIkev2PayloadID second_local_id;
  SshIkev2PayloadID second_remote_id;

  /* If we have a second authentication round, we must store reference
     to the first round auth domain here. Else it might get destroyed
     along with the certificates stored to this P1 */
  SshPmAuthDomain first_round_auth_domain;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_EAP_AUTH
  /* The identity that the remote peer used in EAP authentication if
     different to the remote IKE identity. Is NULL if EAP was not used
     or if the identity is equal to the identity used in IKE. If not NULL
     this identity must be used when performing authorization checks on
     the remote peer, as this identity and not the IKE identity is what the
     peer has used to authenticate itself. */
  SshIkev2PayloadID eap_remote_id;
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  SshIkev2PayloadID second_eap_remote_id;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef WITH_MSCAPI
  /** Remote peer's certificate. */
  SshCertificate auth_cert;

  /** Trusted CA certificate that issued (directly or via sub-CAs)
      the remote peer's certificate 'auth_cert'. */
  SshCertificate auth_ca_cert;
#else /* WITH_MSCAPI */
   /** Remote peer's certificate. */
  SshCMCertificate auth_cert;

  /** Trusted CA certificate that issued (directly or via sub-CAs)
      the remote peer's certificate 'auth_cert'. */
  SshCMCertificate auth_ca_cert;
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_IKE_CERT_AUTH */

  /** The local secret that was used for this Phase-1 authentication. */
  unsigned char *local_secret;
  size_t local_secret_len;

  /** Authorization group IDs. */
  SshUInt32 *authorization_group_ids;
  SshUInt32 num_authorization_group_ids;
  SshUInt32 *xauth_authorization_group_ids;
  SshUInt32 num_xauth_authorization_group_ids;

  /** The compatibility flags, resolved during the IKE Phase-1
     negotiation. */
  SshUInt32 compat_flags;

#ifdef SSHDIST_ISAKMP_CFG_MODE
  /** Configuration mode attributes from the remote peer or locally
      allocated for the remote peer. */
  SshPmRemoteAccessAttrs remote_access_attrs;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /** CFGMODE client given by this Phase-1 SA. */
  SshPmActiveCfgModeClient cfgmode_client;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /** The Quick-Mode threads wait on this condition variable for XAUTH
      negotiation to complete.  The thread who is handling this Phase-1
      negotiation broadcasts this condition variable when the XAUTH
      is complete or if the negotiation fails.  In the failure case,
      after waking up the waiters, the Phase-1 thread also waits on
      this condition variable that the waiters go away. */
  SshFSMConditionStruct xauth_wait_condition;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  /** Tunnel used for negotiating this Phase-1 SA */
  SshUInt32 tunnel_id;

  /** Callbacks stored for asynchronous operation. There is only one
      callback out for given P1 negotiation at any time. */
  SshPmSaCallbacksStruct callbacks;

  /** Thread for SA rekey and deletion. */
  SshFSMThreadStruct thread;

  /** Operation handle for IKE SA rekey operation. */
#define PM_IKE_INITIATOR_OP_REKEY 0
  /** Operation handle for IKE SA deletion operation. */
#define PM_IKE_INITIATOR_OP_DELETE 1
  /** Operation handle for legacy client authentication operation
      towards the application. */
#define PM_IKE_INITIATOR_OP_LA_AUTH 2

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /** Operation handle for remote access server operations. */
#define PM_IKE_INITIATOR_OP_RAS 3
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#ifdef SSHDIST_IPSEC_MOBIKE
  /** Operation handle for IKE SA address update operation. */
#define PM_IKE_INITIATOR_OP_ADDRESS_UPDATE 4
#endif /* SSHDIST_IPSEC_MOBIKE */

#define PM_IKE_NUM_INITIATOR_OPS 5

  /** Operation handle for IKE SA operations. */
  SshOperationHandle initiator_ops[PM_IKE_NUM_INITIATOR_OPS];

#define PM_IKE_MAX_WINDOW_SIZE SSH_IKEV2_MAX_WINDOW_SIZE

  /** Array of ED's associated with this IKE SA. */
  SshIkev2ExchangeData initiator_eds[PM_IKE_MAX_WINDOW_SIZE];

  /** A timeout for childless IKE SA expiry. */
  SshTime childless_sa_expire_time;

  /** Data for an active Phase-1 negotiation.  This is valid as long as
      the Phase-1 negotiation is pending.  When the negotiation is
      completed (either successfully or unsuccessfully), the 'done'
      field is set and this data is freed. */
  SshPmP1Negotiation n;

  /** Temporary authentication data.  This is constructed when needed
      and is valid only as long as the authorization takes. */
  SshPmAuthDataStruct authentication_data;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /** Network connection handle. */
  SshConnection conn_handle;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSH_IPSEC_SMALL
  /** Timeout used for rekeying IKE SA. See spd_ike_init.c, functions
      ssh_pm_ike_sa_timer, and ssh_pm_ike_sa_timer_event for
      details. */
  SshTimeoutStruct timeout[1];
#endif /* SSH_IPSEC_SMALL */

  /** Old SPI's for this IKE SA (the IKE SPI's before the last rekey).
      All zeros if this IKE SA has not rekeyed a previous IKE SA. These
      are used in the SA import/export code. */
  unsigned char old_ike_spi_i[8];
  unsigned char old_ike_spi_r[8];

  /** Delayed IPsec SA delete notifications. */
  SshPmIPsecDeleteNotificationRequest delete_notification_requests;






};

typedef struct SshPmP1Rec SshPmP1Struct;

/** Policy Manager data for IKE Phase-1 SAs negotiations.  This
    structure can be found from the `n' field of the SshPmP1Struct when
    the negotiation is active. */
struct SshPmP1NegotiationRec
{
  /** Link field for PM's list of active Phase-1 negotiations. */
  SshPmP1 next;

  /** Link field for PM's list of active Phase-1 negotiations. */
  SshPmP1 prev;

  /** IKE exchange data. */
  SshIkev2ExchangeData ed;

  /* General fields for both initiator and responder cases. */

  /** The tunnel that is used in a Phase-1 negotiation.

      In the initator case this is the tunnel we are trying to
      establish with this negotiation.

      In the responder case this is used to hold information about our
      responder policy decisions.  When we have matched an incoming IKE
      SA negotiation to a tunnel, the tunnel pointer is stored here.
      Later, if the negotiation uses pre-shared keys for
      authentication, we fetch the keys from this tunnel object. */
  SshPmTunnel tunnel;




  SshPmRule rule;
  Boolean forward;

  /** The Quick-Mode threads wait on this condition variable for this
      negotiation to complete.  The thread who is handling this Phase-1
      negotiation broadcasts this condition variable when the Phase-1
      is complete or if the negotiation fails.  In the failure case,
      after waking up the waiters, the Phase-1 thread also waits on
      this condition variable that the waiters go away. */
  SshFSMConditionStruct wait_condition;

  /** Number of threads, waiting for this Phase-1 negotiation to
      complete. */
  SshUInt32 wait_num_threads;

  SshFSMThreadStruct thread;

  /* Error from EAP module */
  SshIkev2Error eap_error;

  unsigned int conf_received_failed : 1; /** If conf payload parsing failed. */

#ifdef SSHDIST_IKE_EAP_AUTH
  unsigned int eap_received_failed : 1;  /** If EAP payload parsing failed. */
  unsigned int peer_supports_eap_only_auth : 1;  /** Peer supports mutual EAP*/
#endif /* SSHDIST_IKE_EAP_AUTH */
  unsigned int vid_requested : 1; /** Set when vendor ID's have been returned
                                      to the IKE library. */
#ifdef SSHDIST_IPSEC_MOBIKE
  unsigned int peer_supports_mobike : 1; /** Peer has sent MobIKE supported. */
#endif /* SSHDIST_IPSEC_MOBIKE */

  unsigned int transport_recv : 1; /** Unauthenticated USE_TRANSPORT_MODE
                                       notify has been received. */

  /* Reason for failure if the negotiation was not successful. */
  SshUInt32 failure_mask;
  /* Reason for failure in the case of SA selection from IKE library. */
  SshIkev2SaSelectionError ike_failure_mask;
#ifdef SSHDIST_IKE_CERT_AUTH
  /* Reason for failure from the certificate validator. */
  SshCMSearchState cmi_failure_mask;
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
  /** Certificate requests from our IKE peer. */
  struct
  {
    size_t total_cas_length;
    SshUInt32 num_cas;

    unsigned char **cas;
    size_t *ca_lens;
  } crs;

  /** Result of the find path operations, done when we were resolving
      our private key and IKE SA ID based on the received certificate
      requests. */
  SshPmCertReqResult certificate_request_results;

  /** Certificates (User and CA) received from the peer. These certs are
      identified by their Validators cache ID's and the classification to
      user and CA certificates. */
#define SSH_PM_P1N_NUM_USER_CERT_IDS 8
#define SSH_PM_P1N_NUM_CA_CERT_IDS   24
  SshUInt8 num_user_certificate_ids;
  SshUInt8 num_ca_certificate_ids;
  SshUInt8 num_cert_access_urls;
  SshUInt8 cert_access_supported;
  SshUInt32 user_certificate_ids[SSH_PM_P1N_NUM_USER_CERT_IDS];
  SshUInt32 ca_certificate_ids[SSH_PM_P1N_NUM_CA_CERT_IDS];
  char **cert_access_urls;
#endif /* SSHDIST_IKE_CERT_AUTH */

  /** Helper thread executing sub-tasks within an active Phase-1
      negotiation. This thread should only be used as a state machine
      for a single IKE policy call (it can be reused over multiple
      policy calls). */
  SshFSMThreadStruct sub_thread;

#ifdef SSHDIST_IKE_CERT_AUTH
  /** State information for different Phase-1 sub operations. */
  union
  {
    /** Certificate manager thread's find public key operation. */
    struct
    {
      /** Operation arguments. */
      const unsigned char *hash_alg;

      /** Temporary thread state. */
      SshUInt32 next_ca_index;
      SshMPInteger trusted_set;
      struct SshCMSearchInfoRec search_info;
      SshCMCertList search_list;

      /** Status from the by-ID search. */
      struct SshCMSearchInfoRec by_id_search_info;

      /** Which search key is used. */
      SshUInt8 by_id : 1;
      SshUInt8 by_ip : 1;
      SshUInt8 by_presence : 1;
    } cmt_pubkey;

    /** Certificate manager thread's certificate request operation.
        This contains also fields that are used in the processing of
        the ssh_policy_isakmp_id policy function. */
    struct
    {
      /** Operation arguments. */
      int number_of_cas;
      SshIkev2CertEncoding *ca_encodings;
      unsigned char **certificate_authorities;
      size_t *certificate_authority_lens;

      /* Temporary thread state. */

      /** The current authentication key to use. */
      SshPmEk key;

      /** The current authentication key's index in the externalkey storage. */
      SshUInt32 key_index;

      int current_ca;
      int *number_of_certificates;
      SshIkev2CertEncoding **tmp_cert_encodings;
      unsigned char ***tmp_certs;
      size_t **tmp_cert_lens;
      struct SshCMSearchInfoRec search_info;
      SshCMCertList search_list;

    } cmt_cr;

  } u;
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKE_EAP_AUTH
  /** EAP authentication state. */
  SshPmEapState eap;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  SshPmEapState second_eap;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

};
typedef struct SshPmP1NegotiationRec SshPmP1NegotiationStruct;


/** Working space for IKE SA rekey */
typedef struct SshPmIkeRekeyStructRec {
  SshPm pm;
  SshPmP1 old_p1;
  SshPmP1 new_p1;

  SshFSMThreadStruct thread;
  SshOperationHandleStruct operation[1];
  SshIkev2SadRekeyedCB reply_callback;
  void *reply_context;
} SshPmIkeRekeyStruct, *SshPmIkeRekey;

/** Macro for digging out the new IKE SA from old IKE SA after IKE SA rekey. */
#define PM_IKE_SA_REKEY_NEW_P1(old_p1, initiated)                       \
  ((SshPmP1)((old_p1)->ike_sa->rekey == NULL ? NULL :                   \
             ((initiated) ? (old_p1)->ike_sa->rekey->initiated_new_sa : \
                            (old_p1)->ike_sa->rekey->responded_new_sa)))

/** Maximum number of SA rules; one APPLY rule for each traffic selector pair,
    one IKE APPLY and one IKE PASS rule for all traffic selector pairs of each
    inner tunnel. */
#define SSH_PM_MAX_SA_RULES (1 + (2 * SSH_PM_MAX_INNER_TUNNELS) * \
SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS * SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS)

/** Working space for SA handler thread. */
typedef struct SshPmSaHandlerDataRec
{
  /** The transform data structure the SA handler thread is
     constructing.  This is only used by the SA handler thread. */
  SshEngineTransformStruct trd;

  SshUInt16 added_index;  /** current index into 'sa_indices' of added rules */
  SshUInt16 delete_index; /** current index into 'sa_indices' of rules
                             getting deleted if the SA handler fails */

  /** Array of indicies of SA rules added to the engine by SA handler thread */
  SshUInt32 sa_indices[SSH_PM_MAX_SA_RULES];

  /** Temporary traffic selectors for inner tunnel IKE rules. */
  SshIkev2PayloadTS ike_local_ts;
  SshIkev2PayloadTS ike_remote_ts;
  size_t local_ts_index;
  size_t remote_ts_index;

  /** IKE ports of processed inner tunnels. */
  SshUInt16 inner_local_ike_ports[SSH_PM_MAX_INNER_TUNNELS];
  SshUInt16 inner_local_ike_natt_ports[SSH_PM_MAX_INNER_TUNNELS];
  SshUInt16 inner_remote_ike_ports[SSH_PM_MAX_INNER_TUNNELS];
  SshUInt16 inner_remote_ike_natt_ports[SSH_PM_MAX_INNER_TUNNELS];
  Boolean inner_ike_forward[SSH_PM_MAX_INNER_TUNNELS];

} *SshPmSaHandlerData, SshPmSaHandlerDataStruct;


typedef enum
{
  SSH_PM_ED_DATA_UNKNOWN = 0,
  SSH_PM_ED_DATA_QM,
  SSH_PM_ED_DATA_INFO_QM,
  SSH_PM_ED_DATA_INFO_P1,
#ifdef SSHDIST_IPSEC_MOBIKE
  SSH_PM_ED_DATA_INFO_MOBIKE,
#endif /* SSHDIST_IPSEC_MOBIKE */
  SSH_PM_ED_DATA_INFO_DPD,
  SSH_PM_ED_DATA_INFO_OLD_SPI
} SshPmExchangeDataType;

/* Error codes in the Quick-Mode 'error' field that are internal to the
   Policy Manager, they must be different to the IKE library's error
   codes SshIkev2Error. */
#define SSH_PM_QM_ERROR_P1_FAILED    0x50000  /** The Phase-I the QM was
                                                 waiting for has failed. */
#define SSH_PM_QM_ERROR_NO_IKE_PEERS 0x50001  /** No IKE peers found. */

#define SSH_PM_QM_ERROR_INTERNAL_PM  0x50002 /** Internal PM error. */

#define SSH_PM_QM_ERROR_NETWORK_UNAVAILABLE  0x50003 /** Network
                                                     unavailable error. */

/** Policy Manager data for IKE Quick-Mode negotiations.  This
   structure can always be found from the 'application_context' field
   of the SshIkev2ExchangeData structure in initial and create child
   exchanges. */
struct SshPmQmRec
{
  /** Identifies structure as QM when referenced from ed->application_context.
      This field must be the first field of the structure, and its value must
      be set to SSH_PM_ED_DATA_QM when allocating a QM. */
  SshPmExchangeDataType type;

#ifdef DEBUG_LIGHT
  SshUInt32 magic;
#endif /* DEBUG_LIGHT */

  /* General fields for both initiator and responder cases. */

  /** IKE/IPSec exchange data. */
  SshIkev2ExchangeData ed;

  /** Error status from calls to the IKE library API. Either an SshIkev2Error
     code or else one of the policy manager internal codes SSH_PM_QM_ERROR_*
     defined above. */
  int error;

  /* Flags. */
  unsigned int initiator : 1;       /** We are the initiator of this QM. */
  unsigned int forward : 1;         /** The direction of this negotiation. */
  unsigned int trigger : 1;         /** A trigger Quick mode. */
  unsigned int send_trigger_ts : 1; /** Send the trigger packet as IKE TS. */
  unsigned int ike_done : 1;        /** IKE Quick-Mode done. */
  unsigned int sa_handler_done : 1; /** SA handler done. */
  unsigned int rekey : 1;           /** This is a Quick-Mode rekey. */
  unsigned int send_initial_contact : 1; /** Send initial contact. */
  unsigned int transport_sent : 1;  /** Transport mode request sent */
  unsigned int transport_recv : 1;  /** Transport mode request received */
  unsigned int tunnel_accepted : 1;  /** Policy allows tunnel mode */
  unsigned int auto_start : 1;      /** An auto-start Quick-Mode. */
  unsigned int aborted : 1;         /** Quick-Mode aborted. */
  unsigned int delete_trd_on_error : 1; /** Delete trd in SA handler error */
  unsigned int delete_peer_ref_on_error : 1; /** Delete IKE peer reference
                                                 in SA handler error */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  unsigned int delete_vip_ref_on_error : 1; /** Delete VIP reference in SA
                                                handler error. */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  unsigned int additional_ts_received : 1; /** Received this notify message */
  unsigned int dpd : 1;             /** Used for DPD exchanges */
#ifdef SSHDIST_IPSEC_XAUTH_SERVER
#ifdef SSHDIST_IKEV1
  unsigned int waiting_xauth : 1; /** QM SPI allocation sub-thread is waiting
                                      for XAUTH to complete */
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

  unsigned int is_sa_rule_modified : 1; /** Did the SA handler choose different
                                        selectors for the rule. */
  unsigned int spi_neg_started : 1; /** Has this QM marked the SPI out as
                                        having a negotiation ongoing. */

  unsigned int allocating_ike_sa : 1; /** Has this QM marked the peer as
                                          allocating an IKE SA. */

#ifdef SSHDIST_IPSEC_SA_EXPORT
  unsigned int import : 1;            /** This QM is for IPsec SA import. */
#endif /* SSHDIST_IPSEC_SA_EXPORT */

  unsigned int simultaneous_rekey : 1; /** Simultaneous rekey has been
                                           detected. */

  unsigned int simultaneous_rekey_nonce_local : 1; /** The smallest nonce is
                                                       locally generated. */

  /** For simultaneous rekeys this contains the smallest nonce. */
  unsigned char simultaneous_rekey_nonce_data[SSH_IKEV2_NONCE_SIZE];
  size_t simultaneous_rekey_nonce_size;

  /** For rekeys or IKEv1 DPD, the SPI value that is being rekeyed. */
  SshUInt32 old_inbound_spi;
  SshUInt32 old_outbound_spi;

  /** The index of the next IKE peer to try.  This picks one peer from
     the tunnel's remote peer list or the `sel_dst' if tunnel does
     not specify any peers. */
  SshUInt32 next_peer_index;

  /** The initial local and remote addresses of the Phase-1.
      These addresses are chosen before the negotiation begins.
      When the negotiation completes the local and remote addresses
      may be different from these addresses.  Therefore these addresses
      must not be used after the negotiation has been started. */
  SshIpAddrStruct initial_local_addr;
  SshIpAddrStruct initial_remote_addr;

  /** Timeout for triggering packet resend and rekey outbound delayed
      installation. */
  SshTimeoutStruct timeout[1];

  /** Handle to the peer used for creating this Quicksec Mode. Used
      for rekeys and DPD for finding the correct IKE peer and P1 object.
      When set this must be protected by a peer handle reference. This
      reference is freed when the qm is freed. */
  SshUInt32 peer_handle;

  /** The Phase-1 we are using for this Quick-Mode.  This is also the
     Phase-1 we are waiting if it was in progress when we were
     started. */
  SshPmP1 p1;

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
/** Packet's original source and destination IP address, before ANY
     nat was applied. */
  SshIpAddrStruct packet_orig_src_ip;
  SshUInt16 packet_orig_src_port;

  /** Packet's new destination IP address and port, taken NAT
     configuration. */
  SshIpAddrStruct packet_orig_dst_ip;
  SshUInt16 packet_orig_dst_port;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  /** The flow_index of trigger flow in packet triggered qm negotiations. */
  SshUInt32 flow_index;

  /** Reason for failure if the QM was not successful. */
  SshUInt32 failure_mask;

  /** Reason for failure in the case of SA selection from IKE library. */
  SshIkev2SaSelectionError ike_failure_mask;

  /** Diffie-Hellman group used in optional PFS. */
  SshUInt16 dh_group;

  /** FSM thread, executing this negotiation. */
  SshFSMThreadStruct thread;

  /** The rule for which this Quick-Mode negotiation thread is
      negotiating IPSec SAs.  In the intiator case this is the rule
      from which we extracted the proxy IDs.  In the responder case
      this is the rule from which we found a matching policy. */
  SshPmRule rule;

  /** The tunnel (taken from the rule) we are negotiating.  This is
     either the from- or to-tunnel. */
  SshPmTunnel tunnel;

  /** The tunnel to use for p1 negotiations. This may differ from
      `qm->tunnel' if using nested tunnels and the `one-ike-sa' flag. */
  SshPmTunnel p1_tunnel;

  /** Unknown SPI received in an ESP/AH packet. In the initiator case,
      if unknown_spi is nonzero, perform an informational exchange to
      send an INVALID_SPI notify payload. **/
  SshUInt32 unknown_spi;

  /** SA Traffic Selectors for the negotiated rule. */
  SshIkev2PayloadTS local_ts;
  SshIkev2PayloadTS remote_ts;

  /** Indices of local and remote TS items, used when installing the
     resulting TS's into engine at SA handler state machine. */
  size_t local_ts_item_index;
  size_t remote_ts_item_index;

  /** SA Traffic Selectors for the trigger rule. */
  SshIkev2PayloadTS local_trigger_ts;
  SshIkev2PayloadTS remote_trigger_ts;

#ifdef SSHDIST_IPSEC_IPCOMP
  /** IPPCP attributes; chosen algorithm and SPI values */
  SshUInt16 ipcomp_chosen;
  SshUInt16 ipcomp_spi_in;
  SshUInt16 ipcomp_spi_out;
#endif /* SSHDIST_IPSEC_IPCOMP */

  /** SPIs. */
  SshUInt32 spis[3];

  /** Helper thread executing sub-tasks within an active Quick-Mode
      negotiation. This thread should only be used as a state machine
      for a single IKE policy call (it can be reused over multiple
      policy calls). */
  SshFSMThreadStruct sub_thread;

  /** Callbacks stored for asynchronous operation. There is only one
     callback out for given Qm at any time. */
  SshPmSaCallbacksStruct callbacks;


  /** Working space for different sub-operations. */
  SshPmSaHandlerDataStruct sa_handler_data;

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /** Remote access attributes that a remote access client specifies
     in its Conf Request  payload. */
  SshPmRemoteAccessAttrs client_attributes;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  /** Fields used in SA creation. */

  /** The outbound rule of the SA, applying transform data `trd'. */
  SshEnginePolicyRuleStruct sa_outbound_rule;

  /** Lifetimes of the transform `trd'. */
  SshUInt32 trd_life_seconds;
  SshUInt32 trd_life_kilobytes;

  /** If the Quick-Mode was successful, this is the transform index,
     returned from the engine.  For the rekey case, this is the
     transform we are rekeying.  This is only used by the SA handler
     thread. */
  SshUInt32 trd_index;

  /** Index of the SA rule.  This is the result index from
     last ssh_pme_add_rule() call */
  SshUInt32 sa_index;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SshPmVip vip;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /** Transform properties of this Quick-Mode negotiation.  For the
      initial child SA, these are taken from the tunnel `tunnel'.
      For rekey, these are taken from our existing transform data. */
  SshPmTransform transform;

  /** Cipher and Mac key size in bits. For rekey these are taken from
      our existing transform data. For initial child SA these are zero.
      These are used in proposal construction during IPsec SA rekey. */
  SshUInt16 cipher_key_size;
  SshUInt16 mac_key_size;

  /** Fields used in the initiator case. */

  /** The triggered packet and its properties. */
  unsigned char *packet;
  size_t packet_len;

  SshInterceptorProtocol packet_protocol;
  SshUInt32 packet_tunnel_id;
  SshUInt32 packet_prev_transform_index;
  SshUInt32 packet_ifnum;
  SshUInt32 packet_iface_mtu;
  SshUInt32 packet_flags;

  /** Selectors, extracted from the triggered packet.  The `sel_dst'
     field must also be set in the rekey negotiations.  It is used if
     the tunnel does not specify any peer IP addresses.  If this is an
     auto-start negotiation, these are hand-constructed to match the
     tunnel being negotiated. */
  SshIpAddrStruct sel_src;
  SshIpAddrStruct sel_dst;
  SshInetIPProtocolID sel_ipproto;
  SshUInt16 sel_src_port;
  SshUInt16 sel_dst_port;

  /** The continuation states for the `Initiator Quick-Mode
     Negotiation' sub state-machine. */
  SshFSMStepCB fsm_qm_i_n_success;
  SshFSMStepCB fsm_qm_i_n_failed;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /** Network connection handle. */
  SshConnection conn_handle;
  /** Network connection request operation handle. */
  SshOperationHandle conn_op;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSH_IPSEC_TCPENCAP
  /** Encapsulating TCP connection mapping SPI. */
  unsigned char tcp_encaps_conn_spi[SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH];
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSHDIST_IKE_REDIRECT
  int ike_redirected;  /* counter for IKE redirections (client side) */
#endif /* SSHDIST_IKE_REDIRECT */

  /** Link fields for PM's list of active Qm negotiations. */
  SshPmQm next;
  SshPmQm prev;
};

typedef struct SshPmQmRec SshPmQmStruct;

/** Policy Manager data for informational exchanges.  This structure can
    always be found from the `ed->application_context' field
    of the SshIkev2ExchangeData structure in informational exchanges.
    This is always allocated from ed->obstack. */

struct SshPmInfoRec
{
  /** Identifies structure as SshPmInfo when referenced from
      ed->application_context.  This field must be the first field of the
      structure, and its value must be set to a proper SSH_PM_ED_DATA_INFO_*
      when allocating a PmInfo. */
  SshPmExchangeDataType type;
  union
  {
    SshPmQm qm;
    SshPmP1 p1;
#ifdef SSHDIST_IPSEC_MOBIKE
    SshPmMobike mobike;
#endif /* SSHDIST_IPSEC_MOBIKE */
    struct
    {
      SshUInt32 outbound_spi;
      SshUInt32 inbound_spi;
      SshUInt32 tr_index;
      SshUInt8 ipproto;
    } old_spi;
  } u;
};

typedef struct SshPmInfoRec SshPmInfoStruct, *SshPmInfo;

/** Peer information database entry. */

typedef struct SshPmPeerRec *SshPmPeer;
typedef struct SshPmPeerRec SshPmPeerStruct;

struct SshPmPeerRec
{
  /** Peer handle of this peer. */
  SshUInt32 peer_handle;

  /** Forward/reverse links for the pm->peer_handle_hash table. */
  SshPmPeer next_peer_handle;
  SshPmPeer prev_peer_handle;

  /** Forward/reverse links for the pm->peer_sa_hash table. */
  SshPmPeer next_sa_handle;
  SshPmPeer prev_sa_handle;

  /** Forward/reverse links for the pm->peer_local_addr_hash table. */
  SshPmPeer next_local_addr;
  SshPmPeer prev_local_addr;

  /** Forward/reverse links for the pm->peer_remote_addr_hash table. */
  SshPmPeer next_remote_addr;
  SshPmPeer prev_remote_addr;

  /** Peer address and IKE port. */
  SshIpAddrStruct remote_ip[1];
  SshUInt16 remote_port;

  /** Local address and IKE port. */
  SshIpAddrStruct local_ip[1];
  SshUInt16 local_port;

  /** IKE SA for this peer. */
  SshUInt32 ike_sa_handle;

  /** IKE identities. */
  SshIkev2PayloadID local_id;
  SshIkev2PayloadID remote_id;

  /* Flags */
  unsigned int use_ikev1 : 1; /** Use IKEv1 with this peer. */
  unsigned int manual_key : 1; /** Use manual keying with this peer. */
  unsigned int allocating_ike_sa : 1; /** A qm thread is allocating an IKE SA
                                          with this peer. */
  unsigned int ikev1_force_natt_draft_02 : 1; /** Use IKEv1 NAT-T draft 02
                                                  with this peer. */

#ifdef SSH_PM_BLACKLIST_ENABLED
  unsigned int enable_blacklist_check : 1; /** Do blacklist check for this
                                               peer. */
#endif /* SSH_PM_BLACKLIST_ENABLED */

  /** Reference counter. Permanent IKE peer references are taken for
      IKE SA and for each child SA. Temporary references are taken
      for each qm during rekey, DPD and import, and while deleting SAs.
      This field must never be modified directly but instead using the
      functions ssh_pm_peer_handle_take_ref() and ssh_pm_peer_handle_destroy().
  */
  SshUInt32 refcnt;

  /** Linked list of spi_out objects that refer to this peer object. */
  SshPmSpiOut spi_out;

  /** Number of child sas created for this peer. */
  SshUInt32 num_child_sas;

  /** VRF routing instance id */
  SshVriId routing_instance_id;

  /** Debuggable object data. */
  SshPdbgObjectStruct debug_object;

  /** Local debug address. */
  SshIpAddrStruct debug_local[1];

  /** Remote debug address. */
  SshIpAddrStruct debug_remote[1];
};


/* **************************** SA events ************************************/

/** IKE SA event handle. */
typedef struct SshPmIkeSAEventHandleRec
{
  SshPmSAEvent event;
  SshPmP1 p1;

#ifdef SSHDIST_IPSEC_SA_EXPORT
  unsigned char *tunnel_application_identifier;
  size_t tunnel_application_identifier_len;
#endif /* SSHDIST_IPSEC_SA_EXPORT*/
} SshPmIkeSAEventHandleStruct;

/** IPsec SA event handle. */

typedef enum
{
  SSH_PM_IPSEC_SA_UPDATE_UNDEFINED = 0,
  SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED = 1,
  SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED = 2
} SshPmIPsecSAUpdateType;

typedef struct SshPmIPsecSAEventHandleRec
{
  SshPmSAEvent event;

  /* Used in SSH_PM_SA_EVENT_UPDATED */
  SshPmIPsecSAUpdateType update_type;

  /* Used in SSH_PM_SA_EVENT_CREATED and SSH_PM_SA_EVENT_REKEYED */
  SshPmQm qm;

  /* Negotiated SA lifetime in seconds, set only when importing the SA. */
  SshUInt32 life_seconds;

  /* SA expire time, set only when re-exporting the SA after import. */
  SshTime expire_time;

  /* Used in SSH_PM_SA_EVENT_DELETED and in SSH_PM_SA_EVENT_UPDATED
     (update_type is SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED). */
  SshUInt32 inbound_spi;
  SshUInt32 outbound_spi;
  SshUInt8 ipproto;

  /* Used in SSH_PM_SA_EVENT_UPDATED. */
  SshPmPeer peer;

  /* Used in SSH_PM_SA_EVENT_UPDATED (update_type is
     SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED). */
  SshPmSpiOut spi_out;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  Boolean enable_natt;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSH_IPSEC_TCPENCAP
  Boolean enable_tcpencap;
  unsigned char tcp_encaps_conn_spi[8];
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSHDIST_IPSEC_SA_EXPORT
  /* Used when importing the SA. */
  unsigned char *outer_tunnel_application_identifier;
  size_t outer_tunnel_application_identifier_len;
  unsigned char *tunnel_application_identifier;
  size_t tunnel_application_identifier_len;
  unsigned char *rule_application_identifier;
  size_t rule_application_identifier_len;

  void *import_context;
#endif /* SSHDIST_IPSEC_SA_EXPORT*/
} SshPmIPsecSAEventHandleStruct;



/* **************************** IPSec SA handler *****************************/

/** IPSec SA handler for manually keyed SAs. */
Boolean ssh_pm_manual_sa_handler(SshPm pm, SshPmQm qm);

/* ******************************** Tunnels **********************************/

/** Initialize tunnels for the policy manager `pm'. */
Boolean ssh_pm_tunnels_init(SshPm pm);

/** Uninitialize tunnels from the policy manager `pm'.  This assumes
   that an appropriate shutdown has already been done and
   all tunnel object instances exist. */
void ssh_pm_tunnels_uninit(SshPm pm);

/** Return the Diffie-Hellman group with 'index' highest preference
   that is configured for the tunnel tunnel'. If 'pfs' is TRUE search for
   PFS groups for IPSec, otherwise search for IKE groups. */
SshPmDHGroup ssh_pm_tunnel_dh_group(SshPmTunnel tunnel, SshUInt32 index,
                                    Boolean pfs);

/** Updates local interface addresses for the tunnel.  This function is
    called for all existing tunnels whenever an interface change event
    occurs. */
Boolean
ssh_pm_tunnel_update_local_interface_addresses(SshPmTunnel tunnel);

#ifdef SSHDIST_IPSEC_DNSPOLICY
/** Updates local DNS address mappings for the tunnel.  This function is
    called when the DNS resolver completes. */
Boolean
ssh_pm_tunnel_update_local_dns_address(SshPmTunnel tunnel,
                                       SshIpAddr ip,
                                       SshPmDnsReference ref);
#endif /* SSHDIST_IPSEC_DNSPOLICY */

/** Selects local IP address that matches best `peer'. */
void ssh_pm_tunnel_select_local_ip(SshPmTunnel tunnel, SshIpAddr peer,
                                   SshIpAddr local_ip_ret);

/** Returns the tunnel by `tunnel_id'  */
SshPmTunnel ssh_pm_tunnel_get_by_id(SshPm pm, SshUInt32 tunnel_id);


/* ******************************** Servers **********************************/

/** A callback function of this type is called when all servers have
    been stopped are sent. */
typedef void (*SshPmServersStopDoneCB)(void *context);

/** A callback function of this type is called when all servers have
    been updated after an interface change. The 'success' variable
    indicates whether all servers have successfully been updated. */
typedef void (*SshPmServersIfaceChangeDoneCB)(SshPm pm,
                                              Boolean success, void *context);

/** Initialize servers for the policy manager `pm'. */
Boolean ssh_pm_servers_init(SshPm pm);

/** Uninitialize servers from the policy manager `pm'.  This assumes
   that an appropriate shutdown has already been done for
   negotiations, and ssh_pm_servers_stop has been called to shutdown all
   servers. */
void ssh_pm_servers_uninit(SshPm pm);

/** Server selection flags for the ssh_pm_servers_stop() function. */
#define SSH_PM_SERVER_IKE       0x00000001
#ifdef SSHDIST_L2TP
#define SSH_PM_SERVER_L2TP      0x00000002
#endif /* SSHDIST_L2TP */

/** Stop all servers matching the `flags'. The function calls the callback
   function `callback' when all servers have been stopped.*/
void ssh_pm_servers_stop(SshPm pm, SshUInt32 flags,
                         SshPmServersStopDoneCB callback, void *context);

/** Notify servers about updated interface information. Returns FALSE in
   the callback if some server could not be started on a interface,
   otherwise the callback returns with status TRUE. */
void
ssh_pm_servers_interface_change(SshPm pm,
                                SshPmServersIfaceChangeDoneCB callback,
                                void *context);

/** Additional matching criteria flags for server object selection. */
#define SSH_PM_SERVERS_MATCH_IKE_SERVER 0x00000001
#define SSH_PM_SERVERS_MATCH_IFNUM      0x00000002
#define SSH_PM_SERVERS_MATCH_PORT       0x00000004

/** Lookup a server for the local IP address `local_addr'.  The
   argument `flags' specifies additional matching criteria for the
   returned server.  The arguments `ike_server', and `ifnum' are the
   constraints for the additional selection criteria, specified by the
   argument `flags'.  The function returns a server object or NULL if
   no server could be found for the selection criteria. The returned
   server is only valid until control passes to the event loop. */
SshPmServer ssh_pm_servers_select(SshPm pm, SshIpAddr local_addr,
                                  SshUInt32 flags,
                                  SshIkev2Server ike_server,
                                  SshUInt32 ifnum,
                                  int routing_instance_id);

/** Lookup an IKE server for the local IP address `local_addr'.  The
   argument `flags' specifies additional matching criteria for the
   returned server.  The argument `ifnum' is an constraint
   for the additional selection criteria, specified by the
   argument `flags'.  The function returns a IKEv2 server object
   or NULL if no server could be found for the selection criteria.
   The returned server is only valid until control passes to the event
   loop.  */
SshIkev2Server ssh_pm_servers_select_ike(SshPm pm,
                                         SshIpAddr local_addr,
                                         SshUInt32 flags,
                                         SshUInt32 ifnum,
                                         SshUInt16 local_port,
                                         int routing_instance_id);

#ifdef SSHDIST_L2TP
/** Lookup a policy manager server object that defines the L2TP server
   `l2tp_server'. The returned server is only valid until control
   passes to the event loop. */
SshPmServer ssh_pm_servers_select_by_l2tp_server(SshPm pm,
                                                 SshL2tpServer l2tp_server);
#endif /* SSHDIST_L2TP */

/* ********************** Handling active Phase-1 SAs ************************/

/** Lookup a Phase-1 SA that is negotiated (or being currently
   negotiated) with the remote IKE peer at `dst'.  `src' defines
   the local address used for communication. This argument may be
   NULL if it is not required in the lookup. If the
   arguments 'rule' or `tunnel' is not NULL or `peer_handle' is not
   SSH_IPSEC_INVALID_INDEX, the function also checks that
   the SA matches 'rules', `tunnel's and peers constraints.  The argument
   `require_completed' specifies whether the IKE SA must be completed or
   if the negotiation can be in progress. */
SshPmP1 ssh_pm_lookup_p1(SshPm pm, SshPmRule rule, SshPmTunnel tunnel,
                         SshUInt32 peer_handle, SshIpAddr src, SshIpAddr dst,
                         Boolean require_completed);

/** Get p1 by 'ike_sa_handle'. If `ignore_unusable' is TRUE, then this will
    return NULL if the p1 is unusable. */
SshPmP1
ssh_pm_p1_from_ike_handle(SshPm pm, SshUInt32 ike_sa_handle,
                          Boolean ignore_unusable);

/** Insert the Phase-1 SA `p1' into the hash of completed IKE SAs. */
void ssh_pm_ike_sa_hash_insert(SshPm pm, SshPmP1 p1);

/** Remove the Phase-1 SAS `p1' from the hash of completed IKE SAs. */
void ssh_pm_ike_sa_hash_remove(SshPm pm, SshPmP1 p1);

/** Returns the tunnel used for negotiating the Phase-I 'p1' */
SshPmTunnel ssh_pm_p1_get_tunnel(SshPm pm, SshPmP1 p1);

/* ************************** Deleting SAs ***********************************/

/** Delete all IKE and IPsec SAs with IKE peer `peer_handle'. Argument
    `peer_handle' must be a valid handle to an IKE peer. Argument `flags'
    is a bitmask of SSH_IKEV2_IKE_DELETE_FLAGS_*. This will call `callback'
    with status TRUE if one or more matching SAs were marked for deletion,
    and with status FALSE if no SAs were marked for deletion. The actual SA
    deletion happens in a delayed fashion. */
void
ssh_pm_delete_by_peer_handle(SshPm pm, SshUInt32 peer_handle, SshUInt32 flags,
                             SshPmStatusCB callback, void *context);

/** Delete all IKE and IPsec SAs with peer whose address matches `ip'.
    Argument `ip' is the well defined IP address of the peer or NULL, in
    which case this will delete all IKE negotiated SAs in the system.
    Argument `flags' is a bitmask of SSH_IKEV2_IKE_DELETE_FLAGS_*. This
    will call `callback' with status TRUE if one or more matching SAs were
    marked for deletion, and with status FALSE if no SAs were marked for
    deletion. The actual SA deletion happens in a delayed fashion. */
void
ssh_pm_delete_by_peer(SshPm pm, SshIpAddr ip, SshUInt32 flags,
                      SshPmStatusCB callback, void *context);

/** Delete all parentless IPsec SAs (i.e. IKEv1 or manual keyed) whose local
    address matches `local_ip'. This function is called when stopping IKE
    servers to delete those IPsec SAs which would otherwise send packets using
    a non-existent local IP address. */
void
ssh_pm_delete_by_local_address(SshPm pm, SshIpAddr local_ip,
                               SshVriId routing_instance_id);

/** Delete all IKE and IPsec SAs whose remote ID matches `remote_id'. */
void
ssh_pm_delete_by_remote_id(SshPm pm,
                           SshIkev2PayloadID remote_id,
                           SshUInt32 flags);

/** Abort all ongoing IKE negotiations that are using the policy rule
    'rule'. */
void
ssh_pm_delete_rule_negotiations(SshPm pm, SshPmRule rule);

/** Utility function for checking if childless `p1' needs to be deleted.
    Note that if the `p1' is deleted, then this function returns TRUE and
    the caller must not use `p1' (unless it is explicitly protected by an
    IKE SA reference). Otherwise `p1' was not deleted and this returns
    FALSE. This function asserts that `p1' is marked for childless SA
    deletion (that is `p1->delete_childless_sa' is set to 1). **/
Boolean pm_ike_delete_childless_p1(SshPm pm, SshPmP1 p1);

/* ************************** Delete notifications ***************************/

/* Send delete notification for old inbound SPI and invalidate SPI from
   engine. */
void
ssh_pm_send_old_spi_delete_notification(SshPm pm,
                                        SshUInt32 peer_handle,
                                        SshPmTunnel tunnel,
                                        SshPmRule rule,
                                        SshInetIPProtocolID ipproto,
                                        SshUInt32 inbound_spi,
                                        SshUInt32 outbound_spi,
                                        SshUInt32 tr_index);

/** Process an incoming initial contact notification for the Phase-1
    negotiation `peer_p1'.  Note that this function will delete all related
    IPSec SAs and other IKE SAs.  Therefore, this should be called only
    if the notification was authenticated. */
void ssh_pm_process_initial_contact_notification(SshPm pm, SshPmP1 peer_p1);

/** Send an authenticated IPSec delete notification to IKE peer identified
    by `peer_handle'. The delete notification is sent for SPI `spi' for
    protocol `ipproto'. If there is no IKE SA with peer then this will lookup
    an usable IKE SA to IKE peer that was negotiated using `rule' and `tunnel'.
    If no matching IKE SA is found then this will not do anything. If the IKE
    SA is temporarily unusable because of full window, this will add a delayed
    delete notification request which will be processed later. */
void ssh_pm_send_ipsec_delete_notification(SshPm pm,
                                           SshUInt32 peer_handle,
                                           SshPmTunnel tunnel,
                                           SshPmRule rule,
                                           SshInetIPProtocolID ipproto,
                                           int num_spis,
                                           SshUInt32 *spi);

/** Equal to the above funtion, but the delete notification is sent at
    delayed manner for the IP protocol `ipproto' and SPI `spi'. This
    function allocates a delayed delete notification request for the SPI
    and adds it to the p1's list of delete notification requests. The delete
    notification will get sent later when the function
    ssh_pm_send_ipsec_delete_notification_requests() is called. */
Boolean
ssh_pm_request_ipsec_delete_notification(SshPm pm,
                                         SshPmP1 p1,
                                         SshInetIPProtocolID ipproto,
                                         SshUInt32 spi);

/** Send delayed delete notification for `p1'. This function combines
    multiple delete notification requests before sending them out. This may
    consume some or all of the delayed delete notification requests in `p1'.
    This function also checks if `p1' is childless and deletes it if
    necessary. Any IKE SA deletion will happen asynchronously after this
    function has returned. */
void
ssh_pm_send_ipsec_delete_notification_requests(SshPm pm,
                                               SshPmP1 p1);

/** Free delayed ipsec delete notifications. This should be called on error
    cases where the delete notification requests should not be sent. */
void
ssh_pm_free_ipsec_delete_notification_requests(SshPmP1 p1);

/** This is a callback function for ssh_pm_delete_by_spi(). This function
    sends a delete notification for the SPI values in `inbound_spis'. It
    expects that the context is a valid p1 that is protected by a IKE SA
    reference. This will release that IKE SA reference. */
void
ssh_pm_delete_by_spi_send_notifications_cb(SshPm pm,
                                           SshUInt8 ipproto,
                                           SshUInt8 num_spis,
                                           SshUInt32 *inbound_spis,
                                           SshUInt32 *outbound_spis,
                                           void *context);


/* ********************* Peer information database *****************/

/** Uninitialize peer information database. */
void ssh_pm_peers_uninit(SshPm pm);

/** Lookup peer by peer handle `peer_handle'. */
SshPmPeer ssh_pm_peer_by_handle(SshPm pm, SshUInt32 peer_handle);

/** Lookup peer by IKE SA handle `ike_sa_handle'. */
SshPmPeer ssh_pm_peer_by_ike_sa_handle(SshPm pm, SshUInt32 ike_sa_handle);

/** Lookup next peer with equal IKE SA handle as `peer'. This function is
    used for iterating through all peers that refer to an IKE SA. */
SshPmPeer ssh_pm_peer_next_by_ike_sa_handle(SshPm pm, SshPmPeer peer);

/** Lookup peer by IKE SA `p1'. This a convenient variant of the function
    ssh_pm_peer_by_ike_sa_handle(). */
SshPmPeer ssh_pm_peer_by_p1(SshPm pm, SshPmP1 p1);

/** Lookup peer by IKE SA `p1'. Return IKE peer handle, or
    SSH_IPSEC_INVALID_INDEX if no IKE peer is found for IKE SA. */
SshUInt32 ssh_pm_peer_handle_by_p1(SshPm pm, SshPmP1 p1);

/** Lookup IKE SA for peer `peer_handle'. */
SshPmP1 ssh_pm_p1_by_peer_handle(SshPm pm, SshUInt32 peer_handle);

/** Lookup peer by local and remote addresses and ports and local and remote
    identities. Returns the peer handle or SSH_IPSEC_INVALID_INDEX if no
    matching peer was found. */
SshUInt32
ssh_pm_peer_handle_lookup(SshPm pm,
                          SshIpAddr remote_ip, SshUInt16 remote_port,
                          SshIpAddr local_ip, SshUInt16 local_port,
                          SshIkev2PayloadID remote_id,
                          SshIkev2PayloadID local_id,
                          SshVriId routing_instance_id,
                          Boolean use_ikev1,
                          Boolean manual_key);

/** Lookup peer by outbound spi `spi' for transform `trd_index'.
    Return IKE peer handle, or SSH_IPSEC_INVALID_INDEX if no IKE peer
    is found for outbound spi. */
SshUInt32
ssh_pm_peer_handle_by_spi_out(SshPm pm, SshUInt32 spi, SshUInt32 trd_index);

/** Lookup peer by local and remote addresses and ports. */
SshUInt32
ssh_pm_peer_handle_by_address(SshPm pm,
                              SshIpAddr remote_ip, SshUInt16 remote_port,
                              SshIpAddr local_ip, SshUInt16 local_port,
                              Boolean use_ikev1,
                              Boolean manual_key,
                              SshVriId routing_instance_id);

/** Lookup peer by local address. */
SshPmPeer
ssh_pm_peer_by_local_address(SshPm pm, SshIpAddr local_ip);

/** Lookup next peer with equal local IP address as `peer'. This function is
    used for iterating through all peers that use the same local IP. */
SshPmPeer
ssh_pm_peer_next_by_local_address(SshPm pm, SshPmPeer peer);

/** Returns the number of child sas by P1. */
SshUInt32
ssh_pm_peer_num_child_sas_by_p1(SshPm pm, SshPmP1 p1);

/** Allocate peer from freelist. */
SshPmPeer ssh_pm_peer_alloc(SshPm pm);

/** Free peer and return it to freelist. */
void ssh_pm_peer_free(SshPm pm, SshPmPeer peer);

/** Create peer with `remote_ip', `remote_port' and attach IKE SA `p1'
    to it. Return peer handle, or SSH_IPSEC_INVALID_INDEX if creation
    failed. `p1' may be NULL in which case no IKE SA will be bound to the
    peer. Argument `manual_key' specifies whether manual keying is used
    with this peer. It is used for matching peers in
    ssh_pm_peer_handle_by_address().

    On success this functions takes one reference to the created peer
    handle, which the caller must free when no longer needed. In addition
    one reference is taken for the IKE SA if one was specified. This reference
    is automatically freed when the IKE SA is removed from the peer with
    ssh_pm_peer_update_p1(). */
SshUInt32 ssh_pm_peer_create(SshPm pm,
                             SshIpAddr remote_ip, SshUInt16 remote_port,
                             SshIpAddr local_ip, SshUInt16 local_port,
                             SshPmP1 p1, Boolean manual_key,
                             SshVriId routing_instance_id);

/** Peer uses IKEv1 */
#define SSH_PM_PEER_CREATE_FLAGS_USE_IKEV1               0x0001
/** Manual keying is used with this peer. */
#define SSH_PM_PEER_CREATE_FLAGS_MANUAL_KEY              0x0002

#ifdef SSH_PM_BLACKLIST_ENABLED
/** Blacklist check has to be done for this peer. */
#define SSH_PM_PEER_CREATE_FLAGS_ENABLE_BLACKLIST_CHECK  0x0004
#endif /* SSH_PM_BLACKLIST_ENABLED */

/** Same as above, but the IKE identities, IKE version and IKE SA handle are
    passed as arguments instead of `p1'. */
SshUInt32
ssh_pm_peer_create_internal(SshPm pm,
                            SshIpAddr remote_ip, SshUInt16 remote_port,
                            SshIpAddr local_ip, SshUInt16 local_port,
                            SshIkev2PayloadID local_id,
                            SshIkev2PayloadID remote_id,
                            SshUInt32 ike_sa_handle,
                            SshVriId routing_instance_id,
                            SshUInt32 flags,
                            Boolean force_ikev1_natt_draft_02);

/** Release reference to IKE peer. IKE peer is freed when reference count
    reaches zero. This function asserts that the peer_handle points to
    valid IKE peer object. */
void ssh_pm_peer_handle_destroy(SshPm pm, SshUInt32 peer_handle);

/** Take reference to IKE peer. This function asserts that the peer_handle
    points to valid IKE peer object. */
void ssh_pm_peer_handle_take_ref(SshPm pm, SshUInt32 peer_handle);

/** Update IKE peer address for IKE peer that is attached to IKE SA `p1'. */
Boolean ssh_pm_peer_p1_update_address(SshPm pm,
                                      SshPmP1 p1,
                                      SshIpAddr new_remote_ip,
                                      SshUInt16 new_remote_port,
                                      SshIpAddr new_local_ip,
                                      SshUInt16 new_local_port);

/** Update IKE SA `new_p1' to IKE peer `peer'. This function maintains
    the peer reference counting for the IKE SA attached to the peer. If
    there are no external references to the peer and this functions
    detaches the IKE SA from the peer (new_p1 is NULL), then this function
    frees the IKE peer object. */
Boolean ssh_pm_peer_update_p1(SshPm pm, SshPmPeer peer, SshPmP1 new_p1);

/** Report IPsec SA establishment. */
void ssh_pm_peer_debug_ipsec_sa_open(SshPm pm,
                                     SshPmPeer peer,
                                     SshPmQm qm);

/** Report IPsec SA termination. */
void ssh_pm_peer_debug_ipsec_sa_close(SshPm pm,
                                      SshPmPeer peer,
                                      SshEngineTransformData trd);

/** Report an error detected locally. */
void
ssh_pm_peer_debug_error_local(SshPm pm, SshPmPeer peer, const char *text);

/** Report an error detected by the remote end. */
void
ssh_pm_peer_debug_error_remote(SshPm pm, SshPmPeer peer, const char *text);

#ifdef SSHDIST_IKE_EAP_AUTH
/* ********************* Handling EAP state ************************/

/** Initialize EAP context for the authentication domain `ad'. */
Boolean ssh_pm_eap_init(SshPmAuthDomain ad);

/** Uninitialize EAP context from the authentication domain `ad'.  This
   assumes that an appropriate shutdown has already been done for
   negotiations, etc.*/
void ssh_pm_eap_uninit(SshPmAuthDomain ad);

/** Release all resources from the state 'eap'. */
void ssh_pm_ike_eap_destroy(SshPmEapState eap);
#endif /* SSHDIST_IKE_EAP_AUTH */

/* ********************** Handling IKE server context ************************/

/** Initialize IKE server context for the policy manager `pm'. */
Boolean ssh_pm_ike_init(SshPm pm);

/** Uninitialize IKE server context from the policy manager `pm'.  This
   assumes that an appropriate shutdown has already been done for
   negotiations, etc.*/
void ssh_pm_ike_uninit(SshPm pm);

/* ********************** Auto Start ************************/

/** Upate the status of autostart rules after a Quick-Mode negotiation. */
void ssh_pm_qm_update_auto_start_status(SshPm pm, SshPmQm qm);

/** Remove a rule from rule by autostart ADT container. It is safe to call
    this even if rule is not in the ADT container. */
void ssh_pm_rule_auto_start_remove(SshPm pm, SshPmRule rule);

/** Insert a rule to rule by autostart ADT container. It is safe to call
    this even if rule is already in the ADT container. */
void ssh_pm_rule_auto_start_insert(SshPm pm, SshPmRule rule);

#ifdef SSHDIST_L2TP
/* ********************** Handling L2TP server context ***********************/

/** Initialize L2TP server for the policy manager `pm'.  The function
   returns TRUE if the server could be initialized and FALSE
   otherwise. */
Boolean ssh_pm_l2tp_init(SshPm pm);

/** Uninit L2TP server from the policy manager `pm'.  The function will
   call the callback function `callback' when the L2TP server is
   destroyed. */
void ssh_pm_l2tp_uninit(SshPm pm, SshL2tpFinishedCB callback, void *context);
#endif /* SSHDIST_L2TP */


#ifdef SSHDIST_EXTERNALKEY
/* ****************************** Externalkey ********************************/

/** Initialize an externalkey support for the policy manager `pm'. */
Boolean ssh_pm_ek_init(SshPm pm);

/** Uninitialize the externalkey support of the policy manager `pm'.
   The externalkey module can have keys but they must not have any
   users.  This will destory all keys and the container. */
void ssh_pm_ek_uninit(SshPm pm);

/** Externalkey notify function. */
void ssh_pm_ek_notify(SshEkEvent event, const char *keypath,
                      const char *label, SshEkUsageFlags flags,
                      void *context);

/** Get the next usable externalkey key of type `key_selector' which
   index is bigger than `*index'.  Key is usable if it has a valid
   certificate and the system has successfully fetched its private
   key.  The function updates the variable, pointed by `index' to the
   key ID of the returned key.  The function returns the next key or
   NULL if no more keys are left.  The function adds a reference to
   the returned key.  The key must be freed with ssh_pm_ek_unref()
   after it is not longer needed. */
SshPmEk ssh_pm_ek_get_next(SshPm pm, SshPmAuthMethod key_selector,
                           SshUInt32 *index);

/** Get an externalkey using the public key of the certificate `cert'.
   The function returns the key or NULL if there is not a valid key
   available.  The function adds a reference to the returned key.  The
   key must be freed with ssh_pm_ek_unref() after it is not longer
   needed. */
SshPmEk ssh_pm_ek_get_by_cert(SshPm pm, SshCMCertificate cert);

/** Get an externalkey that matches the IKE identity 'id'.
   The function returns the key or NULL if there is not a valid key
   available.  The function adds a reference to the returned key.  The
   key must be freed with ssh_pm_ek_unref() after it is not longer
   needed. */
SshPmEk ssh_pm_ek_get_by_identity(SshPm pm, SshIkev2PayloadID id);

/** Check whether the policy manager has more keys of type type
   `key_selector' with index greater than or equal to `index'. */
Boolean ssh_pm_ek_has_next(SshPm pm, SshPmAuthMethod key_selector,
                           SshUInt32 index);

/** Take a copy of the externalkey `key'.  Actually this returns the
   same key object `key' but adds one reference to it.  The returned
   key must be freed with ssh_pm_ek_unref(). */
SshPmEk ssh_pm_ek_dup(SshPmEk key);

/** Remove a reference from the key `key'.  The function calls
   ssh_pm_ek_destory() if the key was destroyed and this was its last
   reference. */
void ssh_pm_ek_unref(SshPm pm, SshPmEk key);

/** Signal externalkey provider to refresh stored certificates to the
    certificate stores. */
Boolean
ssh_pm_ek_refresh_certificates(SshPm pm, SshPmAuthDomain ad);
#endif /* SSHDIST_EXTERNALKEY */

/** This function is called for IKE initiators to check that the IKE identity
   of the responder is acceptable with local policy. Returns FALSE if the
   responder identity does not agree with that requested by the initiator
   and the initiator has the 'enforce_remote_identity' flag set in the tunnel
   of the Phase I negotiation. Otherwise this function returns TRUE. */
Boolean ssh_pm_ike_check_requested_identity(SshPm pm, SshPmP1 p1,
                                            SshIkev2PayloadID responder_id);


/* ************************ Authorization functions **************************/

/** Resolve authorization group for the Phase-1 SA `p1'. */
void ssh_pm_authorization_p1(SshPm pm, SshPmP1 p1,
                             SshPmAuthorizationResultCB callback,
                             void *context);

/** Check if 'p1' matches authorization required by rule. */
Boolean ssh_pm_check_rule_authorization(SshPmP1 p1, SshPmRule rule);

/** Completion callback for SshPmAuthorizationCB. This function is called
    from the Quick-Mode thread, and it copies the authorization group
    id's to the Phase-I data structure. */
void
ssh_pm_authorization_cb(SshUInt32 *group_ids,
                        SshUInt32 num_group_ids,
                        void *context);

/* ********************* Allocation / freeing objects ************************/

/** Allocate a tunnel object. */
SshPmTunnel ssh_pm_tunnel_alloc(SshPm pm);

/** Free the tunnel object `tunnel'. */
void ssh_pm_tunnel_free(SshPm pm, SshPmTunnel tunnel);

Boolean ssh_pm_tunnel_clear_peers(SshPmTunnel tunnel);

/** Allocate an inbound SPI object */
SshPmSpiIn ssh_pm_spi_in_alloc(SshPm pm);
/** Allocate an outbound SPI object */
SshPmSpiOut ssh_pm_spi_out_alloc(SshPm pm);

/** Free the inbound SPI object `spi'. */
void ssh_pm_spi_in_free(SshPm pm, SshPmSpiIn spi);
/** Free the outbound SPI object `spi'. */
void ssh_pm_spi_out_free(SshPm pm, SshPmSpiOut spi);

/** Allocate an unknown SPI object */
SshPmSpiUnknown ssh_pm_spi_unknown_alloc(SshPm pm);
/** Free an unknown SPI object */
void ssh_pm_spi_unknown_free(SshPm pm, SshPmSpiUnknown spi);

/** Allocate a new Phase-1 structure.  The function returns a Phase-1
   structure or NULL if no structures were available. */
SshPmP1 ssh_pm_p1_alloc(SshPm pm);

/** Free the Phase-1 SA `p1' and release all its resources.  If the
   policy manager is shutting down, this also notifies the main thread
   that this negotiation is complete and the shutdown operation might
   be continued. */
void ssh_pm_p1_free(SshPm pm, SshPmP1 p1);

/** Allocate a new Phase-1 negotiation structure.  The function returns
   a Phase-1 negotiation structure or NULL if no structures were
   available. */
SshPmP1Negotiation ssh_pm_p1_negotiation_alloc(SshPm pm);

/** Free the Phase-1 negotiation `negotiation' and release all its
   resources. */
void ssh_pm_p1_negotiation_free(SshPm pm, SshPmP1Negotiation negotiation);

/** Allocate a new Quick-Mode structure.  The argument `rekey'
   specifies whether the context is needed for a rekey operation or
   for a new Quick-Mode negotiation.  The function returns a
   Quick-Mode struct or NULL if no structures were available. */
SshPmQm ssh_pm_qm_alloc(SshPm pm, Boolean rekey);

/** Free Quick-Mode negotiation `qm' and free all its resources.  If
   the policy manager is shutting down, this also notifies the main
   thread that this negotiation is complete and the shutdown operation
   might be continued.  The freed negotiation structure `qm' is put
   back to the policy manager's freelist. */
void ssh_pm_qm_free(SshPm pm, SshPmQm qm);

/** Functions for allocating and freeing Phase-I rekey contexts. */
SshPmIkeRekey ssh_pm_p1_rekey_alloc(SshPm pm);
void ssh_pm_p1_rekey_free(SshPm pm, SshPmIkeRekey rekey);

/** Allocate a new information exchange context structure.  The argument
    `type' specifies the type of data inside the SshPmInfo. The object is
    allocated from ed->obstack. */
SshPmInfo ssh_pm_info_alloc(SshPm,
                            SshIkev2ExchangeData ed,
                            SshPmExchangeDataType type);

/* *************************** Utility functions *****************************/

/** Perform call to IKE library, and if the call starts successfully
   (e.g. returns non-null operation handle) registers the call for
   abortion. */
Boolean pm_ike_async_call_possible(SshIkev2Sa sa, int *slot);
Boolean pm_ike_async_call_pending(SshIkev2Sa sa);

#define PM_SUSPEND_CONDITION_WAIT(pm, thread)           \
do {                                                    \
  SshPm _pm = (SshPm)(pm);                              \
  SshPmStatus _pm_status = ssh_pm_get_status(_pm);      \
                                                        \
  if ((_pm_status == SSH_PM_STATUS_SUSPENDED) ||        \
      (_pm_status == SSH_PM_STATUS_SUSPENDING))         \
    {                                                   \
      SSH_DEBUG(SSH_D_LOWOK, ("Thread 0x%p suspended, " \
                              "PM status %u", thread,   \
                              _pm_status));             \
      SSH_FSM_CONDITION_WAIT(&pm->resume_cond);         \
   }                                                    \
 } while (0)

#ifdef WITH_IKE

#define PM_IKE_ASYNC_CALL(sa, ed, slot, stmt)           \
do {                                                    \
  SshPmP1 _p1 = (SshPmP1)(sa);                          \
  if ((stmt) != NULL)                                   \
    {                                                   \
      ssh_ikev2_exchange_data_take_ref((ed));           \
      _p1->initiator_eds[(slot)] = (ed);                \
    }                                                   \
} while (0)


/** Completes async call to IKE library (to be called from the
   application callback given to IKE). */
#define PM_IKE_ASYNC_CALL_COMPLETE(sa, ed)              \
do {                                                    \
  int _i;                                               \
  SshPmP1 _p1 = (SshPmP1)(sa);                          \
  for (_i = 0; _i < PM_IKE_MAX_WINDOW_SIZE; _i++)       \
    {                                                   \
      if (_p1->initiator_eds[_i] == (ed))               \
        {                                               \
          ssh_ikev2_exchange_data_free((ed));           \
          _p1->initiator_eds[_i] = NULL;                \
          break;                                        \
        }                                               \
    }                                                   \
 } while (0)

#else /* WITH_IKE */
#define PM_IKE_ASYNC_CALL(sa, ed, slot, stmt) do { SSH_NOTREACHED; } while(0)
#define PM_IKE_ASYNC_CALL_COMPLETE(sa, ed) do { SSH_NOTREACHED; } while(0)
#endif /* WITH_IKE */

/** Macro for calling ssh_ikev2_ike_sa_delete() safely. This is needed because
    ssh_ikev2_ike_sa_delete() may delete the IKE SA synchronously. This macro
    calls ssh_ikev2_ike_sa_delete() and checks the result. If the resulting
    operation handle is not NULL, then an asynchronous delete operation was
    started and the IKE SA has not been freed. In this case the operation
    handle is stored to the p1->initiator_ops[] array, so that it can be
    later aborted. If the resulting operation handle is NULL, then the IKE
    SA may be freed already. */
#define SSH_PM_IKEV2_IKE_SA_DELETE(p1, flags, callback)             \
do                                                                  \
  {                                                                 \
    SshOperationHandle _op =                                        \
      ssh_ikev2_ike_sa_delete((p1)->ike_sa, (flags), (callback));   \
    if (_op != NULL)                                                \
      (p1)->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] = _op;        \
  }                                                                 \
while (0)

#ifdef SSH_IPSEC_SMALL
/** Macro for registering a timer event for an IKE SA. This cancels any
    previous timer event and registers the new at absolute time `when'.
    Current time is given in `now'. */
#define SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(p1, when, now)                  \
do                                                                         \
  {                                                                        \
    ssh_cancel_timeout((p1)->timeout);                                     \
    SSH_DEBUG(SSH_D_LOWOK,                                                 \
              ("Registering IKE SA %p timer event to %ld seconds",         \
               (p1), (long)((when) - (now))));                             \
    ssh_register_timeout((p1)->timeout, (long)((when) - (now)), 0L,        \
                         ssh_pm_ike_sa_timer, (p1));                       \
  }                                                                        \
while (0)
#endif /* SSH_IPSEC_SMALL */

/* ************** IPsec-specific utility functions *********************/

/** Render function for `SshUInt32 spis[3]' array. */
int ssh_pm_spis_render(unsigned char *buf, int buf_size,
                       int precision, void *datum);

/** Render function for IKE SPI's. */
int ssh_pm_render_ike_spi(unsigned char *buf, int buf_size,
                          int precision, void *datum);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/** Compute a hash value of the IKE payload ID `id' into the buffer `hash'. */
void ssh_pm_ike_id_hash(SshPm pm, unsigned char hash[SSH_ENGINE_PEER_ID_SIZE],
                        SshIkev2PayloadID id);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

/** Log Phase-1 negotiation `p1' to the event log.  A call to this
   function should be preceded and followed by ssh_log_event() calls
   which print a header for the Phase-1 event and describe the event
   in more detail. Setting 'verbose' to TRUE will cause a more verbose
   description of the Phase 1. */
void ssh_pm_log_p1(SshLogFacility facility, SshLogSeverity severity,
                   SshPmP1 p1, Boolean verbose);

/** Log an Phase-1 event `event' of the negotiation `p1' to the event
   log.  A call to this function should follow more ssh_log_event()
   calls which describe details of the event. */
void ssh_pm_log_p1_event(SshLogFacility facility, SshLogSeverity severity,
                         SshPmP1 p1, const char *event, Boolean rekey);

/** Log a successful Phase-I negotiation. */
void ssh_pm_log_p1_success(SshPm pm,SshPmP1 p1, Boolean rekey);

#ifdef SSHDIST_IKE_MOBIKE
void
ssh_pm_log_p1_additional_addresses(SshLogFacility facility,
                                   SshLogSeverity severity,
                                   SshPmP1 p1, Boolean verbose);
#endif /* SSHDIST_IKE_MOBIKE */

/** Log extented authenction event (for IKEv1) */
void
ssh_pm_log_xauth_event(SshLogFacility facility,
                       SshLogSeverity severity,
                       SshPmP1 p1,
                       Boolean success);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/** Log an IKE configuration mode event `event' of type `type' using
   the Phase-1 negotiation `p1' to the event log.  A call to this
   function should follow more ssh_log_event() calls which describe
   details of the event. */
void
ssh_pm_log_cfgmode_event(SshLogFacility facility, SshLogSeverity severity,
                         SshPmP1 p1,  SshIkev2ConfType type,
                         const char *event);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/** Log a transform event 'event' from the engine. The transformdata
   'trd' is required for to produce the log event. */
void
ssh_pm_log_trd_event(SshLogFacility facility, SshPmeFlowEvent event,
                     SshEngineTransformData trd);

/** Log a Quick-Mode event `event' of the negotiation `qm' to the event
   log.  A call to this function should follow more ssh_log_event()
   calls which describe details of the event. */
void ssh_pm_log_qm_event(SshLogFacility facility, SshLogSeverity severity,
                         SshPmQm qm, const char *event);

/** Log a manual SA event `event' of the manual SA `qm' to the event
    log.  If `sa_installation' is TRUE, then this function will also
    log transform peer IP addresses and SA algorithms from the transform
    data.  A call to this function should follow more ssh_log_event()
    calls which describe details of the event. */
void
ssh_pm_log_manual_sa_event(SshPm pm, SshPmQm qm, Boolean sa_installation,
                           const char *event);

/** Log responder SA selection failure `failure_mask' with
   ssh_log_event with log `facility' and `severity'.  The function
   logs only the reasons, defined by the `failure_mask'. 'failure_mask'
   should be a mask of the SSH_PM_E_* defines. A call to
   this function should be preceded by another ssh_log_event call
   which describes the failed responder SA selection. */
void ssh_pm_log_sa_selection_failure(SshLogFacility facility,
                                     SshLogSeverity severity,
                                     SshUInt32 failure_mask);

/** Log responder IKE SA selection failure `failure_mask' with
   ssh_log_event with log `facility' and `severity'.  The function
   logs only the reasons, defined by the `failure_mask'.  A call to
   this function should be preceded by another ssh_log_event call
   which describes the failed responder SA selection. */
void
ssh_pm_log_ike_sa_selection_failure(SshLogFacility facility,
                                    SshLogSeverity severity,
                                    SshPmP1 p1,
                                    SshIkev2SaSelectionError failure_mask);

/** Log certificate manager search failure `failure_mask' with
   ssh_log_event with log `facility' and `severity'.  The function
   logs only the reasons, defined by the `failure_mask'.  A call to
   this function should be preceded by another ssh_log_event call
   which describes the failed CMi operation. */
void ssh_pm_log_cmi_failure(SshLogFacility facility,
                            SshLogSeverity severity,
                            SshPmP1,
                            SshUInt32 failure_mask);

/** Log remote access attributes `attributes' with ssh_log_event with
   log `facility' and `severity'.  The function logs only the
   attributes, defined by `attributes'.  A call to this function
   should be preceded by another ssh_log_event call which describes
   the operation that uses the attributes. */
void ssh_pm_log_remote_access_attributes(SshLogFacility facility,
                                         SshLogSeverity severity,
                                         SshPmRemoteAccessAttrs attributes);

#ifdef SSHDIST_L2TP
/** Log an L2TP event `event' of the tunnel `tunnel', session `session'
   to the event log.  The argument `initiator' specifies whether the
   peer is initiator or responder of the L2TP negotiation.  A call to
   this function should follow more ssh_log_event() calls which
   describe details of the event. */
void ssh_pm_log_l2tp_event(SshLogFacility facility, SshLogSeverity severity,
                           SshL2tpTunnelInfo tunnel,
                           SshL2tpSessionInfo session,
                           const char *event);
#endif /* SSHDIST_L2TP */

/** Notify transform delete expire/delete event */
void
ssh_pm_notify_ipsec_sa_delete(SshPm pm,
                              SshPmeFlowEvent event,
                              SshEngineTransform tr);

/** Calculate soft grace time for IKE SA. This is used for calculating how
    many seconds before IKE SA expiry the IKE SA rekey operation is
    initiated. */
SshTime
ssh_pm_ike_sa_soft_grace_time(SshPmP1 p1);

/** Look up a tunnel that matches the addresses 'local', 'remote' for IKE
   endpoints and has IKE algorithms acceptable to those in 'sa_in'. */
SshPmTunnel ssh_pm_tunnel_lookup(SshPm pm, Boolean ikev1,
                                 SshIkev2Server server,
                                 SshIpAddr remote,
                                 SshIkev2PayloadSA sa_in,
                                 SshUInt32 *failure_mask,
                                 SshUInt32 *ike_failure_mask);

/** Contruct an IKE SA payload from the algorithm in the tunnel 'tunnel'. */
SshIkev2Error
ssh_pm_build_ike_sa_from_tunnel(SshPm pm, SshPmTunnel tunnel,
                                SshIkev2PayloadSA *sa_payload_return);

/** Decode secret `secret', `secret_len', from the encoding `encoding'.
   The function returns a dynamically allocated binary secret and sets
   the length of the returned secret in `len_return'.  The function
   returns NULL if the secret could not be decoded or the system ran
   out of memory.  If the secret could not be decoded, the variable,
   pointed by `invalid_encoding_return' is set to TRUE. */
unsigned char *ssh_pm_decode_secret(SshPmSecretEncoding encoding,
                                    const unsigned char *secret,
                                    size_t secret_len,
                                    size_t *len_return,
                                    Boolean *invalid_encoding_return);

/** Decode IKE identity `identity' of type `type'.  The function
   returns a dynamically allocated ID or NULL if the identity could
   not be decoded or if the system ran out of memory.  If the identity
   was malformed, the variable, pointed by `malformed_id_return' is
   set to TRUE. */
SshIkev2PayloadID
ssh_pm_decode_identity(SshPmIdentityType id_type,
                       const unsigned char *identity,
                       size_t identity_len,
                       Boolean *malformed_id_return);

/** Allocate an IKE identity to use for the tunnel and IKE SA.
    If ' consider_ike_ip_identity' is TRUE, fallback to use IP identity
    if no other suitable identity is available. Returns NULL is no identity
    can be allocated. */
SshIkev2PayloadID
ssh_pm_ike_get_identity(SshPm pm, SshPmP1 p1, SshPmTunnel tunnel,
                        Boolean consider_ike_ip_identity);

/** Compare two preshared secrets for equality. If 'consider_id' is TRUE
   then it returns TRUE iff the 'secret' are both identical.
   FALSE is returned if psk1 and psk2 are not identical. */
Boolean
ssh_pm_psk_compare(SshPmPsk psk1, SshPmPsk psk2);


/** Initialize a container for holding IKE identities to preshared keys
   mappings in authentication domain. */
Boolean ssh_pm_ike_preshared_keys_create(SshPm pm, SshPmAuthDomain ad);

/** Free all resources from the authentication domain holding IKE identities
    to preshared keys. */
void
ssh_pm_ike_preshared_keys_destroy(SshPmAuthDomain ad);

/** Look from the authentication domain dor IKE identities to preshared keys
   mappings for the IKEv2 identity 'identity' and it if exists then return
   its corresponding preshared key, with the preshared key length
   returned in 'key_len'. Returns NULL if the identity 'identity' does not
   exist in the global container. */
unsigned char *
ssh_pm_ike_preshared_keys_get_secret(SshPmAuthDomain ad,
                                     SshIkev2PayloadID identity,
                                     size_t *key_len);

/** The two functions below implement simultaneous IKEV2 IPsec SA rekey
    processing as specified in RFC5996 section 2.8.1. */

/** This function compares and stores the smallest available nonce value
    of a simultaneous responder IPsec SA rekey negotiation. This function
    may be called only for succesfully completed responder CREATE_CHILD
    negotiations.

    This function first looks up the simultaneous initiated IPsec SA rekey
    negotiation qm and then compares and stores the smallest nonce of the
    available three nonces (responded Ni and Nr and initiated Ni). The
    smallest nonce is stored in to the simultaneous initiated qm. */
void
ssh_pm_qm_simultaneous_rekey_store_nonces(SshPm pm,
                                          SshIkev2ExchangeData ed);

/** This function selects the loser of a simultaneous IKEv2 IPsec SA rekey.
    This function may be called only for IKEv2 initiator IPsec SA rekeys
    that have been marked as being simultaneous rekeys.

    This function compares the nonce Nr of the initiated IPsec SA to
    the smallest nonce selected in the above function. If the smallest
    nonce is locally generated, then this end is the loser of the
    simultaneous IPsec SA rekey.

    In such case this function returns TRUE and this end must fail the
    installation of the initiated IPsec SA and instead send a delete
    notification for the SA.

    Otherwise this returns FALSE and the SA can be installed as usual. */
Boolean
ssh_pm_qm_simultaneous_rekey_decide_loser(SshPm pm, SshPmQm qm);

/** Call ike_sa_callback for IKE SA `p1' with SSH_PM_SA_EVENT_CREATED. */
void ssh_pm_ike_sa_event_created(SshPm pm, SshPmP1 p1);

/** Call ike_sa_callback for IKE SA `p1' with SSH_PM_SA_EVENT_REKEYED. */
void ssh_pm_ike_sa_event_rekeyed(SshPm pm, SshPmP1 p1);

/** Call ike_sa_callback for IKE SA `p1' with SSH_PM_SA_EVENT_UPDATED. */
void ssh_pm_ike_sa_event_updated(SshPm pm, SshPmP1 p1);

/** Call ike_sa_callback for IKE SA `p1' with SSH_PM_SA_EVENT_DELETED. */
void ssh_pm_ike_sa_event_deleted(SshPm pm, SshPmP1 p1);

/** Call ipsec_sa_callback for IPsec SA `qm' with SSH_PM_SA_EVENT_CREATED. */
void ssh_pm_ipsec_sa_event_created(SshPm pm, SshPmQm qm);

/** Call ipsec_sa_callback for IPsec SA `qm' with SSH_PM_SA_EVENT_REKEYED. */
void ssh_pm_ipsec_sa_event_rekeyed(SshPm pm, SshPmQm qm);

/** Call ipsec_sa_callback for IPsec SA identified by `outbound_spi',
    `inbound_spi' and `ipproto' with SSH_PM_SA_EVENT_DELETED. */
void ssh_pm_ipsec_sa_event_deleted(SshPm pm, SshUInt32 outbound_spi,
                                   SshUInt32 inbound_spi, SshUInt8 ipproto);

/** Call ipsec_sa_callback for all IPsec SAs with `peer' with
    SSH_PM_SA_EVENT_UPDATED. */
void ssh_pm_ipsec_sa_event_peer_updated(SshPm pm,
                                        SshPmPeer peer,
                                        Boolean enable_natt,
                                        Boolean enable_tcpencap);

#ifdef SSHDIST_IPSEC_MOBIKE

/* ************************ Mobike Utility Functions *************************/

/** Reevaluates IKE SA addresses. */
void
ssh_pm_mobike_reevaluate_ike_sa(SshPm pm, SshPmP1 p1);

/** Checks if an address update needs to be performed and starts one
    if necessary. This is called when exchange `ed' has completed
    with `error' for IKE SA `p1->ike_sa'. */
void
ssh_pm_mobike_check_exchange(SshPm pm,
                             SshIkev2Error error,
                             SshPmP1 p1,
                             SshIkev2ExchangeData ed);

/** Checks if an ip address is valid for MobIKE. can be used for checking
    local or peer ip addresses. Return value is TRUE if the address is valid
    and usable for MobIKE. */
Boolean
ssh_pm_mobike_valid_address(SshIpAddr ip);

/** Process received address update notification.  This function is called
    only for IKE SA responder. */
void
ssh_pm_mobike_address_update_received(SshPm pm,
                                      SshPmP1 p1,
                                      SshIkev2ExchangeData ed);

/** Move p1 to new server and remote address. This changes the IKE SA
    addresses, updates the ike_sa_hash table and the outbound SPI mapping. */
Boolean
ssh_pm_mobike_update_p1_addresses(SshPm pm,
                                  SshPmP1 p1,
                                  SshIkev2Server ike_server,
                                  SshIpAddr remote_ip,
                                  SshUInt16 remote_port,
                                  SshUInt32 natt_flags);

/** Handle a additional addresses notify from the IKE peer. MobIKE
    initiators need to check if the remote address for the current exchange
    is different to the of the IKE SA and the set of additional addresses
    does not include the current IKE SA address. If this is the case, the
    initiator must then initiate address update. */
void
ssh_pm_mobike_additional_addresses_received(SshPm pm, SshPmP1 p1,
                                            SshIkev2ExchangeData ed);

/** Simple utility to find a IKE server form the supplied local address
    and port. Returns NULL if no server is available. */
SshIkev2Server
ssh_pm_mobike_get_ike_server(SshPm pm,
                             SshPmTunnel tunnel,
                             SshIpAddr local_ip,
                             SshUInt16 local_port);

/** Get address pair for IKE SA `p1' indexed by `address_index' and return it
    in `server' and `remote_ip'. */
SshIkev2Error ssh_pm_mobike_get_address_pair(SshPm pm, SshPmP1 p1,
                                             SshUInt32 address_index,
                                             SshIkev2Server *server,
                                             SshIpAddr remote_ip);

/* ************************* Mobike State Machine ****************************/

/** Start address update from most preferred address pair. */
#define SSH_PM_MOBIKE_FLAGS_PROBE                    0x1
/** Update IKE SA addresses immediately before address update. */
#define SSH_PM_MOBIKE_FLAGS_IMMEDIATE_IKE_SA_UPDATE  0x2
/** Skip IKE SA address update. */
#define SSH_PM_MOBIKE_FLAGS_NO_IKE_SA_UPDATE         0x4
/** Remote ip is reachable. */
#define SSH_PM_MOBIKE_FLAGS_REMOTE_REACHABLE         0x10
/** Operation is suspended and must be continued later. */
#define SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED      0x20
/** Force address update to use specific addresses. */
#define SSH_PM_MOBIKE_FLAGS_FORCE_ADDRESSES          0x40

/** Performs address update for the IKE SA.  If no flags are given, then the
    address update starts from current IKE SA addresses.  If `flags' includes
    SSH_PM_MOBIKE_FLAGS_PROBE then the address update starts with most
    preferred address pair.  If `flags'includes
    SSH_PM_MOBIKE_FLAGS_IMMEDIATE_IKE_SA_UPDATE then the IKE SA is moved to
    the most preferred local IKE server before address update is started.
    This flag is used when the current local IP address has disappeared. If
    this flag is set then the argument `tunnel'must specify the tunnel that
    `p1' uses, otherwise `tunnel' may be NULL.  This function is called from
    ssh_pm_mobike_reevaluate() and from ssh_pm_mobike_check_exchange(). */
SshOperationHandle
ssh_pm_mobike_initiator_address_update(SshPm pm,
                                       SshPmP1 p1,
                                       SshIkev2ExchangeData ed,
                                       SshPmTunnel tunnel,
                                       SshUInt32 flags,
                                       SshPmMobikeStatusCB callback,
                                       void *context);

/** Performs return routability check and address update for the IKE SA and
    IPsec SAs. */
SshOperationHandle
ssh_pm_mobike_responder_address_update(SshPm pm,
                                       SshPmP1 p1,
                                       SshIkev2ExchangeData ed,
                                       SshPmMobikeStatusCB callback,
                                       void *context);

/** Moves IKE SA and IPsec SAs to most preferred existing address pair.  This
    function is used when current local address disappears on responder. */
SshOperationHandle
ssh_pm_mobike_responder_forced_address_update(SshPm pm,
                                              SshPmP1 p1,
                                              SshPmTunnel tunnel,
                                              SshPmMobikeStatusCB callback,
                                              void *context);

/** Continues a suspended initiator address update. */
void
ssh_pm_mobike_initiator_continue_address_update(SshPm pm,
                                                SshPmMobike ctx);


/** Continues a suspended responder address update. */
void
ssh_pm_mobike_responder_continue_address_update(SshPm pm,
                                                SshPmMobike ctx);

/** Sends an additional addresses notification to peer. This function is called
    from ssh_pm_mobike_reevaluate(). */
SshOperationHandle
ssh_pm_mobike_send_additional_addresses(SshPm pm,
                                        SshPmP1 p1,
                                        SshPmTunnel tunnel,
                                        SshPmMobikeStatusCB callback,
                                        void *context);

/** Extract the NAT-T flags from the NAT-T status of the current exchange.
    Returns TRUE if the NAT-T flags have changed from that currently in
    the IKE SA. */
Boolean ssh_pm_mobike_get_exchange_natt_flags(SshPmP1 p1,
                                              SshIkev2ExchangeData ed,
                                              SshUInt32 *natt_flags);

/* ****************************** Mobike context *****************************/

/** Allocate mobike context data. */
SshPmMobike
ssh_pm_mobike_alloc(SshPm pm, SshPmP1 p1);

/** Free mobike context data. */
void
ssh_pm_mobike_free(SshPm pm, SshPmMobike mobike);

#endif /* SSHDIST_IPSEC_MOBIKE */

/* ***************** Help functions for Quick-Mode threads *******************/


/** A callback function that is called to report the status of an
    engine routing operation.  This is used by Phase-1 initiator and
    responder threads for selecting the IKE server to use with IKE
    peer.  The function sets `qm->route_ok' to 1 if the destination is
    reachable or 0 otherwise.  If the destination is reachable, it sets
    `qm->local_ifnum' and `qm->local_iface_mtu' to the values of the
    `ifnum' and `mtu' arguments.  Also, if the `qm->local_addr' is
    unspecified, the function sets the preferred local IP address into
    the field.  If the `qm->local_addr' is already set, the function
    does not touch the field. */
void ssh_pm_qm_route_cb(SshPm pm, SshUInt32 flags, SshUInt32 ifnum,
                        const SshIpAddr next_hop, size_t mtu, void *context);

/** Destructor for Quick-Mode threads. */
void pm_qm_thread_destructor(SshFSM fsm, void *context);

void pm_qm_sub_thread_destructor(SshFSM fsm, void *context);

/** Check qm->error, if it is not equal to SSH_IKEV2_ERROR_OK then set
    the next state of the thread 'thread' to 'error_state'. This
    function is used for handling the case where the Phase-I object
    'qm->p1' has been freed while a Quick-Mode negotiation is
    ongoing. If the Phase-I has been freed, all Quick-Mode objects
    using that Phase-I will have 'qm->error' error status set. This
    function should be called for Quick-Mode threads after an
    asynchronous operation to check if the Phase-I has been freed. If
    so the Quick-Mode negotiation should be terminated by setting the
    appropiate next FSM state to 'error_state'. */
Boolean ssh_pm_check_qm_error(SshPmQm qm,
                              SshFSMThread thread,
                              SshFSMStepCB error_state);

/** Convert qm->error to human readable error string. */
const char *ssh_pm_qm_error_to_string(int error);

/* Mark that the Quick-Mode 'q'm cannot be completed (by setting qm->error).
   If possible, continue the Quick-Mode's thread or sub-thread. This will
   free 'qm' if no thread is running. */
void ssh_pm_qm_thread_abort(SshPm pm, SshPmQm qm);

/** Decide whether tunnel or transport mode should be used for a Quick-Mode
    negotiation. Tunnel mode will be used unless transport mode is specifically
    requested by the policy. This sets the qm->tunnel_accepted flag. */
void ssh_pm_qm_thread_compute_tunneling_attribute(SshPmQm qm);

/** Result callback for transform create operation.  This copies the
   returned transform index into Quick-Mode threads `trd_index' field
   and continues the Quick-Mode thread.  The context data `context'
   must be the Quick-Mode thread. */
void ssh_pm_transform_index_cb(SshPm pm, SshUInt32 ind, void *context);

/** SA lookup result callback.  This copies the returned transform
   index into Quick-Mode threads `trd_index' field and continues the
   Quick-Mode thread.  The context data `context' must be the
   Quick-Mode thread. */
void ssh_pm_sa_index_cb(SshPm pm, const SshEnginePolicyRule rule,
                        SshUInt32 transform_index, SshUInt32 outbound_spi,
                        void *context);

/** A callback function that is called to notify the status of engine
   rule addition.  This copies the returned rule index into Quick-Mode
   threads `sa_indices' array and continues the Quick-Mode thread.  The
   context data `context' must be the Quick-Mode thread. */
void ssh_pm_add_sa_rule_cb(SshPm pm, SshUInt32 ind,
                           const SshEnginePolicyRule rule,
                           void *context);
/** A callback function that is called to notify the status of engine
   rule addition.  This copies the returned rule index into Quick-Mode
   threads `sa_indices' array and continues the Quick-Mode SA handler
   sub-thread.  The context data `context' must be the Quick-Mode thread. */
void
ssh_pm_add_sa_handler_rule_cb(SshPm pm, SshUInt32 ind,
                              const SshEnginePolicyRule rule,
                              void *context);

/** Create an outbound SA rule for the Quick-Mode negotiation done with
   the rule `rule'.  The argument `forward' specifies the direction of
   the rule `rule' that is used in the negotiation.  This does not set
   transform index of the rule `rule'. */
Boolean
ssh_pm_make_sa_outbound_rule(SshPm pm,
                             SshPmQm qm,
                             Boolean forward, SshPmRule rule,
                             SshIkev2PayloadTS local_ts, size_t local_index,
                             SshIkev2PayloadTS remote_ts, size_t remote_index,
                             SshEnginePolicyRule engine_rule);

/** Calculate traffic selector for IKE trigger, apply and pass rules.
    This will first create an IKE traffic selector with `ike_port' and
    `ike_natt_port' and match all address ranges. Next this narrows the IKE
    traffic selector with `policy_ts' and returns the resulting traffic
    selector. The caller must free the returned value. */
SshIkev2PayloadTS
ssh_pm_calculate_inner_ike_ts(SshPm pm,
                              SshIkev2PayloadTS policy_ts,
                              SshUInt16 ike_port,
                              SshUInt16 ike_natt_port);

/** Create an outbound engine trigger rule for the inner tunnel IKE traffic.
    This will fill `erule' with the selectors from `local_ts' and `remote_ts'
    items indexed by `local_index' and `remote_index'. Param `precedence'
    specifies the engine rule precedence, which must be larger or equal to
    SSH_PM_RULE_PRI_USER_HIGH. If `from_local' is TRUE then the resulting
    engine rule will match only to packets coming from local stack. */
SshPmMakeEngineRuleStatus
ssh_pm_make_inner_ike_trigger_rule(SshPm pm, SshEnginePolicyRule erule,
                                   SshIkev2PayloadTS local_ts,
                                   size_t local_index,
                                   SshIkev2PayloadTS remote_ts,
                                   size_t remote_index,
                                   SshUInt32 precedence,
                                   Boolean from_local,
                                   SshPmRule policy_context);

/** Create an engine apply rule for outbound inner tunnel IKE traffic.
    This will fill `erule' with the selectors from `local_ts' and `remote_ts'
    items indexed by `local_index' and `remote_index'. Param `transform_index'
    specifies the transform to use, `dependent_rule_index' specifies the index
    of the parent engine rule. Param `precedence' specifies the engine rule
    precedence, which must be larger or equal to SSH_PM_RULE_PRI_USER_HIGH.
    If `from_local' is TRUE then the resulting engine rule will match only to
    packets coming from local stack. Param `forward' specifies the direction
    of the rule (as in `qm->forward'). */
Boolean
ssh_pm_make_inner_ike_outbound_apply_rule(SshPm pm, SshEnginePolicyRule erule,
                                          SshIkev2PayloadTS local_ts,
                                          size_t local_index,
                                          SshIkev2PayloadTS remote_ts,
                                          size_t remote_index,
                                          SshUInt32 transform_index,
                                          SshUInt32 dependent_rule_index,
                                          SshUInt32 precedence,
                                          Boolean from_local,
                                          Boolean forward,
                                          SshPmRule policy_context);

/** Create an engine pass rule for inbound inner tunnel IKE traffic.
    This will fill `erule' with the selectors from `local_ts' and `remote_ts'
    items indexed by `local_index' and `remote_index'. Param
    `inbound_tunnel_id' specifies the tunnel where the packet has been
    decapsulated from. Param `precedence' specifies the engine rule precedence,
    which must be larger or equal to SSH_PM_RULE_PRI_USER_HIGH. If `to_local'
    is TRUE then the resulting engine rule will match only to packets going to
    local stack. */
Boolean
ssh_pm_make_inner_ike_inbound_pass_rule(SshPm pm, SshEnginePolicyRule erule,
                                        SshIkev2PayloadTS local_ts,
                                        size_t local_index,
                                        SshIkev2PayloadTS remote_ts,
                                        size_t remote_index,
                                        SshUInt32 inbound_tunnel_id,
                                        SshUInt32 precedence,
                                        Boolean to_local,
                                        SshPmRule policy_context);

/** Check that number of items in traffic selector is below
    SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS.
 */
void
ssh_pm_ts_max_enforce(SshSADHandle sad_handle, SshIkev2PayloadTS *ts);

/** Create SA traffic selectors for the Quick-Mode negotiation `qm'
   and resolve the widest possible traffic selectors for its IPSec tunnel. */
Boolean ssh_pm_resolve_policy_rule_traffic_selectors(SshPm pm, SshPmQm qm);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* ********************* IKE Cfgmode RAS helper functions *******************/

/** Narrow the traffic selectors 'ts_local' and 'ts_remote' with the remote
   access attributes in 'attrs'. If 'client' is TRUE this function is called
   for a remote access client, otherwise for a remote access server.
   When 'client' is TRUE, 'ts_local' is narrowed with the local addresses
   in 'attrs', 'ts_remote' is narrowed with the subnets in 'attrs'. When
   'client' is FALSE, 'ts_local' and 'ts_remote' are reversed.
   The narrowed attributes are allocated and returned in 'ts_return_local'
   and 'ts_return_remote'. Returns SSH_IKEV2_ERROR_OK on success, on failure
   'ts_return_local' and 'ts_return_remote' are returned as NULL. */
SshIkev2Error
ssh_pm_narrow_remote_access_attrs(SshPm pm, Boolean client,
                                  SshPmRemoteAccessAttrs attrs,
                                  SshIkev2PayloadTS ts_local,
                                  SshIkev2PayloadTS ts_remote,
                                  SshIkev2PayloadTS *ts_return_local,
                                  SshIkev2PayloadTS *ts_return_remote);

#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
/* ********************** Extended authentication server *********************/

/** Enable extended authentication server. */
void ssh_pm_xauth_server(SshPm pm, Boolean enable);

/** Set type of extended authentication that the server performs. */
void ssh_pm_xauth_method(SshPm pm,
                         SshIkeXauthType method,
                         SshPmXauthFlags flags);

/** Extract extended authentication type from authentication data. */
SshPmXauthType
ssh_pm_auth_get_xauth_type(SshPmAuthData data);

/** Extract extended authentication attributes from authentication data. */
void *
ssh_pm_auth_get_xauth_attributes(SshPmAuthData data);

/** This function updates IKE SA p1's authorization information after
    a completed extended authentication.

    The argument `xauth_type' specifies the type of the completed
    XAUTH operation.  The argument `xauth_attributes' is `xauth_type'
    dependent attributes giving additional information about the
    extended authentication.  For example, for the RADIUS XAUTH, the
    `xauth_attributes' should hold the AVPs from the RADIUS server.

    The callback function `callback' will be called to notify the new
    authorization group ID back to the XAUTH module.  After the
    callback is received, the XAUTH module should update the group ID
    to the IKE SA.

    This function has not been implemented for the IKEv2 only. */
void
ssh_pm_authorization_xauth(SshPm pm, SshPmP1 p1,
                           SshPmXauthType xauth_type, void *xauth_attributes,
                           SshPmAuthorizationResultCB callback, void *context);

#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

/* ************************** Dead Peer Detection ****************************/

/** Low level init/uninit. Application does not have to care these.
   DPD and dead peer bag are managed using ssh_pm_set_dpd(). */
Boolean ssh_pm_dpd_init(SshPm pm);
void ssh_pm_dpd_uninit(SshPm pm);

/** Process request arriving from the remote. As a responder this
   generates request ack to be send. */
void
ssh_pm_dpd_process_notification(SshPm pm,
                                SshPmP1 p1,
                                const unsigned char *data, size_t len);

/** Process request ack (to request initiated locally) arriving from
   remote */
void
ssh_pm_dpd_process_notification_ack(SshPm pm,
                                    SshPmP1 p1,
                                    const unsigned char *data, size_t len);

/** Initiate DPD exhange when an ipsec flow has been idle at last for
   given worry metric seconds. */
void
ssh_pm_dpd_find_status(SshPm pm,
                       SshPmRule rule,
                       SshPmTunnel tunnel,
                       SshIpAddr peer,
                       SshUInt32 ifnum);

/** Mark a peer as dead. */
void ssh_pm_dpd_peer_dead(SshPm pm, const SshIpAddr addr, Boolean down);
void ssh_pm_dpd_peer_alive(SshPm pm, const SshIpAddr addr);
/** Query if peer is dead. */
Boolean ssh_pm_dpd_peer_dead_p(SshPm pm, const SshIpAddr addr);

/** Receive configuration change notifications. */
void ssh_pm_dpd_policy_change_notify(SshPm pm);


/* *********************  IKE SAD utility functions ******************/

/** Init free list of SA payloads. Return TRUE if successful. */
Boolean
ssh_ikev2_sa_freelist_create(SshSADHandle sad_handle);

/** Destroy free list of SA payloads.  */
void
ssh_ikev2_sa_freelist_destroy(SshSADHandle sad_handle);

/** Init free list of configuration payloads. Return TRUE if successful. */
Boolean
ssh_ikev2_conf_freelist_create(SshSADHandle sad_handle);

/** Destroy free list of configuration payloads.  */
void
ssh_ikev2_conf_freelist_destroy(SshSADHandle sad_handle);

/* ********************** Various SshKeyword tables *************************/

/** Mapping between SshIkeProtocolIdentifiers and their names. */
extern const SshKeywordStruct ssh_pm_ike_protocol_identifiers[];

/** Mapping between SshIkeAttributeAuthMethValues and their names. */
extern const SshKeywordStruct ssh_pm_ike_authentication_methods[];

/** Mapping between CFGMODE message types and their names. */
extern const SshKeywordStruct ssh_pm_ike_cfgmode_message_types[];

/** Mapping between CFGMODE attribute classes and their names. */
extern const SshKeywordStruct ssh_pm_ike_cfgmode_attr_classes[];

/** Mapping between Phase-1 key types and their names. */
extern const SshKeywordStruct ssh_pm_ike_key_type_names[];

/** Mapping between SshIkeCertificateEncodingType and their names. */
extern const SshKeywordStruct ssh_pm_ike_cert_encoding_types[];

/** Mapping between SshIkeErrorCodes and their names. */
extern const SshKeywordStruct ssh_pm_ike_error_codes[];

/** Mapping between SshIkeCertificateEncodingTypes and their names. */
extern const SshKeywordStruct ssh_pm_ike_certificate_encodings[];

/* *********** IPSec SPI allocation and management ********************/

/** Callback function called after deleting a transform record by SPI. The
    callback returns the inbound SPIs of the transform which should be used
    to send a delete notification to the IKE peer. If no transform was found
    for the SPI then the parameter `transform_index' is set to
    SSH_IPSEC_INVALID_INDEX and `inbound_spi' and `outbound_spi' are
    undefined. */
typedef void (*SshPmSpiDeleteCB)(SshPm pm,
                                 SshUInt8 ipproto,
                                 SshUInt8 num_spis,
                                 SshUInt32 *inbound_spis,
                                 SshUInt32 *outbound_spis,
                                 void *context);


/* ************************* Allocating SPI values ***************************/

/** Allocates the specified number of SPIs.  `spibits' specifies which SPIs to
    allocate; it can include the bits (1 << SSH_PME_SPI_ESP_IN), (1 <<
    SSH_PME_SPI_AH_IN) and/or (1 << SSH_PME_SPI_IPCOMP_IN).  This allocates
    SPIs for those protocols that have a bit set in `spibits'; the SPIs are
    stored in the corresponding slots in the `spis' array. Those SPIs that
    were not allocated are set to zero.  Returned AH and ESP SPIs are in the
    range SSH_ENGINE_INBOUND_SPI_MAX_MANUAL - 0xffffffff, and returned IPCOMP
    SPIs are in the range 256-61439 (sic! - see RFC2393).

    If an error occurs, then all three returned SPIs will be zero and this
    return FALSE. Otherwise this returns TRUE. */
Boolean ssh_pm_allocate_spis(SshPm pm, SshUInt32 spibits, SshUInt32 spis[3]);

Boolean ssh_pm_register_inbound_spis(SshPm pm, const SshUInt32 spis[3]);

Boolean ssh_pm_register_outbound_spi(SshPm pm, SshPmQm qm);

/** Frees the given SPIs, which should have been allocated using
    ssh_pm_allocate_spis, but should not have been passed as argument to
    ssh_pm_create_transform or ssh_pm_rekey_transform.  This frees any
    values in the `spis' array which are not zero. */
void ssh_pm_free_spis(SshPm pm, const SshUInt32 spis[3]);

/** These find a matching SpiOut entry from the SPI database. */
SshPmSpiOut
ssh_pm_lookup_outbound_spi(SshPm pm, Boolean match_address,
                           SshUInt32 spi, SshUInt8 ipproto,
                           SshIpAddr remote_ip,
                           SshUInt16 remote_ike_port,
                           SshVriId routing_instance_id);

SshPmSpiOut
ssh_pm_lookup_outbound_spi_by_inbound_spi(SshPm pm,
                                          SshUInt32 outbound_spi,
                                          SshUInt32 inbound_spi);

/** This deletes the IPsec SA matching `spi_out', `ipproto', `remote_ip' and
    `remote_ike_port'. If a matching SPI value is not found then this function
    calls `callback' with the parameter `transform_index' set to
    SSH_IPSEC_INVALID_INDEX. Otherwise this deletes the SA (transform, rules
    and flows) from the engine and calls `callback' with parameters set to
    the deleted SA. This function also creates a destroyed event for the
    deleted IPsec SA. */
void ssh_pm_delete_by_spi(SshPm pm, SshUInt32 spi_out,
                          SshVriId routing_instance_id,
                          SshUInt8 ipproto,
                          const SshIpAddr remote_ip,
                          SshUInt16 remote_ike_port,
                          SshPmSpiDeleteCB callback, void *context);

/** Remove all inbound SPI's in the transform object 'trd' from the
    Policy Manager inbound SPI mapping. If 'old' is TRUE remove old SPI's
    from before the rekey, trd->old_spis, otherwise remove trd->spis. */
void ssh_pm_spi_in_remove_by_trd(SshPm pm, SshEngineTransformData trd,
                                 Boolean old);

/** Lookup inbound SPI value for `trd_index' using `outbound_spi'. */
SshUInt32
ssh_pm_spi_in_by_trd(SshPm pm, SshUInt32 outbound_spi, SshUInt32 trd_index);

/** Remove all outbound SPI from the Policy Manager outbound SPI mapping. */
void ssh_pm_spi_out_remove(SshPm pm,
                           SshUInt32 tr_index,
                           SshUInt32 outbound_spi);

/** Find the outbound SPI entry for 'outbound_spi' and 'inbound_spi'
    and mark it as been successfully rekeyed. */
Boolean
ssh_pm_spi_mark_rekeyed(SshPm pm, SshUInt32 outbound_spi,
                        SshUInt32 inbound_spi);

/** Find the outbound SPI entry from 'outbound_spi' and 'inbound_spi'
    and mark that negotiation has started. */
Boolean
ssh_pm_spi_mark_neg_started(SshPm pm, SshUInt32 outbound_spi,
                            SshUInt32 inbound_spi);

/** Find the outbound SPI entry from 'outbound_spi' and 'inbound_spi' and
    mark that negotiation has been finished. */
Boolean
ssh_pm_spi_mark_neg_finished(SshPm pm, SshUInt32 outbound_spi,
                             SshUInt32 inbound_spi);


/** Find the outbound SPI entry from 'outbound_spi' and 'inbound_spi'
    and check is negotiation ongoing. */
Boolean
ssh_pm_spi_neg_ongoing(SshPm pm, SshUInt32 outbound_spi,
                       SshUInt32 inbound_spi);

/** Mark that we have a received a delete notification for an outbound spi
    `outbound_spi' for protocol `ipproto' from `remote_ip' and `remote_port'.
*/
void
ssh_pm_spi_mark_delete_received(SshPm pm, SshUInt32 outbound_spi,
                                SshUInt8 ipproto, const SshIpAddr remote_ip,
                                SshUInt16 remote_ike_port,
                                SshVriId routing_instance_id);

/** Check if we have received a delete notification for the outbound spi
    that is the counterpart of the inbound spi `inbound_spi'. */
Boolean
ssh_pm_spi_check_delete_received(SshPm pm, SshUInt32 inbound_spi);

/** Checks if SA events are disabled for the IPsec SA identified by
    `outbound_spi' and `inbound_spi'. This returns FALSE if SA events were
    disabled or if no matching IPsec SA was found, and TRUE otherwise. If
    `disable' is TRUE then this also disables the SA events for the IPsec
    SA. */
Boolean
ssh_pm_spi_disable_sa_events(SshPm,
                             SshUInt32 outbound_spi,
                             SshUInt32 inbound_spi,
                             Boolean disable);




void
ssh_pm_unknown_spi_packet(SshPm pm,
                          SshIpAddr local_ip, SshIpAddr remote_ip,
                          SshInetIPProtocolID ipproto, SshUInt32 spi,
                          SshInterceptorProtocol protocol,
                          SshUInt32 tunnel_id,
                          SshVriId routing_instance_id,
                          SshUInt32 ifnum, SshUInt32 flags,
                          SshUInt32 prev_transform_index,
                          unsigned char *packet, size_t packet_len);




void
ssh_pm_invalid_spi_notify(SshPm pm, SshUInt32 ike_sa_handle,
                          SshIpAddr local_ip, SshIpAddr remote_ip,
                          SshUInt16 remote_port, SshInetIPProtocolID ipproto,
                          SshUInt32 spi);

/** Report a new valid inbound SPI. */
void
ssh_pm_new_inbound_spi(SshPm pm,
                       SshIpAddr local_ip, SshIpAddr remote_ip,
                       SshInetIPProtocolID ipproto, SshUInt32 spi,
                       SshPmTunnel tunnel);


/** Initialize SPI management mappings. */
Boolean ssh_pm_spis_create(SshPm pm);

/** Uninitialize SPI management mappings and free all related resources. */
void ssh_pm_spis_destroy(SshPm pm);

/** Initialize unknown SPI management mappings. */
Boolean ssh_pm_unknown_spis_create(SshPm pm);

/** Uninitialize unknown SPI management mappings and free all related
    resources. */
void ssh_pm_unknown_spis_destroy(SshPm pm);



/* ******* General IKEV2 utility function ***************************/

/** Initiate XAUTH to a client after an IKE negotiation completes. Returns
    FALSE if the negotiation could not be initiated and TRUE otherwise. */
Boolean ssh_pm_p1_initiate_xauth_ike(SshPm pm, SshPmP1 p1);


/** Parse the notify payloads reveived in the last IKEv2 packet. */
void ssh_pm_ike_parse_notify_payloads(SshIkev2ExchangeData ed, SshPmQm qm);

/** Compare Identity payload (after linearized) to limited regural
    expression 'pattern'. If 'id' is not of comparable to 'type' this
    will return FALSE, else it will return if the 'id' matches the
    'pattern'. */
Boolean
ssh_pm_ikev2_id_compare_pattern(SshIkev2PayloadID id,
                                SshPmIdentityType type, const char *pattern);

/** Compare two IKE ID payloads.

    @return
    Returns TRUE if they are the same, and FALSE otherwise. */
Boolean ssh_pm_ikev2_id_compare(SshIkev2PayloadID id1,
                                SshIkev2PayloadID id2);

/** Check encapsulation mode from local policy in `tunnel' and proposed in
    `ed'. This also sets the value of `transport_mode_requested'. */
Boolean
ssh_pm_ike_tunnel_match_encapsulation(SshPmTunnel tunnel,
                                      SshIkev2ExchangeData ed,
                                      Boolean *transport_mode_requested);

/** Search for and return a policy rule for IKE responders. This is called
    after the responder has authenticated the initiator in IKE Phase-I.
    This function returns a policy rule for continuing the negotiation
    or NULL if no matching policy rule was found. */

/* Check rule authorization */
#define SSH_PM_RULE_LOOKUP_CHECK_AUTH               0x0001
/* Match encapsulation */
#define SSH_PM_RULE_LOOKUP_MATCH_ENCAP              0x0002
/* Rule lookup is done at IKEv1 phase 1 (all information is not available) */
#define SSH_PM_RULE_LOOKUP_IKEV1_PHASE1             0x0004
/* Attempt to use transport mode NAT-T traffic selectors. */
#define SSH_PM_RULE_LOOKUP_TRANSPORT_MODE_TS        0x0008
/* Attempt to match the packet selectors (first item of ts) */
#define SSH_PM_RULE_LOOKUP_MATCH_TO_FIRST_TS_ITEM   0x00010000

SshPmRule ssh_pm_ike_responder_rule_lookup(SshPm pm, SshPmP1 p1,
                                           SshIkev2ExchangeData ed,
                                           SshUInt32 flags,
                                           Boolean *forward,
                                           SshUInt32 *failure_mask);

/** Search for and return a policy tunnel for IKE responders. This is called
    when the responder receives the AUTH packet from the initiator.
    This function sets p1->n->tunnel used for authenticating the negotiation
    or else return IKEv2 error code if no matching policy tunnel was found. */
SshIkev2Error ssh_pm_select_ike_responder_tunnel(SshPm pm , SshPmP1 p1,
                                                 SshIkev2ExchangeData ed);

/** Returns the traffic selectors from a rule. */
Boolean
ssh_pm_rule_get_traffic_selectors(SshPm pm, SshPmRule rule,
                                  Boolean forward,
                                  SshIkev2PayloadTS *local,
                                  SshIkev2PayloadTS *remote);

/** Duplicate and free ID payload. This returns a mallocated version ID
    payload with identical contents to 'id'. Returns NULL if out of
    memory. The free function can only be used to free 'dup'd id's, not
    the ones received from IKE library (that come from Obstacks). */
SshIkev2PayloadID ssh_pm_ikev2_payload_id_dup(SshIkev2PayloadID id);
void ssh_pm_ikev2_payload_id_free(SshIkev2PayloadID id);


/** Allocate and fill in attributes for a Configuration mode payload. */
SshIkev2PayloadConf
ssh_pm_construct_conf_request_payload(SshPm pm, SshPmP1 p1);

SshIkev2PayloadConf
ssh_pm_construct_conf_reply_payload(SshPm pm, SshPmP1 p1);

/** Worker function for IPSEC SA install */
SshOperationHandle
ssh_pm_ipsec_sa_install_qm(SshPm pm,
                           SshPmP1 p1, SshPmQm qm,
                           SshIkev2SadIPsecSaInstallCB reply_callback,
                           void *reply_callback_context);

/** Worker function for IKE SA get operation */
SshIkev2Sa
ssh_pm_ike_sa_get_by_spi(SshSADHandle sad_handle,
                         const unsigned char *ike_sa_spi);

#ifdef SSHDIST_IKEV1
/** Filter p1 compat flags. This is used for IKEv1 only. */
void pm_ike_sa_filter_v1_compat_flags(SshPm pm, SshPmP1 p1);
#endif /* SSHDIST_IKEV1 */

/* ************** Completion callbacks for IKEv2 exchanges ******************/

/** Completion callback for ssh_ikev2_ipsec_send(). */
void
pm_ipsec_sa_done_callback(SshSADHandle sad_handle,
                          SshIkev2Sa sa,
                          SshIkev2ExchangeData ed,
                          SshIkev2Error error);

/** Common completion callback for ssh_ikev2_info_send() for all operations. */
void
pm_ike_info_done_common(SshPm pm,
                        SshPmP1 p1,
                        SshIkev2ExchangeData ed,
                        SshIkev2Error error);

/** Completion callback for ssh_ikev2_info_send() for simple operations. */
void
pm_ike_info_done_callback(SshSADHandle sad_handle,
                          SshIkev2Sa sa,
                          SshIkev2ExchangeData ed,
                          SshIkev2Error error);

/** Notify callback for ssh_ikev2_ike_sa_delete(). If 'error' indicates that
    the sending of delete notification failed, then this function will call
    ssh_ikev2_ike_sa_delete() with SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION
    to delete the IKE SA. */
void
pm_ike_sa_delete_notification_done_callback(SshSADHandle sad_handle,
                                            SshIkev2Sa sa,
                                            SshIkev2ExchangeData ed,
                                            SshIkev2Error error);

/** Notify callback for ssh_ikev2_ike_sa_delete(). */
void
pm_ike_sa_delete_done_callback(SshSADHandle sad_handle,
                               SshIkev2Sa sa,
                               SshIkev2ExchangeData ed,
                               SshIkev2Error error);

/** Notify callback for ssh_ikev2_ike_sa_rekey(). */
void
pm_ike_sa_rekey_done_callback(SshSADHandle sad_handle,
                              SshIkev2Sa sa,
                              SshIkev2ExchangeData ed,
                              SshIkev2Error error);

/* ************************  IKE SAD interface ******************************/

SshOperationHandle
ssh_pm_ike_sa_allocate(SshSADHandle sad_handle,
                       Boolean initiator,
                       SshIkev2SadIkeSaAllocateCB reply_callback,
                       void *reply_callback_context);

SshOperationHandle
ssh_pm_ike_sa_get(SshSADHandle sad_handle,
                  const SshUInt32 ike_version,
                  const unsigned char *ike_sa_spi_i,
                  const unsigned char *ike_sa_spi_r,
                  SshIkev2SadIkeSaGetCB reply_callback,
                  void *reply_callback_context);

void
ssh_pm_ike_sa_take_ref(SshSADHandle sad_handle, SshIkev2Sa ike_sa);

void
ssh_pm_ike_sa_free_ref(SshSADHandle sad_handle, SshIkev2Sa ike_sa);


SshIkev2ExchangeData
ssh_pm_ike_exchange_data_alloc(SshSADHandle sad_handle,
                               SshIkev2Sa sa);

void ssh_pm_ike_exchange_data_free(SshSADHandle sad_handle,
                                   SshIkev2ExchangeData exchange_data);


void
ssh_pm_ike_enumerate(SshSADHandle sad_handle,
                     SshIkev2SadIkeSaEnumerateCB enumerate_callback,
                     void *context);

SshOperationHandle
ssh_pm_ike_sa_delete(SshSADHandle sad_handle,
                     SshIkev2Sa sa,
                     SshIkev2SadDeleteCB reply_callback,
                     void *reply_context);

SshOperationHandle
ssh_pm_ike_sa_rekey(SshSADHandle sad_handle,
                    Boolean delete_old,
                    SshIkev2Sa old_sa,
                    SshIkev2Sa new_sa,
                    SshIkev2SadRekeyedCB reply_callback,
                    void *reply_context);
void
ssh_pm_ike_sa_done(SshSADHandle sad_handle,
                   SshIkev2ExchangeData ed,
                   SshIkev2Error error_code);

SshOperationHandle
ssh_pm_ipsec_sa_install(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        SshIkev2SadIPsecSaInstallCB reply_callback,
                        void *reply_callback_context);

SshOperationHandle
ssh_pm_ipsec_spi_allocate(SshSADHandle sad_handle,
                          SshIkev2ExchangeData ed,
                          SshIkev2SadIPsecSpiAllocateCB reply_callback,
                          void *reply_context);

void ssh_pm_ipsec_spi_delete(SshSADHandle sad_handle, SshUInt32 spi);

SshOperationHandle
ssh_pm_ipsec_spi_delete_received(SshSADHandle sad_handle,
                                 SshIkev2ExchangeData ed,
                                 SshIkev2ProtocolIdentifiers protocol,
                                 int number_of_spis,
                                 SshUInt32 *spi_array,
                                 SshIkev2SadDeleteReceivedCB reply_callback,
                                 void *reply_context);

void
ssh_pm_ipsec_sa_update(SshSADHandle sad_handle,
                       SshIkev2ExchangeData ed,
                       SshIpAddr ip_address, SshUInt16 port);

void
ssh_pm_ipsec_sa_done(SshSADHandle sad_handle,
                     SshIkev2ExchangeData ed,
                     SshIkev2Error error_code);


/* *********************  IKE SPD interface *****************************/

SshOperationHandle
ssh_pm_ike_spd_fill_ike_sa(SshSADHandle sad_handle,
                           SshIkev2ExchangeData ed,
                           SshIkev2SpdFillSACB reply_callback,
                           void *reply_callback_context);

SshOperationHandle
ssh_pm_ike_spd_fill_ipsec_sa(SshSADHandle sad_handle,
                             SshIkev2ExchangeData ed,
                             SshIkev2SpdFillSACB reply_callback,
                             void *reply_callback_context);

/** Select an IKE SA proposal. */
SshOperationHandle
ssh_pm_ike_spd_select_ike_sa(SshSADHandle sad_handle,
                              SshIkev2ExchangeData ed,
                              SshIkev2PayloadSA sa_in,
                              SshIkev2SpdSelectSACB reply_callback,
                             void *reply_callback_context);


/** Select an IPSEC SA proposal. */
SshOperationHandle
ssh_pm_ike_spd_select_ipsec_sa(SshSADHandle sad_handle,
                               SshIkev2ExchangeData ed,
                               SshIkev2PayloadSA sa_in,
                               SshIkev2SpdSelectSACB reply_callback,
                               void *reply_callback_context);

/** Narrow traffic selectors. */
SshOperationHandle
ssh_pm_ike_narrow_traffic_selectors(SshSADHandle sad_handle,
                                    SshIkev2ExchangeData ed,
                                    SshIkev2PayloadTS ts_in_local,
                                    SshIkev2PayloadTS ts_in_remote,
                                    SshIkev2SpdNarrowCB reply_callback,
                                    void *reply_callback_context);

/** Encode remote access attributes into the IKEv2 configuration payload. */
Boolean
ssh_pm_encode_remote_access_attrs(SshIkev2PayloadConf conf_payload,
                                  SshPmRemoteAccessAttrs attributes);

/** Encode the IKEV2 configuration payload into remote access attributes */
Boolean
ssh_pm_decode_conf_payload_request(SshIkev2PayloadConf conf_payload,
                                   SshPmRemoteAccessAttrs cfgmode_attrs);

/** Notify for responder exchange completion. */
void
ssh_pm_ike_spd_responder_exchange_done(SshSADHandle sad_handle,
                                       SshIkev2Error error,
                                       SshIkev2ExchangeData ed);

/* *********************  IKE PAD interface *****************************/

SshOperationHandle
ssh_pm_ike_new_connection(SshSADHandle sad_handle,
                          SshIkev2Server server,
                          SshUInt8 major, SshUInt8 minor,
                          SshIpAddr remote_address,
                          SshUInt16 port,
                          SshIkev2PadNewConnectionCB reply_callback,
                          void *reply_callback_context);

#ifdef SSHDIST_IKE_REDIRECT
SshOperationHandle
ssh_pm_ike_redirect(SshSADHandle sad_handle,
                    SshIkev2ExchangeData ed,
                    SshIkev2PadIkeRedirectCB reply_callback,
                    void *reply_callback_context);
#endif /* SSHDIST_IKE_REDIRECT */

SshOperationHandle
ssh_pm_ike_id(SshSADHandle sad_handle,
              SshIkev2ExchangeData ed,
              Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
              SshUInt32 authentication_round,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
              SshIkev2PadIDCB reply_callback,
              void *reply_callback_context);

SshOperationHandle
ssh_pm_ike_pre_shared_key(SshSADHandle sad_handle,
                          SshIkev2ExchangeData ed,
                          Boolean local,
                          SshIkev2PadSharedKeyCB reply_callback,
                          void *reply_callback_context);


void
ssh_pm_ike_received_vendor_id(SshSADHandle sad_handle,
                              SshIkev2ExchangeData ed,
                              const unsigned char *vendor_id,
                              size_t vendor_id_len);

SshOperationHandle
ssh_pm_ike_request_vendor_id(SshSADHandle sad_handle,
                             SshIkev2ExchangeData ed,
                             SshIkev2PadAddVendorIDCB reply_callback,
                             void *reply_callback_context);

SshOperationHandle
ssh_pm_ike_spd_notify_request(SshSADHandle sad_handle,
                               SshIkev2ExchangeData ed,
                               SshIkev2SpdNotifyCB reply_callback,
                              void *reply_callback_context);

void
ssh_pm_ike_spd_notify_received(SshSADHandle sad_handle,
                               SshIkev2NotifyState notify_state,
                               SshIkev2ExchangeData ed,
                               SshIkev2ProtocolIdentifiers protocol_id,
                               unsigned char *spi,
                               size_t spi_size,
                               SshIkev2NotifyMessageType notify_message_type,
                               unsigned char *notification_data,
                               size_t notification_data_size);

void
ssh_pm_ike_conf_received(SshSADHandle sad_handle,
                         SshIkev2ExchangeData ed,
                         SshIkev2PayloadConf conf_payload_in);

SshOperationHandle
ssh_pm_ike_conf_request(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        SshIkev2PadConfCB reply_callback,
                        void *reply_callback_context);


#ifdef SSHDIST_IPSEC_MOBIKE
SshOperationHandle
ssh_pm_ike_get_address_pair(SshSADHandle sad_handle,
                            SshIkev2ExchangeData ed,
                            SshUInt32 address_index,
                            SshIkev2PadGetAddressPairCB reply_callback,
                            void *reply_callback_context);

SshOperationHandle
ssh_pm_ike_get_additional_address_list(SshSADHandle sad_handle,
                                       SshIkev2ExchangeData ed,
                                       SshIkev2PadGetAdditionalAddressListCB
                                       reply_callback,
                                       void *reply_callback_context);
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_IKE_EAP_AUTH
void
ssh_pm_ike_eap_received(SshSADHandle sad_handle,
                        SshIkev2ExchangeData ed,
                        const unsigned char *eap,
                        size_t eap_length);
SshOperationHandle
ssh_pm_ike_eap_request(SshSADHandle sad_handle,
                       SshIkev2ExchangeData ed,
                       SshIkev2PadEapRequestCB reply_callback,
                       void *reply_callback_context);
SshOperationHandle
ssh_pm_ike_eap_key(SshSADHandle sad_handle,
                   SshIkev2ExchangeData ed,
                   SshIkev2PadSharedKeyCB reply_callback,
                   void *reply_callback_context);

#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_XAUTH
SshOperationHandle
ssh_pm_xauth(SshSADHandle sad_handle,
             SshIkev2ExchangeData ed,
             SshIkev2FbXauthRequest request,
             SshIkev2FbXauthSet set,
             SshIkev2FbXauthDone done,
             void *callback_context);

SshOperationHandle
pm_xauth_client_request(SshIkev2Sa sa,
                        SshIkev2FbXauthAttributes attributes,
                        SshIkev2FbXauthStatus callback,
                        void *callback_context,
                        void *user_callback_context);

SshOperationHandle
pm_xauth_client_set(SshIkev2Sa sa,
                    Boolean status,
                    const unsigned char *message, size_t message_len,
                    SshIkev2FbXauthAttributes attributes,

                    SshIkev2FbXauthStatus callback,
                    void *callback_context,
                    void *user_callback_context);
#endif /* SSHDIST_IKE_XAUTH */

/* *************************** Virtual adapters *****************************/

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT

/** Start setting up the virtual IP corresponding to tunnel
    `tunnel' and rule `rule' and return immediately. Return TRUE if a
    virtual IP subthread was started succesfully, FALSE otherwise.
    On success this functions sets the virtual adapter reference count
    to one. This reference is freed when the qm thread terminates. */
Boolean
ssh_pm_use_virtual_ip(SshPm pm, SshPmTunnel tunnel, SshPmRule rule);

/** Signal vip thread to start shutdown.  This is called from
    ssh_pm_virtual_ip_free when the vip reference count reaches zero. */
void
ssh_pm_stop_virtual_ip(SshPm pm, SshPmTunnel tunnel);

/** Take a reference to the virtual IP. A reference is taken for each
    IPSec SA during trd creation, and for each qm negotiation that uses the
    virtual IP interface. */
Boolean
ssh_pm_virtual_ip_take_ref(SshPm pm, SshPmTunnel tunnel);

/** Free reference to the virtual IP. When the reference count reaches
    zero, the virtual IP will be stopped. References from IPSec SAs
    are freed when the destroyed event is received for the trd. References
    from qm negotiations are freed when the qm thread terminates. */
Boolean
ssh_pm_virtual_ip_free(SshPm pm, SshUInt32 trd_index, SshPmTunnel tunnel);

/** Returns TRUE if the IP address 'addr' is an address of the virtual
    adpater 'vip' and FALSE otherwise. */
Boolean
ssh_pm_address_is_virtual(SshPm pm, SshPmVip vip, SshIpAddr addr);

/** Set IKE peer to vip object. The peer is used for deleting SA which use
    this vip object. This returns TRUE on success. */
Boolean
ssh_pm_virtual_ip_set_peer(SshPm pm, SshPmTunnel tunnel,
                           SshUInt32 peer_handle);

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
/** Add policy rules based on received config mode information if
    necessary. Return TRUE if any rules were added, FALSE
    otherwise. */
Boolean
ssh_pm_virtual_ip_update_cfgmode_rules(SshPm pm, SshPmVip vip);
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

/** Open a RADIUS accounting session for cfgmode client and send
    Accounting-Start request.  Does nothing, if RADIUS configuration
    is disabled in PM.
 */
void pm_ras_radius_acct_start(SshPm pm, SshPmActiveCfgModeClient client);

/** Close a RADIUS accounting session of the cfgmode client and send
    Accounting-Stop request.  Does nothing is the client has not an
    open RADIUS accounting session. If RADIUS accounting configuration
    in PM is disabled accounting session is closed, but no
    Accounting-Stop is sent.
 */
void pm_ras_radius_acct_stop(SshPm pm, SshPmActiveCfgModeClient client);

/** Causes RADIUS Accounting instance to be released. The resources,
    i.e.  Memory and udp listener, are freed when there are no longer
    pending requests. Can be called multiple times to poll if shutdown
    is complete. Returns TRUE when shutdown is complete FALSE, when
    there are still requests in transmission.
 */
Boolean pm_ras_radius_acct_shutdown(SshPm pm);

/** Encodes possible RADIUS Accounting session to buffer from
    client. Returns 0 on error.
 */
size_t pm_radius_acct_encode_session(SshBuffer buffer,
                                     SshPmP1 p1);

/** Decodes RADIUS Accounting session from buffer. If no Accounting
    session available, or on error, returns NULL. On success returns
    pointer to accounting session data within buffer. The pointer must
    not be freed and it may not be used after the buffer is freed.
 */
const void * pm_radius_acct_decode_session(SshBuffer buffer);

/** Installs RADIUS Accounting session from pointer returned by
    pm_radius_acct_decode_session() to client. Expects both client and
    radius_acct_context to be valid pointers.
 */
void pm_radius_acct_install_session(SshPmActiveCfgModeClient client,
                                    const void * radius_acct_context);

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/* *************************** Auth domain internal **************************/

#ifdef SSHDIST_CERT
/* Policy manager internal utility function.
   Do NOT use outside policymanager i.e. from xmlconf. */
SshCMCertificate
ssh_pm_auth_domain_add_cert_internal(SshPm pm, SshPmAuthDomain ad,
                                     const unsigned char *cert,
                                     size_t cert_len,
                                     Boolean external);
#endif /* SSHDIST_CERT */

#endif /* not IPSEC_INTERNAL_H */
