/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp global defaults.
*/

#ifndef ISAKMP_DEFAULTS_H
#define ISAKMP_DEFAULTS_H

/*                                                              shade{0.9}
 *
 * Some configuration defines.
 *                                                              shade{1.0}
 */

/*                                                              shade{0.9}
 *
 * Some defaults.
 *                                                              shade{1.0}
 */

/* Default ip to listen */
#define SSH_IKE_DEFAULT_IP      SSH_IPADDR_ANY
/* Default port to listen */
#define SSH_IKE_DEFAULT_PORT    "500"
/* Length of ip address string */
#define SSH_IKE_IP_ADDR_STR_LEN 64
/* Length of port number string */
#define SSH_IKE_IP_PORT_STR_LEN 16
/* Max length of isakmp udp packet */
#define SSH_IKE_MAX_UDP_PACKET  65535
/* Max length of isakmp packet (in encode, leave some space for padding etc) */
#define SSH_IKE_MAX_PACKET_LEN  65520

/* Base timers */
/* Isakmp retry limit */
#define SSH_IKE_BASE_RETRY_LIMIT                10

/* Isakmp retry timer. When this expires the packet is retransmitted. */
#define SSH_IKE_BASE_RETRY_TIMER                0
#define SSH_IKE_BASE_RETRY_TIMER_USEC           500000

/* Isakmp max retry timer. Maximum value the retransmit timer can be. */
#define SSH_IKE_BASE_RETRY_TIMER_MAX            30
#define SSH_IKE_BASE_RETRY_TIMER_MAX_USEC       0

/* Isakmp SA expire timer (in seconds). When this expires the whole isakmp sa
   negotition is removed. */
#define SSH_IKE_BASE_EXPIRE_TIMER               300
#define SSH_IKE_BASE_EXPIRE_TIMER_USEC          0

/* Extended timers */
/* Isakmp retry limit */
#define SSH_IKE_EXTENDED_RETRY_LIMIT            10

/* Isakmp retry timer. When this expires the packet is retransmitted. */
#define SSH_IKE_EXTENDED_RETRY_TIMER            1
#define SSH_IKE_EXTENDED_RETRY_TIMER_USEC       0

/* Isakmp max retry timer. Maximum value the retransmit timer can be. */
#define SSH_IKE_EXTENDED_RETRY_TIMER_MAX        60
#define SSH_IKE_EXTENDED_RETRY_TIMER_MAX_USEC   0

/* Isakmp SA expire timer (in seconds). When this expires the whole isakmp sa
   negotition is removed. */
#define SSH_IKE_EXTENDED_EXPIRE_TIMER           600
#define SSH_IKE_EXTENDED_EXPIRE_TIMER_USEC      0

/* Isakmp local secret recreation timer. No isakmp SA can be exist longer
   than twice this seconds, because after that its cookie is no longer
   recognized as ours. */
#define SSH_IKE_SECRET_RECREATE_TIMER   (4*60*60)
/* Default life duration for isakmp sa (in seconds) */
#define SSH_IKE_DEFAULT_LIFE_DURATION   (3*60*60)

/* Number of randomizers calculated one, max number of randomizers for group,
   limit of idle time (sec) before generating one and retry timer time (secs),
   first default groups then private groups. */
#define SSH_IKE_RANDOMIZERS_DEFAULT_CNT         2
#define SSH_IKE_RANDOMIZERS_DEFAULT_MAX_CNT     100
#define SSH_IKE_RANDOMIZERS_DEFAULT_RETRY       2
#define SSH_IKE_RANDOMIZERS_PRIVATE_CNT         1
#define SSH_IKE_RANDOMIZERS_PRIVATE_MAX_CNT     10
#define SSH_IKE_RANDOMIZERS_PRIVATE_RETRY       2

/* Use new ssh_ike_register_policy_functions() call to register policy manager
   callbacks, instead of using fixed names. */
#ifdef SSHDIST_IPSEC
#define SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
#else /* SSHDIST_IPSEC */
#undef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
#endif /* SSHDIST_IPSEC */

#endif /* ISAKMP_DEFAULTS_H */
