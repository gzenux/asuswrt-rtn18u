/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file defines tunable configuration parameters for the IPsec
   system (Interceptor, FastPath, Engine and Policy Manager).

   @description
   Most values define the maximum number of objects allowed, and some
   are used for scaling the system.

   Note: When deleting rules, tunnels or services for an existing
   policy and replacing them with new ones in the same commit call,
   the deletions are done only after the additions. This should be
   taken into account when estimating resource usage.
*/

#ifndef IPSEC_PARAMS_H
#define IPSEC_PARAMS_H

/* Get distribution definition and configuration values. */
#include "sshincludes.h"

/** Define SSH_IPSEC_SMALL to compile a minimal system.

   This will:

   * leave out most optional algorithms
   * optimize various algoritms for space rather than performance
   * use linear scan for decision tree
   * use arrays and linear scans for interfaces
   * not use repetive timers to enable systems to sleep.

   This is appropriate when Engine is used in small environments,
   such as handheld devices (PDAs, mobile phones) or low-end consumer
   products (such as ISDN modems).  This would often be combined with
   SSH_IPSEC_PREALLOCATE_TABLES and/or SSH_IPSEC_UNIFIED_ADDRESS_SPACE. */

/* #define SSH_IPSEC_SMALL */


/* Read in distribution related configuration header. */
#ifdef SSH_IPSEC_SMALL
#include "ipsec_params_small.h"
#endif /* SSH_IPSEC_SMALL */






/* ********************************************************************
 * The following parameters can be tuned on a per-system basis.  They
 * directly affect memory allocation style and memory requirements of
 * the engine and policy manager, and consequently the number of
 * maximum security security associations, flows, etc. that can be
 * supported.  Several options related to whether individual features
 * should be compiled in are also included here.
 * ********************************************************************/

/** Define this if you want tables (flow table, flow id hash, next hop
   data, arp cache, etc) to be preallocated with fixed sizes (as
   global variables).  This may be desirable on many embedded
   platforms.  Preallocated tables implies that there can be only one
   instance of the engine in the system.  It also implies that the
   maximum amount of memory needed for the tables will always be
   consumed, even if the tables are almost empty.  This variable can
   also be defined in a Makefile so that the source tree does not need
   to be modified. */
#ifndef SSH_IPSEC_PREALLOCATE_TABLES
/* #define SSH_IPSEC_PREALLOCATE_TABLES */
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

/** Define SSH_IPSEC_UNIFIED_ADDRESS_SPACE if Engine and Policy
    Manager both reside in the same address space.  This will
    eliminate a fair amount of code related to communication between
    Engine and Policy Manager, and will change the way debug
    messages are handled (this implies that Engine and Policy
    Manager share the same debug settings).  DO NOT SET THIS HERE.
    THIS IS CURRENTLY SET IN THE MAKEFILE IN THE UNIFIED SUBDIRECTORY.
    */

/* #define SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

#ifdef VXWORKS
/* Override SSH_IPSEC_UNIFIED_ADDRESS_SPACE for VxWorks. VxWorks is
   compiled in the unified-kernel subdirectory but uses message-based
   interface between the policy manager and the engine. */
#undef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
#endif /* VXWORKS */


/* Define this if the interceptor operates at IP level (that is, no
   interface supplies or requires packets at ethernet level, or
   generally media level).  Generally there is no much difference in
   performance whether the interceptor operates at ethernet level or
   at IP level; however, some functionality (particularity the ability
   to proxy arp so that the same subnet can be shared for both
   external and DMZ interfaces) is not available without an ethernet
   level interceptor. */

/* #define SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#if defined(VXWORKS) || defined(WINDOWS)
#undef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#endif /* VXWORKS or WINDOWS */

/* Maximum number of low level interceptor packets out at any given time. */
#ifndef SSH_INTERCEPTOR_MAX_PACKETS
# ifdef WINDOWS
#  define SSH_INTERCEPTOR_MAX_PACKETS 20000
# else /* WINDOWS */
#  define SSH_INTERCEPTOR_MAX_PACKETS (0xffffffff)
# endif /* WINDOWS */
#endif /* SSH_INTERCEPTOR_MAX_PACKETS */

/** Define this if statistics should be collected. */
#define SSH_IPSEC_STATISTICS

/** Define this if you want internal routing in the engine. */
/* #define SSH_IPSEC_INTERNAL_ROUTING */

/** Define this if you want to include the AH transform. */
#define SSH_IPSEC_AH

/** Define this to add support for IPCOMP in software. Software IPCOMP
    currently cannot be used when building on systems with small stack
    sizes (when MINIMAL_STACK is defined). */
#ifndef MINIMAL_STACK
#define SSH_IPSEC_IPCOMP_IN_SOFTWARE
#endif /* MINIMAL_STACK */

/** Enable the single DES cipher for use in IKE and IPsec. RFC 4305 specifies
    that implementations SHOULD NOT provide single DES, and so it is disabled
    here by default . */
/* #define SSH_IPSEC_CRYPT_DES */

/** Extension ciphers.  You can uncomment the following definitions to
    define additional ciphers to the extension slots 1 and 2.  Note
    that if you define any of the extension ciphers to have a big key
    size (bigger that 3DES' 192) you must also update the
    SSH_IPSEC_MAX_ESP_KEY_BITS below. */






/** Maximum number of bits in an ESP encryption key.  Make this bigger
    if you want to use bigger keys.  However, 256 bits should be
    sufficient for most practical purposes and for standards
    compliance (aes, 3des, des).

    If using counter mode encryption, the ESP cipher nonce is
    concatenated with the ESP encryption key. This implies that the
    ESP cipher key length plus the ESP cipher nonce length must be no
    larger than SSH_IPSEC_MAX_ESP_KEY_BITS, e.g. if you wish to use
    AES-192 CTR mode or AES-192 GCM mode, SSH_IPSEC_MAX_ESP_KEY_BITS
    must be 192 + 32 = 224 (the nonce size is 32 bits). For cbc mode
    of encryption the cipher nonce is not present.

*/
#ifndef SSH_IPSEC_MAX_ESP_KEY_BITS
# define SSH_IPSEC_MAX_ESP_KEY_BITS      (256+32) /* aes256-ctr */
#endif /* SSH_IPSEC_MAX_ESP_KEY_BITS */

/** The maximum number of bits in a message authentication code key
   (for AH or ESP).  Make this bigger if you want to use bigger keys.
   160 should be sufficient for most practical purposes and for
   standards compliance. However, SHA2 requires up-to 512 bits and
   AES-GMAC requires up-to 288 bits. */

#ifdef SSHDIST_CRYPT_SHA512
#define SSH_IPSEC_MAX_MAC_KEY_BITS      512
#else /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_MODE_GCM
#define SSH_IPSEC_MAX_MAC_KEY_BITS      (256+32)
#else /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_SHA256
#define SSH_IPSEC_MAX_MAC_KEY_BITS      256
#else /* SSHDIST_CRYPT_SHA256 */
#define SSH_IPSEC_MAX_MAC_KEY_BITS      160
#endif /* SSHDIST_CRYPT_SHA256 */
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_SHA512 */

/** The maximum number of bits in a message integrity check value.
    With hmac-md5 and hmac-sha1 96 bits are typically used. However,
    with SHA2 algorithms 128 to 256 bits are used.
    AES-GCM also requires 128 bits. */
#ifdef SSHDIST_CRYPT_SHA512
#define SSH_IPSEC_MAX_HMAC_OUTPUT_BITS  256
#else /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_SHA256
#define SSH_IPSEC_MAX_HMAC_OUTPUT_BITS  128
#else /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_MODE_GCM
#define SSH_IPSEC_MAX_HMAC_OUTPUT_BITS  128
#else /* SSHDIST_CRYPT_MODE_GCM */
#define SSH_IPSEC_MAX_HMAC_OUTPUT_BITS   96
#endif /* SSHDIST_CRYPT_MODE_GCM */
#endif /* SSHDIST_CRYPT_SHA256 */
#endif /* SSHDIST_CRYPT_SHA512 */

/** Default policy for fragment handling. See core_pm_shared.h
    SshEngineFragmentPolicy typedef for legal values. */
#define SSH_IPSEC_DEFAULT_FRAG_POLICY SSH_IPSEC_FRAGS_LOOSE_MONITOR

/* Specify sanity checking of unknown IP options. If this is set
   to TRUE, then unrecognized options are allowed. If this
   is set to FALSE, they are dropped.
   Note that the semantics of IP options are such, that
   it is not possible to parse correctly the set of
   options in a packet if the option is recognized.
   This is because the encoding of the option
   (1 byte for type or several bytes of type-length-value)
   is specified on a case-by-case basis. Quicksec
   assumes that the encoding is type-length-value for
   unrecognized options and if it fails to parse
   correctly the set of headers it drops the packet. */
#define SSH_IPSEC_ALLOW_UNKNOWN_IPV4_OPTIONS TRUE

/* Enable TCP/UDP protocol monitoring. This implies that certain
   attacks and stateful inspection of TCP session will be
   performed. The TCP monitor options below have no effect if
   this option is disabled. */
/* #define SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

/* Enable this to start IKE & other servers on link local
   addresses. */
/* #define SSH_IPSEC_LINK_LOCAL_SERVERS */

/* Enable TCP encapsulation of IKE and IPsec packets. */
/* #define SSH_IPSEC_TCPENCAP */

/* Do not perform sanity checks on packets which are redundant
   compared to those performed by the Linux ip_rcv() function.
   Set this if you are receiving packets via Linux netfilter
   hooks. Works only on IP level interceptor. */
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* #define SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Define this to convert SNAP packets into ethernet II frames. In
   Microsoft Windows Mobile platforms this is enabled by default. */
/* #define SSH_IPSEC_CONVERT_SNAP_TO_EII */

#if !defined(SSH_IPSEC_UNIFIED_ADDRESS_SPACE) && !defined(USERMODE_ENGINE)
/* Perform additional stack unwinds and recursive call detection. This
   is required if ssh_interceptor_send() is synchronous and a
   recursion back into the quicksec engine can happen from it. This is
   never the case on unified usermode. By default this is always turned
   on, since it's safer and per platform turned off if necessary. */
#define SSH_IPSEC_SEND_IS_SYNC
#endif /* not unified usermode */

#if defined(VXWORKS) || defined(WINDOWS) || defined(__linux__)
/* Leaving SSH_IPSEC_SEND_IS_SYNC undefined for VxWorks, Windows
   and linux generally gives better performance. */
#undef SSH_IPSEC_SEND_IS_SYNC
#endif /* VXWORKS || WINDOWS || __linux__ */

/* Unsetting this tunable disables ingress filtering in the reverse
   direction of flows. This has a security implication.
   Flow lookups for packets in the reverse direction will
   not consider the interface the packet arrived on, e.g.
   ingress filtering is not performed. This can help in
   scenarios where the external routes can be ambiguous. */
#define SSH_IPSEC_REVERSE_IFNUM_FILTERING

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

/* Enable TCP sequence number monitoring. Note that this requires
   that fragmentation policy be set to SSH_IPSEC_FRAGS_STRICT_MONITOR
   at runtime. This allows one to filter out illegitimate RST and FIN
   control messages. This incurs a penalty of at least 12 bytes
   per flow. If this is not enabled you might want to disable
   Protocol Monitors completely. */
#define SSH_IPSEC_TCP_SEQUENCE_MONITOR

/* Enable TCP sequence number randomization. This adds/subtracts
   cryptographically strong pseudo-random deltas to sequence
   numbers passing through. This incurs a penalty of
   at least 8 bytes per flow. */
#define SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER

#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

#ifdef SSHDIST_XML
/* Enable XML policy parsing. If this is not set, then no
   XML parsing will be performed. The purpose of this tunable
   is to let the source tree compile cleanly even if sshxml
   library is not included. */
#define SSH_IPSEC_XML_CONFIGURATION
#endif /* SSHDIST_XML */

#ifdef SSHDIST_HTTP_SERVER
/* Enable HTTP interface for statistics etc. If this is set,
   then the HTTP interface can be configured via policy, otherwise
   it does not exist in the binary. The existence of the HTTP
   interface is currently dependent on the inclusion of XML config
   parsing. */
#ifdef SSH_IPSEC_XML_CONFIGURATION
#define SSH_IPSEC_HTTP_INTERFACE
#endif /* SSH_IPSEC_XML_CONFIGURATION */
#endif /* SSHDIST_HTTP_SERVER */







/* Allow flows to survive transient TransformData deletions. This
   is useful, if NAT, APPGWS or PROTOCOL monitors are used. */
#if defined(SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS) || defined(SSHDIST_IPSEC_NAT)
/* If the new transform has different outer header IP addresses than the old
   transform, the flow should be rerouted rather than undangled.
   Undefining this setting causes all flow to be deleted when their transform
   is deleted. The flows are recreated through normal engine rule execution
   once the new transform has been installed. */
/* #define SSH_ENGINE_DANGLE_FLOWS */
#endif


/* ********************************************************************
 * Rough specification of the size of the system in terms of the
 * maximum number of TCP/IP connections and security associations
 * that may be active simultaneously.
 * Suitable values may be something like:
 *   PDA, mobile phone:     5 SAs, 10 sessions (<100 kB?)
 *   xDSL gateway:          20 SAs, 200 sessions (1MB?)
 *   medium router/VPN:     1000 SAs, 10 000 sessions (20MB?)
 *   huge router/VPN:       100 000 SAs, 200 000 sessions (>200MB?)
 * ********************************************************************/

/* The largest malloc() the engine can do. This is currently only
   heeded by the flow_table. On a Linux system you might want
   to consult the cache_sizes array in linux/mm/slab.c for a
   suitable setting. */
#if 0
#define SSH_ENGINE_MAX_MALLOC 65536
#else
#define SSH_ENGINE_MAX_MALLOC 32768
#endif /* 0 */

/* The maximum size packet for which the actual packet contents get included
   in triggers to the policy manager. Packets larger than this size will
   still be triggered to the policy manager but their packet data will not
   get included in the trigger. This has the practical effect that if the
   packet causing the trigger is larger than SSH_ENGINE_MAX_TRIGGER_PACKET_SIZE
   bytes, then this packet will be dropped. */
#ifndef SSH_ENGINE_MAX_TRIGGER_PACKET_SIZE
#define SSH_ENGINE_MAX_TRIGGER_PACKET_SIZE (SSH_ENGINE_MAX_MALLOC - 1000)
#endif /* SSH_ENGINE_MAX_TRIGGER_PACKET_SIZE */

/* The maximum number of filedescriptors the quicksecpm tries to
   request from the operating system. If SSH_PM_MAX_FILEDESCRIPTORS is
   set to -1 then the policymanager leaves the "max filedescriptors"
   limit untouched. If SSH_PM_MAX_FILEDESCRIPTORS is 0 then the pm
   requests unlimited filedescriptors. If SSH_PM_MAX_FILEDESCRIPTORS
   is set to any other value then this amount is requested to be used
   as the maximum. */








#ifndef SSH_PM_MAX_FILEDESCRIPTORS
#define SSH_PM_MAX_FILEDESCRIPTORS (-1)
#endif /* not SSH_PM_MAX_FILEDESCRIPTORS */



#ifdef SSHDIST_IPSEC_NAT
/* The maximum number of pending interface NATs.  This should be
   enought for all setups since you can only specify two NATs per
   interface, therefore this should be two times number of system
   interfaces. */
#ifndef SSH_PM_MAX_INTERFACE_NATS
#define SSH_PM_MAX_INTERFACE_NATS 20
#endif /* not SSH_PM_MAX_INTERFACE_NATS */

#ifdef SSHDIST_IPSEC_FIREWALL
/* The maximum number of application gateways being registered to
   a policy manager. */
#ifndef SSH_PM_MAX_APPGWS
#define SSH_PM_MAX_APPGWS       8
#endif /* not SSH_PM_MAX_APPGWS */

/* The maximum number of application gateway connections through the
   system. */
#ifndef SSH_PM_MAX_APPGW_CONNECTIONS
#define SSH_PM_MAX_APPGW_CONNECTIONS    (SSH_ENGINE_MAX_SESSIONS / 10 + 10)
#endif /* not SSH_PM_MAX_APPGW_CONNECTIONS */
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

/* The maximum number of high-level tunnel objects. */
#ifndef SSH_PM_MAX_TUNNELS
#define SSH_PM_MAX_TUNNELS              20
#endif /* not SSH_PM_MAX_TUNNELS */

/* The maximum number of high-level policy rules. */
#ifndef SSH_PM_MAX_RULES
#define SSH_PM_MAX_RULES        (SSH_PM_MAX_TUNNELS * 4)
#endif /* not SSH_PM_MAX_RULES */

/* The maximum number of service objects. */
#ifndef SSH_PM_MAX_SERVICES
#define SSH_PM_MAX_SERVICES     SSH_PM_MAX_RULES
#endif /* not SSH_PM_MAX_SERVICES */

/** Maximum number of peer objects in the peer information database. */
#define SSH_PM_MAX_PEER_HANDLES      (SSH_PM_MAX_TUNNELS * 2)

/** Maximum number of port pairs IKE is listening. The default is one
    pair (500,4500). */
#ifndef SSH_IPSEC_MAX_IKE_PORTS
#define SSH_IPSEC_MAX_IKE_PORTS 2
#endif /* SSH_IPSEC_MAX_IKE_PORTS */

/* The maximum number of active IKE SAs at the IKE library. */
#ifndef SSH_PM_MAX_IKE_SAS_IKE
#define SSH_PM_MAX_IKE_SAS_IKE       (SSH_PM_MAX_TUNNELS * 2)
#endif /* not SSH_PM_MAX_IKE_SAS_IKE */

/* The maximum number of active IKE SA contexts at policy manager.
   The policy manager has few more contexts than our IKE library.
   This way IKE can expire old negotiation and policy manager can
   start new ones even if IKE has all its SSH_PM_MAX_IKE_SAS_IKE
   established. */
#ifndef SSH_PM_MAX_IKE_SAS
#define SSH_PM_MAX_IKE_SAS   \
(SSH_PM_MAX_IKE_SAS_IKE + SSH_PM_MAX_IKE_SAS_IKE / 10)
#endif /* SSH_PM_MAX_IKE_SAS */

/* Size of the IKE SA hash table in the policy manager. */
#ifndef SSH_PM_IKE_SA_HASH_TABLE_SIZE
#define SSH_PM_IKE_SA_HASH_TABLE_SIZE   \
(SSH_PM_MAX_IKE_SAS < 100 ? 10 : SSH_PM_MAX_IKE_SAS / 10)
#endif /* SSH_PM_IKE_SA_HASH_TABLE_SIZE */

/* The maximum number of simultaneous IKE SA negotiations.  The system
   can have SSH_PM_MAX_IKE_SAS SAs but this limits the number of
   active negotiations. */
#ifndef SSH_PM_MAX_IKE_SA_NEGOTIATIONS
#define SSH_PM_MAX_IKE_SA_NEGOTIATIONS  25
#endif /* not SSH_PM_MAX_IKE_SA_NEGOTIATIONS */

/* The maximum number of simultaneous aggressive mode IKE SA
   negotiations. This value should always be less than or equal to
   SSH_PM_MAX_IKE_SA_NEGOTIATIONS */
#ifndef SSH_PM_MAX_AGGR_MODE_NEGOTIATIONS
#define SSH_PM_MAX_AGGR_MODE_NEGOTIATIONS \
        ((SSH_PM_MAX_IKE_SA_NEGOTIATIONS / 10) + 1)
#endif /* SSH_PM_MAX_AGGR_MODE_NEGOTIATIONS */

/* The maximum number of simultaneous Quick-Mode (IPsec) negotiations.
   The system supports more IPsec SAs but this limits the number of
   active negotiations. One half of this number of negtotiations,
   SSH_PM_MAX_QM_NEGOTIATIONS/2, are reserved for rekeys.  */
#ifndef SSH_PM_MAX_QM_NEGOTIATIONS
#define SSH_PM_MAX_QM_NEGOTIATIONS      50
#endif /* not SSH_PM_MAX_QM_NEGOTIATIONS */

/* The maximum number of child SAs per IKE SA. Define to zero to allow
   unlimited number of child SAs per IKE SA. The default value allows
   half of available child SAs for one IKE SA. */
#ifndef SSH_PM_MAX_CHILD_SAS
#define SSH_PM_MAX_CHILD_SAS            (SSH_PM_MAX_TUNNELS)
#endif /* not SSH_PM_MAX_CHILD_SAS */

/* The maximum number of pending IPsec delete notifications.  The
   IPsec delete notification processing is delayed for about 1 second
   after it is received.  This is needed to interoperate with some
   IPsec implementations which delete the old inbound IPsec SA
   immediately after rekey. */
#ifndef SSH_PM_MAX_PENDING_DELETE_NOTIFICATIONS
#define SSH_PM_MAX_PENDING_DELETE_NOTIFICATIONS (SSH_PM_MAX_IKE_SAS * 2)
#endif /* not SSH_PM_MAX_PENDING_DELETE_NOTIFICATIONS */

/* The maximum number of pending messages from policy manager to
   engine.  At the maximum the policy manager needs this many messages
   to run the requested amount of operations.  Each Quick-Mode
   negotiation can have one pending trigger completion running and one
   asynchronous engine operation from the next negotiation.  The `+1'
   is reserved for the main thread that handles policy
   reconfigurations and interface change processing. */
#ifndef SSH_PM_MAX_PENDING_ENGINE_OPERATIONS
#define SSH_PM_MAX_PENDING_ENGINE_OPERATIONS \
  ((SSH_PM_MAX_QM_NEGOTIATIONS) < 25 ? 51 : \
   ((SSH_PM_MAX_QM_NEGOTIATIONS) * 2 + 1))
#endif /* not SSH_PM_MAX_PENDING_ENGINE_OPERATIONS */

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
/* Maximum number of hosts implementing the same application
   gateway. This should be greater than number of interfaces on the
   system. */
#ifndef SSH_PM_MAX_APPGW_HOSTS
#define SSH_PM_MAX_APPGW_HOSTS          32
#endif /* SSH_PM_MAX_APPGW_HOSTS */
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

/* Maximum number of remote access clients using IKE configuration
   mode.  The IKE configuration mode does not have an easy way to
   implement IP address lease.  Therefore, the remote access server
   must have its own bookkeeping for these remote access clients.
   Note that the system can simultaneously have other remote access
   clients using, for example, L2TP or DHCP over IPsec. */
#ifndef SSH_PM_MAX_CONFIG_MODE_CLIENTS
#define SSH_PM_MAX_CONFIG_MODE_CLIENTS  SSH_PM_MAX_TUNNELS
#endif /* SSH_PM_MAX_CONFIG_MODE_CLIENTS */

/* Maximun number of L2TP clients. */
#ifndef SSH_PM_MAX_L2TP_CLIENTS
#define SSH_PM_MAX_L2TP_CLIENTS         SSH_PM_MAX_TUNNELS
#endif /* SSH_PM_MAX_L2TP_CLIENTS */

/* Maximum number of concurrent L2TP tunnel requests. */
#ifndef SSH_PM_MAX_L2TP_TUNNEL_REQUESTS
#define SSH_PM_MAX_L2TP_TUNNEL_REQUESTS \
(SSH_PM_MAX_L2TP_CLIENTS > 5 ? 5 : SSH_PM_MAX_L2TP_CLIENTS)
#endif  /* SSH_PM_MAX_L2TP_TUNNEL_REQUESTS */

/* The maximum lifetime in seconds of an IPsec SA which has only a
   kilobyte lifetime. An IPsec SA which has only a kilobyte lifetime will
   be deleted after this number of seconds if the SA has not already been
   deleted. This ensures that SA's with kilobyte lifetimes are always deleted
   even if there is no traffic through such SA's. This parameter does not
   affect SA's that have a lifetime in seconds. */
#ifndef SSH_IPSEC_MAXIMUM_IPSEC_SA_LIFETIME_SEC
#define SSH_IPSEC_MAXIMUM_IPSEC_SA_LIFETIME_SEC  (24 * 60 * 60)
#endif /* SSH_IPSEC_MAXIMUM_IPSEC_SA_LIFETIME_SEC  */

/* Number of concurrent DNS queries */
#ifndef SSH_PM_MAX_DNS_QUERIES
# define SSH_PM_MAX_DNS_QUERIES         10
#endif /* SSH_PM_MAX_DNS_QUERIES */

/* Maximum number of simultaneous TCP/IP connections (or other sessions)
   through the firewall. */
#ifndef SSH_ENGINE_MAX_SESSIONS
#define SSH_ENGINE_MAX_SESSIONS         1000
#endif /* SSH_ENGINE_MAX_SESSIONS */

/* Maximum number of simultaneous tunnels.  A tunnel consists of
   up to four IPSEC SAs (AH in, ESP in, AH out, ESP out) plus incoming
   and outgoing IPCOMP transform, plus possibly NAT Traversal and L2TP
   encapsulations. */
#ifndef SSH_ENGINE_MAX_TUNNELS
#define SSH_ENGINE_MAX_TUNNELS          (SSH_PM_MAX_TUNNELS * 2)
#endif /* SSH_ENGINE_MAX_TUNNELS */

/* Maximum level of tunnel nesting. */
#ifndef SSH_ENGINE_MAX_TUNNEL_NESTING
#define SSH_ENGINE_MAX_TUNNEL_NESTING   3
#endif /* SSH_ENGINE_MAX_TUNNEL_NESTING */

#ifndef SSH_ENGINE_MAX_APPGW_OPEN_PORTS
/* Maximum number of ports that can be dynamically opened by application
   gateways by calling ssh_appgw_open_port. */
#define SSH_ENGINE_MAX_APPGW_OPEN_PORTS 0
#endif /* SSH_ENGINE_MAX_APPGW_OPEN_PORTS */

/* Maximum number of policy rules (firewall rules and VPN rules) in
   the engine.  This value is the number of rules on the engine level.
   This number tries to be a conservative maximum.  In real devices it
   may be desirable to tune this number down somewhat, based on actual
   instrumentation using real policies generated by the system. */
#ifndef SSH_ENGINE_MAX_RULES
#define SSH_ENGINE_MAX_RULES            \
  (SSH_ENGINE_MAX_TUNNELS + SSH_PM_MAX_RULES * 2 + \
   SSH_ENGINE_MAX_APPGW_OPEN_PORTS + 26)
#endif /* SSH_ENGINE_MAX_RULES */

/* Maximum number of policy rules which have a range as their
   destination ip number in the engine.  The upper limit is not
   strict, but used to scale other constants according to the expected
   needs. */
#ifndef SSH_ENGINE_MAX_DST_IP_RANGE_RULES
#define SSH_ENGINE_MAX_DST_IP_RANGE_RULES(max_rules) \
  (((max_rules) < 500)   ? (max_rules) :      \
   ((max_rules) < 5000)  ? 1000 :             \
   ((max_rules) < 50000) ? 10000 :            \
   25000)
#endif

/* Maximum number of packet context objects that can exist simultaneously.
   This also specifies the maximum number of packets that can be being
   processed simultaneously.  Packets that are waiting for ARP completion
   or reassembly are counted here, as are packets that are being processed
   by hardware-accelerated transforms, or are being executed by a kernel
   thread in the engine.  Packets that have been triggered to the policy
   manager are not counted here. */
#ifndef SSH_ENGINE_MAX_PACKET_CONTEXTS
#ifdef SSH_IPSEC_HWACCEL_CONFIGURED
#define SSH_ENGINE_MAX_PACKET_CONTEXTS  500
#else /* SSH_IPSEC_HWACCEL_CONFIGURED */
#define SSH_ENGINE_MAX_PACKET_CONTEXTS  100
#endif /* SSH_IPSEC_HWACCEL_CONFIGURED */
#endif /* SSH_ENGINE_MAX_PACKET_CONTEXTS */

/* The number of times per second for which the policymanager will
   request the engine to send its pending audit events. This number
   may be dynamically decreased if the system is under attack.

   If the value zero is given, then the engine will request policy
   manager to poll audit events when they are available. This avoids
   running a high granularity timer at the system. */
#ifndef SSH_PM_AUDIT_REQUESTS_PER_SECOND
# define SSH_PM_AUDIT_REQUESTS_PER_SECOND 10
#endif /* SSH_PM_AUDIT_REQUESTS_PER_SECOND */

/* Maximum number of pending audit events. Audit events that are
   generated in the engine are queued until the policymanager requests
   the engine to send it some audit events. If the number of pending audit
   events becomes greater than this value, then some audit events
   will be dropped. In normal situations, the policymanager will request
   the engine to send it SSH_PM_AUDIT_REQUESTS_PER_SECONDS audit events
   per second, so this allows for
   (SSH_PM_AUDIT_REQUESTS_PER_SECOND * SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS)
   audit events to be generated every second without loss.

   If SSH_PM_AUDIT_REQUESTS_PER_SECOND equals to zero, then the engine
   will request audit message poll when
   SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS / 2 messages are queued or the
   oldest event age is one second. */

#ifndef SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS
#define SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS 50
#endif /* SSH_ENGINE_MAX_AUDIT_EVENTS */

/* Enable the flow create rate limiting feature in the engine.
   If flow create rate limiting is not used, the values below
   which impact flow create limitation are meaningless. They
   are left here to keep the pm->engine API independent
   of this setting. */
#ifndef SSH_ENGINE_FLOW_RATE_LIMIT
#define SSH_ENGINE_FLOW_RATE_LIMIT
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

/* The maximum amount of flow creates a single slot in the flow rate
   limitation table is allowed to own without it ever being considered
   for rate limitation. */
#ifndef SSH_ENGINE_FLOW_RATE_ALLOW_THRESHOLD
#define SSH_ENGINE_FLOW_RATE_ALLOW_THRESHOLD 5
#endif /* SSH_ENGINE_FLOW_ALLOW_THRESHOLD */

/* The maximum amount of flow creates a second allowed from a slot
   in the limitation table. Any more than this and the flow
   creates will always be rate limited. */
#ifndef SSH_ENGINE_FLOW_RATE_MAX_THRESHOLD
#define SSH_ENGINE_FLOW_RATE_MAX_THRESHOLD 50
#endif /* SSH_ENGINE_FLOW_RATE_DENY_THRESHOLD */

/* Rate limitation in percentages. If more than this
   threshold of max flows are in use, then the rate limitation
   below will be used. */
#ifndef SSH_ENGINE_FLOW_RATE_LIMIT_THRESHOLD
#define SSH_ENGINE_FLOW_RATE_LIMIT_THRESHOLD 50
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT_THRESHOLD */

/* The amount of flow creates over the total requested that
   is allowed from a single hash slot */
#ifndef SSH_ENGINE_FLOW_RATE_MAX_SHARE
#define SSH_ENGINE_FLOW_RATE_MAX_SHARE 30
#endif /* SSH_ENGINE_FLOW_RATE_MAX_SHARE */

/* Size of the hash table used here. */
#ifndef SSH_ENGINE_FLOW_RATE_HASH_SIZE
#define SSH_ENGINE_FLOW_RATE_HASH_SIZE 1009
#endif /* SSH_ENGINE_FLOW_RATE_HASH_SIZE */

/* The replay window size is given by the following parameter multiplied by
   32. The default value corresponds to a window size of 128. */
#ifndef SSH_ENGINE_REPLAY_WINDOW_WORDS
#define SSH_ENGINE_REPLAY_WINDOW_WORDS 4
#endif /* SSH_ENGINE_REPLAY_WINDOW_WORDS */

#if defined(SSH_IPSEC_UNIFIED_ADDRESS_SPACE) && defined(USERMODE_ENGINE)
/* This is the stack size we try to set when handling packets
   IF {set,get}rlimit() is available AND we are running a unified-usermode
   build. */
#define SSH_ENGINE_ASSUMED_KERNEL_STACK_SIZE 8192








#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

/* ********************************************************************
 * Values computed from the number of sessions and security associations.
 * These usually need not be touched, but can be tuned if desired.
 * ********************************************************************/

/* This determines the size of the flow id hash. The flow id hash
   is an open chaining hash table and this parameter affects
   the time it takes to find or remove a flow. This parameter
   should be a prime (or a product of a few large primes). */

#ifndef SSH_ENGINE_FLOW_ID_HASH_SIZE
#define SSH_ENGINE_FLOW_ID_HASH_SIZE \
  (SSH_ENGINE_FLOW_TABLE_SIZE)
#endif /* SSH_ENGINE_FLOW_ID_HASH_SIZE */

/* This determines the size of the flow table.  If the flow table is
   full, no more flows can be created. */
#ifndef SSH_ENGINE_FLOW_TABLE_SIZE
#define SSH_ENGINE_FLOW_TABLE_SIZE \
  (SSH_ENGINE_MAX_SESSIONS + SSH_ENGINE_MAX_TUNNELS)
#endif /* SSH_ENGINE_FLOW_TABLE_SIZE */

/* Size of the next hop hash.  This determines the maximum number of hosts
   or gateways that we can talk to directly.  Any hosts behind a router
   do not count; this is the maximum number of hosts (or routers) on
   a directly connected switched network. */
#ifndef SSH_ENGINE_NEXT_HOP_HASH_SIZE
#define SSH_ENGINE_NEXT_HOP_HASH_SIZE            \
  ((SSH_ENGINE_MAX_SESSIONS <= 10) ? 5 :         \
   (SSH_ENGINE_MAX_SESSIONS <= 100) ? 100 :      \
   (SSH_ENGINE_MAX_SESSIONS <= 1000) ? 500 :     \
   (SSH_ENGINE_MAX_SESSIONS <= 10000) ? 2000 :   \
   10000)
#endif /* SSH_ENGINE_NEXT_HOP_HASH_SIZE */

/* Size of the transform table.  Each transform corresponds to a bidirectional
   tunnel, including at largest AH in, ESP in, IPCOMP in, AH out, ESP out,
   IPCOMP out, NAT-T and L2TP transformations simultanously. */
#ifndef SSH_ENGINE_TRANSFORM_TABLE_SIZE
#define SSH_ENGINE_TRANSFORM_TABLE_SIZE SSH_ENGINE_MAX_TUNNELS
#endif /* SSH_ENGINE_TRANSFORM_TABLE_SIZE */

/* Number of cached transform encryption contexts to keep available.
   NOTE. If you are using transform level hardware acceleration (so
   called combined hwaccel), two transform contexts are needed for
   each IPsec tunnel, therefore the value here should be equal or
   greater than two times the SSH_ENGINE_MAX_TUNNELS parameter */
#ifndef SSH_ENGINE_MAX_TRANSFORM_CONTEXTS
#ifdef SSH_IPSEC_HWACCEL_USE_COMBINED_TRANSFORM
#define SSH_ENGINE_MAX_TRANSFORM_CONTEXTS  (2 * SSH_ENGINE_MAX_TUNNELS)
#else /* SSH_IPSEC_HWACCEL_USE_COMBINED_TRANSFORM */
#define SSH_ENGINE_MAX_TRANSFORM_CONTEXTS       \
  ((SSH_ENGINE_MAX_TUNNELS < 10) ? 4 :          \
   (SSH_ENGINE_MAX_TUNNELS < 100) ? 20 :        \
   (SSH_ENGINE_MAX_TUNNELS < 10000) ? 100 :     \
   1000)
#endif /* SSH_IPSEC_HWACCEL_USE_COMBINED_TRANSFORM */
#endif /* SSH_ENGINE_MAX_TRANSFORM_CONTEXTS */

#ifndef SSH_IPSEC_SMALL
/* Size of the separate chaining hash table which is used to hash
   rules which have point destination ip address.  Best be a power of
   two. */
#ifndef SSH_ENGINE_POINT_DST_IP_HASH_SIZE
#define SSH_ENGINE_POINT_DST_IP_HASH_SIZE       \
  ((SSH_ENGINE_MAX_RULES <= 20) ? 8 :           \
   (SSH_ENGINE_MAX_RULES <= 40) ? 16 :          \
   (SSH_ENGINE_MAX_RULES <= 80) ? 32 :          \
   (SSH_ENGINE_MAX_RULES <= 150) ? 64 :         \
   (SSH_ENGINE_MAX_RULES <= 300) ? 128 :        \
   (SSH_ENGINE_MAX_RULES <= 550) ? 256 :        \
   (SSH_ENGINE_MAX_RULES <= 1000) ? 512 :       \
   (SSH_ENGINE_MAX_RULES <= 1900) ? 1024 :      \
   (SSH_ENGINE_MAX_RULES <= 3500) ? 2048 :      \
   (SSH_ENGINE_MAX_RULES <= 7000) ? 4096 :      \
   (SSH_ENGINE_MAX_RULES <= 13000) ? 8192 :     \
   (SSH_ENGINE_MAX_RULES <= 25000) ? 16384 :    \
   (SSH_ENGINE_MAX_RULES <= 50000) ? 32768 :    \
   (SSH_ENGINE_MAX_RULES <= 100000) ? 65536 :   \
   (SSH_ENGINE_MAX_RULES <= 200000) ? 131072 :  \
   (SSH_ENGINE_MAX_RULES <= 400000) ? 262144 :  \
   (SSH_ENGINE_MAX_RULES <= 800000) ? 524288 :  \
   1048576)
#endif /* SSH_ENGINE_POINT_DST_IP_HASH_SIZE */

/* Size of the memory pool from which the decision trees allocates
   memory for references to rules which have a range in their
   destination ip addresses.  Should this value be too small, but
   nevertheless larger than the number of rules expected , the
   decision trees can still be built, but they will be slower,
   gradually degrading to a linear search.  Also, the more the rules
   overlap in destination and source ip and port numbers, the larger
   the rule vector pool should be compared to the number of rules.
   The current value is relatively pessimistic -- after
   experimentation it could be reduced, but please do keep it above
   SSH_ENGINE_MAX_RULES in order to ensure that rule insertion never
   fails even if all rules are dst ip range rules.

   Note that if the value of this define is large, then the define
   SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL may need to be set. */
#ifndef SSH_ENGINE_RULE_VECTOR_POOL_SIZE
#define SSH_ENGINE_RULE_VECTOR_POOL_SIZE(max_rules, max_range_rules) \
  ((max_rules) + (15 * (max_range_rules)))
#endif /* SSH_ENGINE_RULE_VECTOR_POOL_SIZE */

/* Size of a cache which is used to improve sharing in the rule vector
   pool. */
#ifndef SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE
#define SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE(max_range_rules) \
  (((max_range_rules) <= 20) ? 4 :              \
   ((max_range_rules) <= 80) ? 8 :              \
   ((max_range_rules) <= 300) ? 16 :            \
   ((max_range_rules) <= 1000) ? 32 :           \
   ((max_range_rules) <= 3500) ? 64 :           \
   ((max_range_rules) <= 13000) ? 128 :         \
   ((max_range_rules) <= 50000) ? 256 :         \
   ((max_range_rules) <= 200000) ? 512 :        \
   ((max_range_rules) <= 800000) ? 1024 :       \
   2048)
#endif /* SSH_ENGINE_RULE_VECTOR_POOL_CACHE_SIZE */

/* Size of the memory pool from which we allocate decision tree nodes.
   As for SSH_ENGINE_RULE_VECTOR_POOL_SIZE, should this value be too
   low, the decision tree reduces to a linear search.  This value,
   too, is a conservative estimate -- most probably it could be
   reduced to half, but not much more.  It should always be at least
   one. This is function of size of vector_pool.

   Note that if the value of this define is large, then the define
   SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL may need to be set. */
#ifndef SSH_ENGINE_RULE_NODE_POOL_SIZE
#define SSH_ENGINE_RULE_NODE_POOL_SIZE(max_rules, max_range_rules) \
  (1 + (((max_rules) / 15) + (max_range_rules)))
#endif  /* SSH_ENGINE_RULE_NODE_POOL_SIZE */

/* Preallocate the rule lookup node pool. This may need to be set if
   SSH_IPSEC_PREALLOCATE_TABLES is not defined but the number of engine
   policy rules is large. If SSH_IPSEC_PREALLOCATE_TABLES is defined
   then the rule lookup node pool is always preallocated. */
#ifndef SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL
/* #define SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL 1 */
#endif /* SSH_ENGINE_RULE_PREALLOCATE_NODE_POOL */

/* Preallocate the rule lookup node pool. This may need to be set if
   SSH_IPSEC_PREALLOCATE_TABLES is not defined but the number of engine
   policy rules is large. If SSH_IPSEC_PREALLOCATE_TABLES is defined
   then the rule lookup rule pool is always preallocated. */
#ifndef SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL
/* #define SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL 1 */
#endif /* SSH_ENGINE_RULE_PREALLOCATE_RULE_POOL */

#endif /* !SSH_IPSEC_SMALL */

/* Size of the ARP cache (i.e., maximum number of hosts/routers for
   which we have cached the media address).  This is no hard limit,
   and only affects performance.  Typically the ARP cache is only used
   when a new flow is created (and when routing information or media
   addresses change or expire and need to be revalidated). */
#ifndef SSH_ENGINE_ARP_CACHE_SIZE
#define SSH_ENGINE_ARP_CACHE_SIZE \
  ((SSH_ENGINE_NEXT_HOP_HASH_SIZE < 500) ? SSH_ENGINE_NEXT_HOP_HASH_SIZE : 500)
#endif /* SSH_ENGINE_ARP_CACHE_SIZE */

/* Size of the peer hash table. */
#ifndef SSH_ENGINE_PEER_HASH_SIZE
#define SSH_ENGINE_PEER_HASH_SIZE (SSH_ENGINE_TRANSFORM_TABLE_SIZE / 32 + 2)
#endif /* SSH_ENGINE_PEER_HASH_SIZE */

/* Size of the engine peer handle hash table. */
#ifndef SSH_ENGINE_PEER_HANDLE_HASH_SIZE
#define SSH_ENGINE_PEER_HANDLE_HASH_SIZE \
  (SSH_ENGINE_TRANSFORM_TABLE_SIZE / 32 + 2)
#endif /* SSH_ENGINE_PEER_HANDLE_HASH_SIZE */

/* The maximum value of manually keyed SPIs. The engine reserves the
   SPI range from 256 to SSH_ENGINE_INBOUND_SPI_MAX_MANUAL for
   manually keyed SAs. It is guaranteed that the IKE negotiated SPIs
   never overlap manually keyed SPIs in this range. The SPIs of
   manually keyed SAs should never exceed this value, especially if
   there could be significant amounts (more than a few) of manually
   keyed SAs installed in the system. */
#ifndef SSH_ENGINE_INBOUND_SPI_MAX_MANUAL
#define SSH_ENGINE_INBOUND_SPI_MAX_MANUAL 4096
#endif /* SSH_ENGINE_INBOUND_SPI_MAX_MANUAL */

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL

/* Size of the peer ID in the transform data structure. */
#ifndef SSH_ENGINE_PEER_ID_SIZE
#define SSH_ENGINE_PEER_ID_SIZE 8
#endif /* SSH_ENGINE_PEER_ID_SIZE */
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSH_IPSEC_INTERNAL_ROUTING
/* Size of the engine routing table.  Note that the engine routing mechanism
   is currently not designed to handle very large number of routes. */
#ifndef SSH_ENGINE_ROUTE_TABLE_SIZE
#define SSH_ENGINE_ROUTE_TABLE_SIZE     20
#endif /* SSH_ENGINE_ROUTE_TABLE_SIZE */
#endif /* SSH_IPSEC_INTERNAL_ROUTING */

/* Number of fragmented packets that may be being processed
   simultaneously.  This includes both packets that are processed a
   fragment at a time and packets that are reassembled before
   processing. */
#define SSH_ENGINE_FRAGMENT_TABLE_SIZE  \
  ((SSH_ENGINE_MAX_SESSIONS < 1000) ? 32 : \
   (SSH_ENGINE_MAX_SESSIONS < 10000) ? 256 : \
   (SSH_ENGINE_MAX_SESSIONS < 100000) ? 1024 : \
   4096)

/* Size of the hash table into fragment magic / reassembly entries. */
#define SSH_ENGINE_FRAGMENT_HASH_SIZE SSH_ENGINE_FRAGMENT_TABLE_SIZE

/* Maximum total number of interceptor packets that may be held in reassembly
   queues. */
#define SSH_ENGINE_FRAGMENT_MAX_PACKETS \
  (5 * SSH_ENGINE_MAX_SESSIONS + 100)

/* Maximum total number of bytes in the packets that may be held in reassembly
   queues. */
#define SSH_ENGINE_FRAGMENT_MAX_BYTES \
  ((SSH_ENGINE_MAX_SESSIONS < 1000) ? (70*1024) : \
   (SSH_ENGINE_MAX_SESSIONS < 10000) ? (256*1024) : \
   (SSH_ENGINE_MAX_SESSIONS < 100000) ? (2048*1024) : \
   (8192 * 1024))

/* Maximum number of fragments that we will hold per packet.  If there are
   more than this, we'll throw the packet away. Assuming an MTU
   of 576 bytes and an IP packet of 65335 bytes, then this results
   in approximately 120 fragments per packet.
   The default value is tuned towards more common cases occurring
   in practice. */
#ifndef SSH_ENGINE_MAX_FRAGS_PER_PACKET
# define SSH_ENGINE_MAX_FRAGS_PER_PACKET 70
#endif /* SSH_ENGINE_MAX_FRAGS_PER_PACKET */

/* Maximum time between the first and last fragment of a packet.

   "Requirements for Internet Hosts -- Communication Layers" [RFC 1122]
   specifies a value between 60-120 seconds for the reassembly
   timeout of hosts. This timeout must be greater than the reassembly
   timeout of hosts plus the latency involved in getting a packet
   to the host fragment reassembly.

   This is an obvious problem as the speed of data communication has
   increased since RFC 1122, but the fragment id is still 16 bits. If
   PMTU is not used and data is transferred in approximately 4k packet,
   then the fragment id's will wrap around even if less than 30 Mbps
   bandwith is available.

   On several platforms one can not even assume that the full 2^16 cycle
   (or even most of it) is available (e.g. the fragment id's cycle
   independetly of src/dst IP's. */
#define SSH_ENGINE_FRAGMENT_TIMEOUT 35

/* Should support for a PRNG in the quicksec engine be compiled in? */
#ifdef SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER
#define SSH_ENGINE_PRNG
#endif /* SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER */

/* ********************************************************************
 * The following parameters can also be tuned; however, these would
 * usually not be tuned on a per-system basis, and some represent
 * tradeoffs in security policy etc.
 * ********************************************************************/

/* The flags passed to the engine when loading the interceptor. See
   src/interceptor/include/engine.h for the defined flags. The
   default setting causes default rule matches to result in
   a "drop packet" in quicksec. */
#ifndef SSH_IPSEC_ENGINE_FLAGS
#define SSH_IPSEC_ENGINE_FLAGS (SSH_ENGINE_DROP_IF_NO_IPM)
#endif /* !SSH_IPSEC_ENGINE_FLAGS */






/* Minimum size of the first fragment. Note that RFC791 says the
   minimum size is 68 bytes, but all practical links support bigger
   fragments and 68-byte fragments open denial of service
   possibilities.  This is used in sanity checks of packets and
   in validating sanity of MTU values. */
#define SSH_ENGINE_MIN_FIRST_FRAGMENT_V4 160

/* Minimum fragment size for V4 (this is payload size, not including
   IP header) for non-first and non-last fragments.  This must be less
   than or equal to SSH_ENGINE_MIN_FIRST_FRAGMENT_V4. This is used
   in sanity checks of packets. */
#define SSH_ENGINE_MIN_FRAGMENT_V4      8

/* Minimum fragment size for IPv6 (RFC2460, section 5).  This is the minimum
   first fragment size. The assumption is that any fragmenters along
   the path try to keep the first fragment size sane. This is currently
   only used for validating MTU sanity. */
#define SSH_ENGINE_MIN_FIRST_FRAGMENT_V6 8

/* The minimum packet size that is required for the Don't Fragment (DF)
   bit to be heeded. Packets below this size will be fragmented
   if necessary even if the DF bit is set. */
#ifndef SSH_ENGINE_MIN_DF_LENGTH
#define SSH_ENGINE_MIN_DF_LENGTH 576
#endif /* SSH_ENGINE_MIN_DF_LENGTH */

/* Default idle timeout for a flow.  Normally flows will timeout after this
   many seconds if there is no traffic.  This can be overriden in
   protocol-specific code. */
#define SSH_ENGINE_DEFAULT_IDLE_TIMEOUT 30

/* Default idle timeout for TCP flows.  Note that any keepalive messages
   are also counted as traffic, and will keep the flow alive. */
#define SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT     (8 * 3600)

/* Timeout for invalidating old SPI value after IPsec SA rekey.
   The Engine generates the SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED
   event roughly this many seconds after the rekey. */
#define SSH_ENGINE_IPSEC_REKEY_INVALIDATE_TIMEOUT 30

/* Timeout for disabling trigger events for a trigger flow after a failed
   IPsec SA negotiation or after a negotiation that resulted into traffic
   selectors that do not match the trigger flow. The trigger flow is put
   to drop mode and its hard expiry is set to this many seconds in future.
   Trigger events for this flow are re-enabled when the trigger flow
   expires. */
#define SSH_ENGINE_TRIGGER_FLOW_EXPIRE_TIMEOUT 30

/* How often a flow is visited in engine age timeout call, in other words
   how long it takes to traverse the whole flow table. This determines how
   accurate the timing of flow and transform events is and how long the
   minimum usable IPsec SA lifetime is. The default values for this setting
   expect that systems with large flow tables are capable of processing
   engine events at higher rate. */
#define SSH_ENGINE_AGE_FULL_SECONDS \
  ((SSH_ENGINE_FLOW_TABLE_SIZE > 500000) ? 300 : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 300000) ? 240 : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 150000) ? 180 : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 75000)  ? 120 : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 37500)  ? 90  : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 18000)  ? 60  : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 10000)  ? 45  : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 5000)   ? 30  : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 2000)   ? 20  : \
   (SSH_ENGINE_FLOW_TABLE_SIZE > 1000)   ? 10  : \
                                           5)

/* The number of engine age timeout rounds a transform idle event is ignored
   after an idle event has been sent to the policy manager. The first idle
   event is sent when the 'transform_dpd_timeout' (in engine params) seconds
   have gone since the last packet has been received from the peer and we have
   sent packets toward the peer. After sending the event the next idle event is
   sent after SSH_ENGINE_AGE_IDLE_EVENT_IGNORE_COUNT age timeout rounds have
   gone by without any packet being received from the peer or without the
   transform being rekeyed. Valid range of values for this parameter is 0-7
   inclusive. */
#define SSH_ENGINE_AGE_IDLE_EVENT_IGNORE_COUNT  7

/* The maximum number of transform events per second the engine sends to the
   policy manager. This limits the rate of expired, rekey, rekey inbound
   invalidated and idle events. The destroyed events are not rate limited.
   When the rate limit hits, the engine age timeout returns before having
   processed the configured number of flows. This behaviour means that it may
   temporarily take longer than age full seconds to complete the flow table
   traverse. Setting this to 0 disables rate limiting. This setting has no
   effect if SSH_IPSEC_SMALL is defined. */
#define SSH_ENGINE_AGE_TRANSFORM_EVENT_RATE     0

/* Default UDP appgw trigger flow idle timeout. This is the time
   alloted for a UDP appgw instance to enter the connected state,
   before the triggering flow is destroyed.. */
#define SSH_ENGINE_DEFAULT_UDP_APPGW_TRIGGER_TIMEOUT 2

/* Maximum number of host system route lookups that may be active
   simultaneously.  Each such route lookup allocates a context object
   of about 30 bytes.  Very few lookups are normally in progress
   simultaneously (less than ten; route lookups are normally not
   performed per-packet but when a flow is created).  This limit
   provides a hard limit on the memory consumed by the context; if
   more than this many are active, the rest will silently fail. */
#define SSH_ENGINE_MAX_ACTIVE_ROUTE_LOOKUPS     20

#ifdef SSHDIST_IPSEC_NAT
/* Size of hash table for storing each <IP:PORT> pair associated with
   each flow if SSHDIST_IPSEC_NAT is enabled. */
#ifndef SSH_ENGINE_FLOW_NAT_HASH_SIZE
# define SSH_ENGINE_FLOW_NAT_HASH_SIZE   10000
#endif /* SSH_ENGINE_FLOW_NAT_HASH_SIZE */
#endif /* SSHDIST_IPSEC_NAT */

/* The maximum amount of traffic selector items allowed in a traffic
   selector. The memory usage of high-level policy level rules
   (SshPmRuleStruct) is proportional to the square of this value,
   in bytes the memory usage per rule is
   8 * (SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS ^ 2). */
#ifndef SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS
#define SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS 5
#endif /* SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS */

#ifdef SSHDIST_IPSEC_IPCOMP
/* The minimum size of the packet for which IP Payload compression shall
   be attempted. Packets smaller than this size do not gain any appreciable
   compression against execution speed */
#ifndef SSH_ENGINE_IPCOMP_SIZE_THRESHOLD
#define SSH_ENGINE_IPCOMP_SIZE_THRESHOLD 100
#endif /* SSH_ENGINE_IPCOMP_SIZE_THRESHOLD */

/* Maximum number of available bufffers used in IPComp decompression
   operation. */
#ifndef SSH_ENGINE_IPCOMP_MAX_AVAILABLE_BUFFERS
#define SSH_ENGINE_IPCOMP_MAX_AVAILABLE_BUFFERS 15
#endif /* SSH_ENGINE_IPCOMP_MAX_AVAILABLE_BUFFERS */

#endif /* SSHDIST_IPSEC_IPCOMP */

/* ********************************************************************
 * The following parameters are not normally tuned.
 * ********************************************************************/

/* Port number at which IKE runs.  Note that some protocols, such as
   NAT Traversal, may depend on IKE running in the standard port. */
#ifndef SSH_IPSEC_IKE_PORT
#define SSH_IPSEC_IKE_PORT      500
#endif /* SSH_IPSEC_IKE_PORT */

/* Port number at which IKE runs in NAT traversal. */
#ifndef SSH_IPSEC_IKE_NATT_PORT
#define SSH_IPSEC_IKE_NATT_PORT 4500
#endif /* SSH_IPSEC_IKE_NATT_PORT */

/* Port number at which L2TP runs. */
#define SSH_IPSEC_L2TP_PORT     1701

/* Maximum length of the application gateway identifier in characters. */
#define SSH_APPGW_MAX_IDENT_LEN 32

/* Length of listen backlog queue for appgw initiator stream sockets. */
#define SSH_APPGW_INITIATOR_STREAM_BACKLOG 200

/* Default timeout after which application gateways are automatically
   closed.  This should typically be on the order of a few hours.  The timeout
   can be changed dynamically by the application gateway itself. */
#define SSH_APPGW_DEFAULT_TIMEOUT (8*3600)

/* The size of the hash table used to speed up association
   of flows to appgw instances. */
#define SSH_APPGW_FLOW_HASH_SIZE (SSH_ENGINE_FLOW_TABLE_SIZE/2)

/* The interval (in seconds) how often NAT-T keepalive packets are
   sent. If interval is zero, NAT-T keepalive is disabled. */
#define SSH_IPSEC_NATT_KEEPALIVE_INTERVAL 20

/* Minimum number of seconds before time-based hard expiration that we send a
   soft event for the incoming IPsec flow. The first soft event is sent when
   1/20 of the IPsec SA lifetime is left, unless it is limited by this and
   the following setteing. This setting also affects the minimum usable IPsec
   SA lifetime, which is twice the soft grace time, i.e. four times engine age
   full seconds, or at least 60 seconds. */
#define SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME \
  (SSH_ENGINE_AGE_FULL_SECONDS > 15 ? (2 * SSH_ENGINE_AGE_FULL_SECONDS) : 30)

/* Maximum number of seconds before time-based hard expiration that we send a
   soft event for the incoming IPsec flow. */
#define SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME_MAX 300

/* Number of kilobytes before kilobyte-based hard expiration that we
   send a soft event for the flow.  Once the soft event for
   kilobyte-based expiration is sent, the flow is given
   SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME seconds to rekey, with the
   limit on the bytes transferred disabled.  The RFCs do not really
   specify when to send soft events, and this behavior may provide
   more robust operation over a wide range of practically occurring
   link conditions and peers (link speeds from kilobits to gigabits
   per second, IKE rekey times from milliseconds to tens of seconds).
   We further modify this by requiring that the grace in kilobytes be
   at least 5% of the total lifetime.

   Default value for this is calculated with average rate of 1000MB per
   second for SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME seconds.

   One can not configure life-time smaller than twice this value. */

#define SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB \
  (SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME * 1000)

/* Enable Multicast feature. This will enable multicast traffic forwarding
   and esp tunnel with manual SA's for Multicast peers. For identifying the
   SA for esp packets between multicast peers,spi and destination multicast
   address will be used (as per rfc 4303). Rules should be added with
   destination multicast address for the packets we want to secure using
   tunnel. Routing information for Multicast packets is picked from system
   routing table. */
/* #define SSH_IPSEC_MULTICAST */
#if defined(VXWORKS) || defined(WINDOWS)
#undef SSH_IPSEC_MULTICAST
#endif /* VXWORKS or WINDOWS */

/* By enabling this define, the engine pad's the packet into the minimum
   size of ethernet frame. The padding is added as zeroes to the end of
   the packet. */
/* #define SSH_ENGINE_PAD_ETHERNET_FRAME */
#if defined(__linux__) || defined(WINDOWS)
#undef SSH_ENGINE_PAD_ETHERNET_FRAME
#endif /* __linux__ or WINDOWS */

/* Enable multiple authentications feature. This will enable initiator
   to perform a second authentication round during IKEv2 negotiation
   and responder to require it. First authentication method is not limited,
   but only EAP is supported as the second method. */

#ifdef SSHDIST_IKE_EAP_AUTH
#define SSH_IKEV2_MULTIPLE_AUTH
#endif /* SSHDIST_IKE_EAP_AUTH */

/* Set the maximum number of proposal per SA. This affect also
   IKEv1. Some implementations send many proposals for example for IKE
   SA. Only SSH_IKEV2_SA_MAX_PROPOSALS proposals are decoded and taken
   into account in the negotiation the rest are ignored. Value affects
   also size of SshIkev2PayloadSA structure.
 */
#ifndef SSH_IKEV2_SA_MAX_PROPOSALS
#define SSH_IKEV2_SA_MAX_PROPOSALS   20
#endif /* SSH_IKEV2_SA_MAX_PROPOSALS */

/* When when combined mode (authenticating) ciphers are used together
   with normal node (non-authenticating) ciphers. Two proposals, one
   for each mode, are formed to the SA payloads.

   The order of the proposals in the SA payloads defines the
   preference of the proposals. Setting SSH_PM_COMBINED_MODE_FIRST to
   TRUE causes the proposal containing combined mode ciphers to be
   placed first in the SA payload. Setting it to FALSE places it
   second.
 */
#ifndef SSH_PM_COMBINED_MODE_FIRST
#define SSH_PM_COMBINED_MODE_FIRST FALSE
#endif /* SSH_PM_COMBINED_MODE_FIRST */

#endif /* IPSEC_PARAMS_H */
