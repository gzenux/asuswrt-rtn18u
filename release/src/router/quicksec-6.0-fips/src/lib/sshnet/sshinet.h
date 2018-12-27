/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP protocol specific definitions.  This file also contains functions
   and macros for manipulating IP addresses in various forms, as well
   as for manipulating IP, TCP, and UDP headers.  This file also
   contains definitions specific to various media types (e.g. ethernet).

   The system can be configured to support IPv4 addresses only.
   In this configuration system will recongnize IPv6 address
   strings, but it can not parse them into addresses. Accessing
   address using IPv6 accessors will fail.
*/

#ifndef SSHINET_H
#define SSHINET_H

#include "sshgetput.h"
#include "sshenum.h"
#include "sshether.h"

/* Special IP address string that can be given for TCP and UDP
   listeners to bind to all local IP addresses.  This will bind both
   to IPv4 and IPv6 addresses, if supported by the system. */
#define SSH_IPADDR_ANY ssh_ipaddr_any

/* Special IP address strings that can be given for TCP and UDP
   listeners to bind only to local IP addresses of requested type. */
#define SSH_IPADDR_ANY_IPV4 ssh_ipaddr_any_ipv4
#define SSH_IPADDR_ANY_IPV6 ssh_ipaddr_any_ipv6

/* Constant placeholder for the SSH_IPADDR_ANY address string. */
#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const char *const ssh_ipaddr_any;
extern const char *const ssh_ipaddr_any_ipv4;
extern const char *const ssh_ipaddr_any_ipv6;

/* Predicate to check whether the address string `addr' is an
   SSH_IPADDR_ANY. */
#define SSH_IS_IPADDR_ANY(addr) \
  ((addr)                       \
   && ((addr) == ssh_custr(SSH_IPADDR_ANY) \
       || ssh_usstrcmp(addr, SSH_IPADDR_ANY) == 0))

/* Predicates to check whether the address string `addr' is an
   SSH_IPADDR_ANY_IPV4 or SSH_IPADDR_ANY_IPV6. */
#define SSH_IS_IPADDR_ANY_IPV4(addr) \
  ((addr)                       \
   && ((addr) == SSH_IPADDR_ANY_IPV4 \
       || strcmp((addr), SSH_IPADDR_ANY_IPV4) == 0))
#define SSH_IS_IPADDR_ANY_IPV6(addr) \
  ((addr)                       \
   && ((addr) == SSH_IPADDR_ANY_IPV6 \
       || strcmp((addr), SSH_IPADDR_ANY_IPV6) == 0))

/* IP protocol names to keywords definitions */
#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const SshKeywordStruct ssh_ip_protocol_id_keywords[];

/* IP protocol identifiers */
typedef enum {
  SSH_IPPROTO_HOPOPT = 0,    /* IPv6 HOP by HOP option [RFC1833] */
  SSH_IPPROTO_ICMP = 1,      /* Internet Control Message [RFC792] */
  SSH_IPPROTO_IGMP = 2,      /* Internet Group Mgmt [RFC1112] */
  SSH_IPPROTO_GGP = 3,       /* Gateway-to-Gateway [RFC823] */
  SSH_IPPROTO_IPIP = 4,      /* IP in IP [RFC2003] */
  SSH_IPPROTO_ST = 5,        /* Stream [RFC1190] */
  SSH_IPPROTO_TCP = 6,       /* Transmission Control [RFC793] */
  SSH_IPPROTO_CBT = 7,       /* CBT [Ballardie] */
  SSH_IPPROTO_EGP = 8,       /* Exterior GW Protocol [RFC888] */
  SSH_IPPROTO_IGP = 9,       /* any private interior GW [IANA] */
  SSH_IPPROTO_BBN = 10,      /* BBN RCC Monitoring [SGC] */
  SSH_IPPROTO_NVP = 11,      /* Network Voice Protocol [RFC741] */
  SSH_IPPROTO_PUP = 12,      /* PUP [PUP XEROX] */
  SSH_IPPROTO_ARGUS = 13,    /* ARGUS [RWS4] */
  SSH_IPPROTO_EMCON = 14,    /* EMCON [BN7] */
  SSH_IPPROTO_XNET = 15,     /* Cross Net Debugger [IEN158] */
  SSH_IPPROTO_CHAOS = 16,    /* Chaos [NC3] */
  SSH_IPPROTO_UDP = 17,      /* User Datagram [RFC768 JBP] */
  SSH_IPPROTO_MUX = 18,      /* Multiplexing [IEN90 JBP] */
  SSH_IPPROTO_DCN = 19,      /* DCN Measurement Subsystems [DLM1] */
  SSH_IPPROTO_HMP = 20,      /* Host Monitoring [RFC869 RH6] */
  SSH_IPPROTO_PRM = 21,      /* Packet Radio Measurement [ZSU] */
  SSH_IPPROTO_XNS = 22,      /* XEROX NS IDP [ETHERNET XEROX] */
  SSH_IPPROTO_TRUNK1 = 23,   /* Trunk-1 [BWB6] */
  SSH_IPPROTO_TRUNK2 = 24,   /* Trunk-2 [BWB6] */
  SSH_IPPROTO_LEAF1 = 25,    /* Leaf-1 [BWB6] */
  SSH_IPPROTO_LEAF2 = 26,    /* Leaf-2 [BWB6] */
  SSH_IPPROTO_RDP = 27,      /* Reliable Data Protocol [RFC908] */
  SSH_IPPROTO_IRTP = 28,     /* Reliable Transaction  [RFC938] */
  SSH_IPPROTO_ISOTP4 = 29,   /* ISO Transport [RFC905 RC77] */
  SSH_IPPROTO_NETBLT = 30,   /* Bulk Data Transfer [RFC969] */
  SSH_IPPROTO_MFE = 31,      /* MFE Network Services [MFENET] */
  SSH_IPPROTO_MERIT = 32,    /* MERIT Internodal Protocol [HWB] */
  SSH_IPPROTO_SEP = 33,      /* Sequential Exchange [JC120] */
  SSH_IPPROTO_3PC = 34,      /* Third Party Connect [SAF3] */
  SSH_IPPROTO_IDPR = 35,     /* InterDomain Policy Routing [MXS1] */
  SSH_IPPROTO_XTP = 36,      /* XTP [GXC] */
  SSH_IPPROTO_DDP = 37,      /* Datagram Delivery [WXC] */
  SSH_IPPROTO_IDPRC = 38,    /* IDPR Control Msg Transport [MXS1] */
  SSH_IPPROTO_TP = 39,       /* TP++ Transport [DXF] */
  SSH_IPPROTO_IL = 40,       /* IL Transport [Presotto] */
  SSH_IPPROTO_IPV6 = 41,     /* Ipv6 [Deering] */
  SSH_IPPROTO_SDRP = 42,     /* Source Demand Routing  [DXE1] */
  SSH_IPPROTO_IPV6ROUTE = 43,/* Routing Hdr for IPv6 [Deering] */
  SSH_IPPROTO_IPV6FRAG = 44, /* Fragment Hdr for IPv6 [Deering] */
  SSH_IPPROTO_IDRP = 45,     /* Inter-Domain Routing [Sue Hares] */
  SSH_IPPROTO_RSVP = 46,     /* Reservation Protocol [Bob Braden] */
  SSH_IPPROTO_GRE = 47,      /* General Routing Encapsulation */
  SSH_IPPROTO_MHRP = 48,     /* Mobile Host Routing */
  SSH_IPPROTO_BNA = 49,      /* BNA [Gary Salamon] */
  SSH_IPPROTO_ESP = 50,      /* Encap Security Payload [RFC2406] */
  SSH_IPPROTO_AH = 51,       /* Authentication Header [RFC2402] */
  SSH_IPPROTO_INLSP = 52,    /* Integrated Net Layer Sec TUBA */
  SSH_IPPROTO_SWIPE = 53,    /* IP with Encryption [JI6] */
  SSH_IPPROTO_NARP = 54,     /* NBMA Address Resolution [RFC1735] */
  SSH_IPPROTO_MOBILE = 55,   /* IP Mobility [Perkins] */
  SSH_IPPROTO_TLSP = 56,     /* TLS with Kryptonet KM [Oberg] */
  SSH_IPPROTO_SKIP = 57,     /* SKIP [Markson] */
  SSH_IPPROTO_IPV6ICMP = 58, /* ICMP for IPv6 [RFC1883] */
  SSH_IPPROTO_IPV6NONXT = 59,/* No Next Header for IPv6 [RFC1883] */
  SSH_IPPROTO_IPV6OPTS = 60, /* Opts IPv6 host internal [RFC1883] */
  SSH_IPPROTO_CFTP = 62,     /* CFTP [CFTP,H CF2] */
  SSH_IPPROTO_LOCAL = 63,    /* local network [IANA] */
  SSH_IPPROTO_SAT = 64,      /* SATNET and Backroom EXPAK [SHB] */
  SSH_IPPROTO_KRYPTOLAN = 65,/* Kryptolan [PXL1] */
  SSH_IPPROTO_RVD = 66,      /* MIT Remote Virtual Disk [MBG] */
  SSH_IPPROTO_IPPC = 67,     /* Internet Pluribus Packet Core */
  SSH_IPPROTO_DISTFS = 68,   /* Any distributed FS [IANA] */
  SSH_IPPROTO_SATMON = 69,   /* SATNET Monitoring [SHB] */
  SSH_IPPROTO_VISA = 70,     /* VISA Protocol [GXT1] */
  SSH_IPPROTO_IPCV = 71,     /* Internet Packet Core Utility */
  SSH_IPPROTO_CPNX = 72,     /* Computer Network Executive */
  SSH_IPPROTO_CPHB = 73,     /* Computer Heart Beat */
  SSH_IPPROTO_WSN = 74,      /* Wang Span Network [VXD] */
  SSH_IPPROTO_PVP = 75,      /* Packet Video Protocol [SC3] */
  SSH_IPPROTO_BRSATMON = 76, /* Backroom SATNET Monitoring [SHB] */
  SSH_IPPROTO_SUNND = 77,    /* SUN ND PROTOCOL-Temporary [WM3] */
  SSH_IPPROTO_WBMON = 78,    /* WIDEBAND Monitoring [SHB] */
  SSH_IPPROTO_WBEXPAK = 79,  /* WIDEBAND EXPAK [SHB] */
  SSH_IPPROTO_ISOIP = 80,    /* ISO Internet Protocol [MTR] */
  SSH_IPPROTO_VMTP = 81,     /* VMTP [DRC3] */
  SSH_IPPROTO_SECUREVMTP = 82, /* SECURE-VMTP [DRC3] */
  SSH_IPPROTO_VINES = 83,    /* VINES [BXH] */
  SSH_IPPROTO_TTP = 84,      /* TTP [JXS] */
  SSH_IPPROTO_NSFNET = 85,   /* NSFNET-IGP [HWB] */
  SSH_IPPROTO_DGP = 86,      /* Dissimilar Gateway [DGP] */
  SSH_IPPROTO_TCF = 87,      /* TCF [GAL5] */
  SSH_IPPROTO_EIGRP = 88,    /* EIGRP [CISCO GXS] */
  SSH_IPPROTO_OSPFIGP = 89,  /* OSPFIGP [RFC1583 JTM4] */
  SSH_IPPROTO_SPRITE = 90,   /* Sprite RPC [SPRITE BXW] */
  SSH_IPPROTO_LARP = 91,     /* Locus Address Resolution [BXH] */
  SSH_IPPROTO_MTP = 92,      /* Multicast Transport [SXA] */
  SSH_IPPROTO_AX25 = 93,     /* AX.25 Frames [BK29] */
  SSH_IPPROTO_IPWIP = 94,    /* IP-within-IP Encapsulation [JI6] */
  SSH_IPPROTO_MICP = 95,     /* Mobile Internetworking Ctrl [JI6] */
  SSH_IPPROTO_SCC = 96,      /* Semaphore Communications [HXH] */
  SSH_IPPROTO_ETHERIP = 97,  /* Ethernet-within-IP Encapsulation */
  SSH_IPPROTO_ENCAP = 98,    /* Encapsulation Header [RFC1241] */
  SSH_IPPROTO_ENCRYPT = 99,  /* Any private encryption [IANA] */
  SSH_IPPROTO_GMTP = 100,    /* GMTP [RXB5] */
  SSH_IPPROTO_IFMP = 101,    /* Ipsilon Flow Management [Hinden] */
  SSH_IPPROTO_PNNI = 102,    /* PNNI over IP [Callon] */
  SSH_IPPROTO_PIM = 103,     /* Protocol Independent Multicast */
  SSH_IPPROTO_ARIS = 104,    /* ARIS [Feldman] */
  SSH_IPPROTO_SCPS = 105,    /* SCPS [Durst] */
  SSH_IPPROTO_QNX = 106,     /* QNX [Hunter] */
  SSH_IPPROTO_AN = 107,      /* Active Networks [Braden] */
  SSH_IPPROTO_IPPCP = 108,   /* IP Payload Compr Protocol */
  SSH_IPPROTO_SNP = 109,     /* Sitara Networks Protocol */
  SSH_IPPROTO_COMPAQ = 110,  /* Compaq Peer Protocol */
  SSH_IPPROTO_IPXIP = 111,   /* IPX in IP [Lee] */
  SSH_IPPROTO_VRRP = 112,    /* Virtual Router Redundancy */
  SSH_IPPROTO_PGM = 113,     /* PGM Reliable Transport */
  SSH_IPPROTO_0HOP = 114,    /* Any 0-hop protocol [IANA] */
  SSH_IPPROTO_L2TP = 115,    /* Layer Two Tunneling [Aboba] */
  SSH_IPPROTO_DDX = 116,     /* D-II Data Exchange (DDX) [Worley]  */
  SSH_IPPROTO_IATP = 117,    /* Interactive Agent Transfer Protocol [Murphy] */
  SSH_IPPROTO_STP = 118,     /* Schedule Transfer Protocol [JMP] */
  SSH_IPPROTO_SRP = 119,     /* SpectraLink Radio Protocol [Hamilton] */
  SSH_IPPROTO_UTI = 120,     /* UTI [Lothberg] */
  SSH_IPPROTO_SMP = 121,     /* Simple Message Protocol [Ekblad] */
  SSH_IPPROTO_SM = 122,      /* SM [Crowcroft] */
  SSH_IPPROTO_PTP = 123,     /* Performance Transparency Protocol [Welzl] */
  SSH_IPPROTO_ISISIPV4 = 124,/* ISIS over IPv4 [Przygienda] */
  SSH_IPPROTO_FIRE = 125,    /* FIRE [Partridge] */
  SSH_IPPROTO_CRTP = 126,    /* Combat Radio Transport Protocol [Sautter] */
  SSH_IPPROTO_CRUDP = 127,   /* Combat Radio User Datagram [Sautter] */
  SSH_IPPROTO_SSCOPMCE = 128,/* SSCOPMCE [Waber] */
  SSH_IPPROTO_IPLT = 129,    /* IPLT [Hollbach] */
  SSH_IPPROTO_SPS = 130,     /* Secure Packet Shield [McIntosh] */
  SSH_IPPROTO_PIPE = 131,    /* Private IP Encapsulation within IP [Petri] */
  SSH_IPPROTO_SCTP = 132,    /* Stream Control Transmission Protocol[Stewart]*/
  SSH_IPPROTO_FC = 133,      /* Fibre Channel [Rajagopal] */
  SSH_IPPROTO_RSVP_E2E_IGNORE = 134, /* RSVP-E2E-IGNORE [RFC3175] */
  SSH_IPPROTO_MOBILITY = 135,   /* Mobility header [RFC3775] */
  SSH_IPPROTO_UDPLITE = 136,    /* UDP lite [RFC3828] */
  SSH_IPPROTO_ANY = 255         /* Reserved [IANA]; ANY [SSH] */
} SshInetIPProtocolID;

#define SSH_IPPROTO_MIN (  0)
#define SSH_IPPROTO_MAX (255)

/* Minimum length of the ICMP header. */
#define SSH_ICMP_HEADER_MINLEN  8
#define SSH_ICMP_MINLEN  SSH_ICMP_HEADER_MINLEN

/* ICMP types and codes */
typedef enum {
  SSH_ICMP_TYPE_ECHOREPLY = 0,           /* Echo reply */
  SSH_ICMP_TYPE_UNREACH = 3,             /* Destination unreachable */
  SSH_ICMP_TYPE_SOURCEQUENCH = 4,        /* Congestion slow down */
  SSH_ICMP_TYPE_REDIRECT = 5,            /* Shorter route */
  SSH_ICMP_TYPE_ECHO = 8,                /* Echo service */
  SSH_ICMP_TYPE_ROUTERADVERT = 9,        /* Router advertisement */
  SSH_ICMP_TYPE_ROUTERSOLICIT = 10,      /* Router solicitation */
  SSH_ICMP_TYPE_TIMXCEED = 11,           /* Time exceeded */
  SSH_ICMP_TYPE_PARAMPROB = 12,          /* Ip header bad */
  SSH_ICMP_TYPE_TSTAMP = 13,             /* Timestamp request */
  SSH_ICMP_TYPE_TSTAMPREPLY = 14,        /* Timestamp reply */
  SSH_ICMP_TYPE_IREQ = 15,               /* Information request */
  SSH_ICMP_TYPE_IREQREPLY = 16,          /* Information reply */
  SSH_ICMP_TYPE_MASKREQ = 17,            /* Address mask request */
  SSH_ICMP_TYPE_MASKREPLY = 18           /* Address mask reply */
} SshInetIPIcmpType;

typedef enum {
  SSH_ICMP_CODE_UNREACH_NET = 0,         /* Bad network */
  SSH_ICMP_CODE_UNREACH_HOST = 1,        /* Bad host */
  SSH_ICMP_CODE_UNREACH_PROTOCOL = 2,    /* Bad protocol */
  SSH_ICMP_CODE_UNREACH_PORT = 3,        /* Bad port */
  SSH_ICMP_CODE_UNREACH_NEEDFRAG = 4,    /* IP_DF caused drop, frag needed */
  SSH_ICMP_CODE_UNREACH_SRCFAIL = 5,     /* Src route failed */
  SSH_ICMP_CODE_UNREACH_NET_UNKNOWN = 6, /* Unknown net */
  SSH_ICMP_CODE_UNREACH_HOST_UNKNOWN = 7,/* Unknown host */
  SSH_ICMP_CODE_UNREACH_ISOLATED = 8,    /* Src host is isolated */
  SSH_ICMP_CODE_UNREACH_NET_PROHIB = 9,  /* Prohibited network access */
  SSH_ICMP_CODE_UNREACH_HOST_PROHIB = 10,/* Prohibited host access */
  SSH_ICMP_CODE_UNREACH_TOSNET = 11,     /* Bad TOS for net */
  SSH_ICMP_CODE_UNREACH_TOSHOST = 12,    /* Bad TOS for host */
  SSH_ICMP_CODE_UNREACH_ADMIN_PROHIBIT = 13   /* Communication prohibited */
} SshInetIPIcmpUnreachCode;

typedef enum {
  SSH_ICMP_CODE_REDIRECT_NET = 0,        /* Redirect for network */
  SSH_ICMP_CODE_REDIRECT_HOST = 1,       /* ... for host */
  SSH_ICMP_CODE_REDIRECT_TOSNET = 2,     /* ... for TOS and net */
  SSH_ICMP_CODE_REDIRECT_TOSHOST = 3     /* ... for TOS and host */
} SshInetIPIcmpRedirectCode;

typedef enum {
  SSH_ICMP_CODE_TIMXCEED_INTRANS = 0,    /* TTL becomes zero in transit */
  SSH_ICMP_CODE_TIMXCEED_REASS = 1       /* TTL becomes zero in reassembly */
} SshInetIPIcmpTimexceedCode;


/* RFC 2461 defines this minimum length for ICMP neighbor solicitation. */
#define SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN 24
#define SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN 24
#define SSH_ICMP6_ROUTER_ADVERTISEMENT_MINLEN   16

/* ICMP6 types and codes */
typedef enum {
  /* ICMP6 error types */
  SSH_ICMP6_TYPE_UNREACH = 1,           /* Destination unreachable */
  SSH_ICMP6_TYPE_TOOBIG = 2,            /* Packet too big */
  SSH_ICMP6_TYPE_TIMXCEED = 3,          /* Time exceeded */
  SSH_ICMP6_TYPE_PARAMPROB = 4,         /* Parameter problem */

  /* ICMP6 informational types */
  SSH_ICMP6_TYPE_ECHOREQUEST = 128,     /* Echo request */
  SSH_ICMP6_TYPE_ECHOREPLY = 129,       /* Echo reply */

  /* From RFC2461 */
  SSH_ICMP6_TYPE_ROUTER_SOLICITATION = 133,    /* Router solicitation */
  SSH_ICMP6_TYPE_ROUTER_ADVERTISEMENT = 134,   /* Router advertisement */
  SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION = 135,  /* Neighbor Solicitation */
  SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT = 136, /* Neighbor Advertisement */
  SSH_ICMP6_TYPE_REDIRECT = 137                /* Redirect from router */
} SshInetIPIcmp6Type;

/* ICMP6 destination unreachable codes */
typedef enum {
  SSH_ICMP6_CODE_UNREACH_NOROUTE = 0,   /* No route to destination */
  SSH_ICMP6_CODE_UNREACH_PROHIBITED = 1, /* Communication with host
                                            administratively prohibited */
  SSH_ICMP6_CODE_UNREACH_ADDRESS = 3,   /* Address unreachable */
  SSH_ICMP6_CODE_UNREACH_PORT = 4       /* Port unreachable */
} SshInetIPIcmp6UnreachCode;

/* ICMP6 time exceeded codes */
typedef enum {
  SSH_ICMP6_CODE_TIMXCEED_HOP = 0,      /* Hop limit exceeded */
  SSH_ICMP6_CODE_TIMXCEED_REASS = 1     /* Reassembly time exceeded */
} SshInetIPIcmp6TimexceedCode;

/* ICMP6 parameter problem codes */
typedef enum {
  SSH_ICMP6_CODE_PARAMPROB_HEADER = 0,  /* Erroneous header */
  SSH_ICMP6_CODE_PARAMPROB_NH = 1,      /* Unrecognized NH (next hop) type */
  SSH_ICMP6_CODE_PARAMPROB_OPTION = 2   /* Unrecognized option */
} SshInetIPIcmp6ParamprobCode;

/* ICMP6 neighbor discovery option types */
typedef enum {
  SSH_ICMP6_NEIGHDISC_OPT_SOURCE_LINK_ADDRESS = 1,
  SSH_ICMP6_NEIGHDISC_OPT_TARGET_LINK_ADDRESS = 2,
  SSH_ICMP6_NEIGHDISC_OPT_PREFIX_INFORMATION = 3,
  SSH_ICMP6_NEIGHDISC_OPT_REDIRECTED_HEADER = 4,
  SSH_ICMP6_NEIGHDISC_OPT_MTU = 5
} SshInetIPIcmp6NeighdiscOptionType;

/*************************** Auxiliary functions ****************************/

/* Determines whether the given string is a valid numeric IP address
   (either v4 or v6 address). */
Boolean ssh_inet_is_valid_ip_address(const unsigned char *address);

/* Compares two IP addresses, and returns <0 if address1 is smaller
   (in some implementation-defined sense, usually numerically), 0 if
   they denote the same address (though possibly written differently),
   and >0 if address2 is smaller (in the implementation-defined
   sense). */
int ssh_inet_ip_address_compare(const unsigned char *address1,
                                const unsigned char *address2);

/* Compares comma separated list of ip nets and ip-address. Returns
   TRUE if ip-address is inside one of the nets given in
   net-address/netmask-bits format. */
Boolean ssh_inet_compare_netmask(const unsigned char *nets,
                                 const unsigned char *ip);

/* Convert ip number string to binary format. The binary format is
   unsigned character array containing the ip address in network byte
   order. If the ip address is ipv4 address then this fills 4 bytes to
   the buffer, if it is ipv6 address then this will fills 16 bytes to
   the buffer. The buffer length is modified accordingly. This returns
   TRUE if the address is valid and conversion successful and FALSE
   otherwise. If system is configured not to support IPv6, and input
   'ip_address' is IPv6, this will return FALSE. */
Boolean
ssh_inet_strtobin(const unsigned char *ip_address,
                  unsigned char *out_buffer, size_t *out_buffer_len_in_out);

/******** Protocol specifiers to be used in protocol selection masks ********/

#define SSH_IP_TYPE_MASK_IP4    0x00000001
#define SSH_IP_TYPE_MASK_IP6    0x00000002

/***************************** SshIpAddr stuff ******************************/

typedef enum {
    SSH_IP_TYPE_NONE = 0,
    SSH_IP_TYPE_IPV4 = 1,
    SSH_IP_TYPE_IPV6 = 2
} SshIpAddrType;


#if defined(WITH_IPV6)
/* An IPv6 link-local address scope ID. */
struct SshScopeIdRec
{
  union
  {
    SshUInt32 ui32;
  } scope_id_union;
};

typedef struct SshScopeIdRec SshScopeIdStruct;
typedef struct SshScopeIdRec *SshScopeId;

#endif /* WITH_IPV6 */

/* SSH_IP_ADDR_STRING_SIZE is enough to fit following:

   IPv4:
   <ip address> + /<netmask> + few bytes extra

   IPv6:
   <ip address> + %<scope id> + /<prefix length> + few bytes extra
*/

#if !defined(WITH_IPV6)
#define SSH_IP_ADDR_SIZE 4
#define SSH_IP_ADDR_STRING_SIZE 32
#else /* WITH_IPV6 */
#define SSH_IP_ADDR_SIZE 16
#define SSH_IP_ADDR_STRING_SIZE 64
#endif /* !WITH_IPV6 */

typedef struct SshIpAddrRec
{
  /* Note: All fields of this data structure are private, and should
     not be accessed except using the macros and functions defined in
     this header.  They should never be accessed directly; the
     internal definition of this structure is subject to change
     without notice. */

  SshUInt8 type; /* KEEP type first if changing rest of the contents */
  SshUInt8 mask_len;

  /* There is a hole of 16 bits here */

  /* For optimised mask comparison routine _addr_data has to be 32-bit
     aligned so it can be read as words on machines requiring
     alignment */
  union {
    unsigned char _addr_data[SSH_IP_ADDR_SIZE];
    SshUInt32 _addr_align;
  } addr_union;

#define addr_data addr_union._addr_data

#if defined(WITH_IPV6)
  SshScopeIdStruct scope_id;
#endif /* WITH_IPV6 */

} *SshIpAddr, SshIpAddrStruct;

#define SSH_IP_DEFINED(ip_addr) ((ip_addr)->type != SSH_IP_TYPE_NONE)
#define SSH_IP_IS4(ip_addr)     ((ip_addr)->type == SSH_IP_TYPE_IPV4)
#define SSH_IP_IS6(ip_addr)     ((ip_addr)->type == SSH_IP_TYPE_IPV6)

#define SSH_IP_ADDR_LEN(ip_addr)        \
  (SSH_PREDICT_TRUE(SSH_IP_IS4(ip_addr))\
   ? (4)                                \
   : (SSH_IP_IS6(ip_addr)               \
      ? (16)                            \
      : 0))

/* Make given IP address undefined. */
#define SSH_IP_UNDEFINE(IPADDR)         \
do {                                    \
  (IPADDR)->type = SSH_IP_TYPE_NONE;    \
} while (0)

#if defined(WITH_IPV6)
/* Decode, that is fill given 'ipaddr', with given 'type', 'bytes' and
   'masklen' information. */
#define __SSH_IP_MASK_DECODE(IPADDR,TYPE,BYTES,BYTELEN,MASKLEN) \
  do {                                                          \
    (IPADDR)->type = (TYPE);                                    \
    memmove((IPADDR)->addr_data, (BYTES), (BYTELEN));           \
    memset(&(IPADDR)->scope_id, 0, sizeof((IPADDR)->scope_id)); \
    (IPADDR)->mask_len = (MASKLEN);                             \
  } while (0)
#else /* WITH_IPV6 */
#define __SSH_IP_MASK_DECODE(IPADDR,TYPE,BYTES,BYTELEN,MASKLEN) \
  do {                                                          \
    (IPADDR)->type = (TYPE);                                    \
    memmove((IPADDR)->addr_data, (BYTES), (BYTELEN));           \
    (IPADDR)->mask_len = (MASKLEN);                             \
  } while (0)
#endif /* WITH_IPV6 */

/* Encode, that is copy from 'ipaddr' into 'bytes'.  The
   input 'ipaddr' needs to be of given 'type'. It is an fatal error
   to call this for invalid address type. */
#define __SSH_IP_ENCODE(IPADDR,TYPE,BYTES,BYTELEN)              \
  do {                                                          \
    SSH_VERIFY((IPADDR)->type == (TYPE));                       \
    memmove((BYTES), (IPADDR)->addr_data, (BYTELEN));           \
  } while (0)

/* Encode, that is copy from 'ipaddr' into 'bytes' and 'maskptr'.  The
   input 'ipaddr' needs to be of given 'type'. It is an fatal error
   to call this for invalid address type. */
#define __SSH_IP_MASK_ENCODE(IPADDR,TYPE,BYTES,BYTELEN,MASKPTR) \
  do {                                                          \
    __SSH_IP_ENCODE(IPADDR,TYPE,BYTES,BYTELEN);                 \
    if (SSH_PREDICT_FALSE(MASKPTR))                             \
      *((SshUInt32 *) (MASKPTR)) = (IPADDR)->mask_len;          \
  } while (0)

/* IPv4 Address manipulation */
#define SSH_IP4_ENCODE(ip_addr,bytes) \
  __SSH_IP_ENCODE(ip_addr,SSH_IP_TYPE_IPV4,bytes,4)
#define SSH_IP4_MASK_ENCODE(ip_addr,bytes,mask) \
  __SSH_IP_MASK_ENCODE(ip_addr,SSH_IP_TYPE_IPV4,bytes,4,mask)

#define SSH_IP4_DECODE(ip_addr,bytes) \
  __SSH_IP_MASK_DECODE(ip_addr,SSH_IP_TYPE_IPV4,bytes,4,32)
#define SSH_IP4_MASK_DECODE(ip_addr,bytes,mask) \
  __SSH_IP_MASK_DECODE(ip_addr,SSH_IP_TYPE_IPV4,bytes,4,mask)

/* IPv6 address manipulation */
#define SSH_IP6_ENCODE(ip_addr,bytes) \
  __SSH_IP_ENCODE(ip_addr,SSH_IP_TYPE_IPV6,bytes,16)
#define SSH_IP6_MASK_ENCODE(ip_addr,bytes,mask) \
  __SSH_IP_MASK_ENCODE(ip_addr,SSH_IP_TYPE_IPV6,bytes,16,mask)

/* Some hardware accelerators expect to get the buffer in host
   byte order */
#define SSH_IP6_ENCODE_HOST(ip_addr, buf) do { \
  *((SshUInt32 *)((buf) + 0)) =  SSH_IP6_WORD0_TO_INT(ip_addr); \
  *((SshUInt32 *)((buf) + 4)) =  SSH_IP6_WORD1_TO_INT(ip_addr); \
  *((SshUInt32 *)((buf) + 8)) =  SSH_IP6_WORD2_TO_INT(ip_addr); \
  *((SshUInt32 *)((buf) + 12)) =  SSH_IP6_WORD3_TO_INT(ip_addr);\
} while (0)

#if !defined(WITH_IPV6)
#define SSH_IP6_DECODE(ip_addr,bytes) SSH_IP_UNDEFINE(ip_addr)
#define SSH_IP6_MASK_DECODE(ip_addr,bytes,mask) SSH_IP_UNDEFINE(ip_addr)
#else /* WITH_IPV6 */
#define SSH_IP6_DECODE(ip_addr,bytes) \
  __SSH_IP_MASK_DECODE(ip_addr,SSH_IP_TYPE_IPV6,bytes,16,128)
#define SSH_IP6_MASK_DECODE(ip_addr,bytes,mask) \
  __SSH_IP_MASK_DECODE(ip_addr,SSH_IP_TYPE_IPV6,bytes,16,mask)
#endif /* !WITH_IPV6 */

/* Decode given octets in 'addr_buf' (whose length is 'addr_len'
   bytes) into 'ip_addr'. The 'addr_len' determines the address
   family. */
#define SSH_IP_DECODE(ip_addr,addr_buf,addr_len)        \
do {                                                    \
  if ((addr_len) == 4)                                  \
    SSH_IP4_DECODE(ip_addr,addr_buf);                   \
  else if ((addr_len) == 16)                            \
    SSH_IP6_DECODE(ip_addr,addr_buf);                   \
  else                                                  \
    SSH_IP_UNDEFINE(ip_addr);                           \
} while(0)

/* Encode from 'ip_addr' into given address buffer and length information.
   '(void)(addr_len);' is added for the cases when addr_len is not used */
#define SSH_IP_ENCODE(ip_addr,addr_buf,addr_len)        \
do {                                                    \
  (addr_len) = SSH_IP_ADDR_LEN(ip_addr);                \
  (void)(addr_len);                                     \
  if (SSH_PREDICT_TRUE(SSH_IP_IS4(ip_addr)))            \
    SSH_IP4_ENCODE(ip_addr,addr_buf);                   \
  else if (SSH_IP_IS6(ip_addr))                         \
    SSH_IP6_ENCODE(ip_addr, addr_buf);                  \
} while(0)

#define SSH_IP4_TO_INT(ip_addr) SSH_GET_32BIT((ip_addr)->addr_data)

#define SSH_INT_TO_IP4(ip_addr, num)            \
do                                              \
  {                                             \
    (ip_addr)->type = SSH_IP_TYPE_IPV4;         \
    (ip_addr)->mask_len = 32;                   \
    SSH_PUT_32BIT((ip_addr)->addr_data, (num)); \
  }                                             \
while (0)

#define SSH_IP4_BYTE1(ip_addr) ((ip_addr)->addr_data[0])
#define SSH_IP4_BYTE2(ip_addr) ((ip_addr)->addr_data[1])
#define SSH_IP4_BYTE3(ip_addr) ((ip_addr)->addr_data[2])
#define SSH_IP4_BYTE4(ip_addr) ((ip_addr)->addr_data[3])

#define SSH_IP4_BYTEN(ip_addr,n) ((ip_addr)->addr_data[(n)])

#define SSH_IP_BYTEN(ip_addr,n) ((ip_addr)->addr_data[(n)])
#define SSH_IP_ADDR_DATA(ip_addr) ((ip_addr)->addr_data)

#if !defined(WITH_IPV6)
#define SSH_IP6_WORD0_TO_INT(ip_addr) (0)
#define SSH_IP6_WORD1_TO_INT(ip_addr) (0)
#define SSH_IP6_WORD2_TO_INT(ip_addr) (0)
#define SSH_IP6_WORD3_TO_INT(ip_addr) (0)

#define SSH_IP6_INT_TO_WORD0(ip_addr, val)
#define SSH_IP6_INT_TO_WORD1(ip_addr, val)
#define SSH_IP6_INT_TO_WORD2(ip_addr, val)
#define SSH_IP6_INT_TO_WORD3(ip_addr, val)

#define SSH_IP6_BYTE1(ip_addr)  (0)
#define SSH_IP6_BYTE2(ip_addr)  (0)
#define SSH_IP6_BYTE3(ip_addr)  (0)
#define SSH_IP6_BYTE4(ip_addr)  (0)
#define SSH_IP6_BYTE5(ip_addr)  (0)
#define SSH_IP6_BYTE6(ip_addr)  (0)
#define SSH_IP6_BYTE7(ip_addr)  (0)
#define SSH_IP6_BYTE8(ip_addr)  (0)
#define SSH_IP6_BYTE9(ip_addr)  (0)
#define SSH_IP6_BYTE10(ip_addr) (0)
#define SSH_IP6_BYTE11(ip_addr) (0)
#define SSH_IP6_BYTE12(ip_addr) (0)
#define SSH_IP6_BYTE13(ip_addr) (0)
#define SSH_IP6_BYTE14(ip_addr) (0)
#define SSH_IP6_BYTE15(ip_addr) (0)
#define SSH_IP6_BYTE16(ip_addr) (0)

#define SSH_IP6_BYTEN(ip_addr,n)(0)

#else /* WITH_IPV6 */

#define SSH_IP6_WORD0_TO_INT(ip_addr) SSH_GET_32BIT((ip_addr)->addr_data)
#define SSH_IP6_WORD1_TO_INT(ip_addr) SSH_GET_32BIT((ip_addr)->addr_data + 4)
#define SSH_IP6_WORD2_TO_INT(ip_addr) SSH_GET_32BIT((ip_addr)->addr_data + 8)
#define SSH_IP6_WORD3_TO_INT(ip_addr) SSH_GET_32BIT((ip_addr)->addr_data + 12)

#define SSH_IP6_INT_TO_WORD0(ip_addr, val) \
  SSH_PUT_32BIT((ip_addr)->addr_data, val)
#define SSH_IP6_INT_TO_WORD1(ip_addr, val) \
  SSH_PUT_32BIT((ip_addr)->addr_data + 4, val)
#define SSH_IP6_INT_TO_WORD2(ip_addr, val) \
  SSH_PUT_32BIT((ip_addr)->addr_data + 8, val)
#define SSH_IP6_INT_TO_WORD3(ip_addr, val) \
  SSH_PUT_32BIT((ip_addr)->addr_data + 12, val)

#define SSH_IP6_BYTE1(ip_addr) ((ip_addr)->addr_data[0])
#define SSH_IP6_BYTE2(ip_addr) ((ip_addr)->addr_data[1])
#define SSH_IP6_BYTE3(ip_addr) ((ip_addr)->addr_data[2])
#define SSH_IP6_BYTE4(ip_addr) ((ip_addr)->addr_data[3])
#define SSH_IP6_BYTE5(ip_addr) ((ip_addr)->addr_data[4])
#define SSH_IP6_BYTE6(ip_addr) ((ip_addr)->addr_data[5])
#define SSH_IP6_BYTE7(ip_addr) ((ip_addr)->addr_data[6])
#define SSH_IP6_BYTE8(ip_addr) ((ip_addr)->addr_data[7])
#define SSH_IP6_BYTE9(ip_addr) ((ip_addr)->addr_data[8])
#define SSH_IP6_BYTE10(ip_addr) ((ip_addr)->addr_data[9])
#define SSH_IP6_BYTE11(ip_addr) ((ip_addr)->addr_data[10])
#define SSH_IP6_BYTE12(ip_addr) ((ip_addr)->addr_data[11])
#define SSH_IP6_BYTE13(ip_addr) ((ip_addr)->addr_data[12])
#define SSH_IP6_BYTE14(ip_addr) ((ip_addr)->addr_data[13])
#define SSH_IP6_BYTE15(ip_addr) ((ip_addr)->addr_data[14])
#define SSH_IP6_BYTE16(ip_addr) ((ip_addr)->addr_data[15])
#define SSH_IP6_BYTEN(ip_addr,n) ((ip_addr)->addr_data[(n)])
#endif /* !WITH_IPV6 */

#define SSH_IP_MASK_LEN(ip_addr) ((ip_addr)->mask_len)

#if defined(WITH_IPV6)
#define SSH_IP6_SCOPE_ID(ip_addr) ((ip_addr)->scope_id.scope_id_union.ui32)
#endif /* WITH_IPV6 */

/* Compare two IP addresses (in sort-function sense; return ip1 - ip2) */
#define SSH_IP_CMP(ip1, ip2)            \
  (((ip1)->type != (ip2)->type)         \
   ? ((ip1)->type - (ip2)->type)        \
   : (memcmp((ip1)->addr_data, (ip2)->addr_data, SSH_IP_IS6(ip1) ? 16U : 4U)))


/* Return pointer to the min or max of the ip-addresses. */
#define SSH_IP_MIN(ip1,ip2) ((SSH_IP_CMP((ip1), (ip2)) < 0) ? (ip1) : (ip2))
#define SSH_IP_MAX(ip1,ip2) ((SSH_IP_CMP((ip1), (ip2)) > 0) ? (ip1) : (ip2))

/* Compare two IP addresses (in equality sense; return true || false */
#define SSH_IP_EQUAL(ip1, ip2)                          \
  ((ip1)->type == (ip2)->type                           \
   && memcmp((ip1)->addr_data, (ip2)->addr_data,        \
             SSH_IP_IS6(ip1) ? 16U : 4U) == 0)

#define SSH_IP_MASK_EQUAL(ip1, ip2) ssh_ipaddr_mask_equal((ip1), (ip2))
#define SSH_IP_WITH_MASK_EQUAL(ip1, ip2,mask) \
  ssh_ipaddr_with_mask_equal((ip1), (ip2), (mask))

/* Calculate 32bit hash value over the address. */
#define SSH_IP_HASH(ip_addr) ssh_ipaddr_hash((ip_addr))

/* Address class management. Broadcasts, Multicasts, and NULL
   addresses.  These are not defined for undefined address type. */
#define SSH_IP4_NULLADDR "0.0.0.0"
#define SSH_IP6_NULLADDR "::"

#define SSH_IP_IS_NULLADDR(ip_addr)                     \
  (SSH_PREDICT_TRUE(SSH_IP_DEFINED(ip_addr))            \
   ? (SSH_PREDICT_FALSE(SSH_IP_IS6(ip_addr))            \
      ? !memcmp((ip_addr)->addr_data,                   \
                "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) \
      : !SSH_PREDICT_FALSE(memcmp((ip_addr)->addr_data, "\0\0\0\0", 4))) \
   : 0)

/* Returns TRUE if the given IP address is the link broadcast address
   255.255.255.255.  This returns FALSE for IPv6, where link local
   addresses are apparently treated like multicast addresses, at least
   for ARP. */
#define SSH_IP_IS_BROADCAST(ip_addr)                    \
  (SSH_IP_DEFINED(ip_addr) && !SSH_IP_IS6(ip_addr)      \
   && (ip_addr)->addr_data[0] == 0xff                   \
   && (ip_addr)->addr_data[1] == 0xff                   \
   && (ip_addr)->addr_data[2] == 0xff                   \
   && (ip_addr)->addr_data[3] == 0xff)

/* Returns TRUE if the given IP address is a multicast address. */
#define SSH_IP_IS_MULTICAST(ip_addr)                                          \
  (SSH_IP_DEFINED(ip_addr)                                                    \
   ? (SSH_IP_IS6(ip_addr)                                                     \
      ? ((ip_addr)->addr_data[0] == 0xff)                                     \
      : ((ip_addr)->addr_data[0] >= 0xe0 && (ip_addr)->addr_data[0] <= 0xef)) \
   : 0)

/* Return TRUE if the IPv6 address `ip_addr' is a multicast
   address. */
#define SSH_IP6_IS_MULTICAST(ip_addr) (SSH_IP6_BYTE1(ip_addr) == 0xff)

/* Returns TRUE if the given IP address is a loopback address. */
#define SSH_IP_IS_LOOPBACK(ip_addr)                             \
  (SSH_IP_DEFINED(ip_addr)                                      \
   ? (SSH_IP_IS6(ip_addr)                                       \
      ? (memcmp((ip_addr)->addr_data,                           \
                "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16) == 0)   \
      : (SSH_IP4_BYTE1(ip_addr) == 127))                        \
   : 0)

/* Returns TRUE if the given IP address is an IPv6 link-local
   address. */
#define SSH_IP6_IS_LINK_LOCAL(ip_addr)  \
  (SSH_IP_IS6((ip_addr))                \
   && (((SSH_IP6_WORD0_TO_INT((ip_addr))) & 0xffc00000) == 0xfe800000))

/* Returns TRUE if the given IP address is an IPv6 site-local
   address. */
#define SSH_IP6_IS_SITE_LOCAL(ip_addr)  \
  (SSH_IP_IS6((ip_addr))                \
   && (((SSH_IP6_WORD0_TO_INT((ip_addr))) & 0xffc00000) == 0xfec00000))

/* IPv6 multicast address scopes. */

#define SSH_IP6_MC_SCOPE(ip_addr) (SSH_IP6_BYTE2(ip_addr) & 0x0f)

#define SSH_IP6_IS_MC_NODE_LOCAL(ip_addr)       \
(SSH_IP6_IS_MULTICAST(ip_addr) && (SSH_IP6_MC_SCOPE(ip_addr) == 0x01))

#define SSH_IP6_IS_MC_LINK_LOCAL(ip_addr)       \
(SSH_IP6_IS_MULTICAST(ip_addr) && (SSH_IP6_MC_SCOPE(ip_addr) == 0x02))

#define SSH_IP6_IS_MC_SITE_LOCAL(ip_addr)       \
(SSH_IP6_IS_MULTICAST(ip_addr) && (SSH_IP6_MC_SCOPE(ip_addr) == 0x05))

#define SSH_IP6_IS_MC_ORG_LOCAL(ip_addr)        \
(SSH_IP6_IS_MULTICAST(ip_addr) && (SSH_IP6_MC_SCOPE(ip_addr) == 0x08))

#define SSH_IP6_IS_MC_GLOBAL(ip_addr)   \
(SSH_IP6_IS_MULTICAST(ip_addr) && (SSH_IP6_MC_SCOPE(ip_addr) == 0x0e))


/******************** Definitions for IP(4/6) packets ***********************/

#define SSH_IPH_VERSION(ucp) SSH_GET_4BIT_HIGH(ucp)
#define SSH_IPH_SET_VERSION(ucp, v) SSH_PUT_4BIT_HIGH(ucp, (v))

#define SSH_IPH_IS4(ucp) (SSH_IPH_VERSION(ucp) == 4 ? TRUE : FALSE)
#define SSH_IPH_IS6(ucp) (SSH_IPH_VERSION(ucp) == 6 ? TRUE : FALSE)

/*********************** Definitions for IPv4 packets ***********************/


/* Minimum length of an IPv4 header. */
#define SSH_IPH4_HDRLEN 20         /* IPv4 header length */
#define SSH_IPH4_MAX_HEADER_LEN 60 /* maximum ipv4 header len */

/* Offsets of various fields in IPv4 headers. */
#define SSH_IPH4_OFS_VERSION            0
#define SSH_IPH4_OFS_HLEN               0
#define SSH_IPH4_OFS_TOS                1
#define SSH_IPH4_OFS_LEN                2
#define SSH_IPH4_OFS_ID                 4
#define SSH_IPH4_OFS_FRAGOFF            6
#define SSH_IPH4_OFS_TTL                8
#define SSH_IPH4_OFS_PROTO              9
#define SSH_IPH4_OFS_CHECKSUM          10
#define SSH_IPH4_OFS_SRC               12
#define SSH_IPH4_OFS_DST               16

/* Address length */
#define SSH_IPH4_ADDRLEN                4

/* Macros for accessing IPv4 packet header fields.  Any returned values
   will be in host byte order. */
#define SSH_IPH4_VERSION(ucp) SSH_IPH_VERSION(ucp)
#define SSH_IPH4_HLEN(ucp) SSH_GET_4BIT_LOW(ucp)
#define SSH_IPH4_TOS(ucp) SSH_GET_8BIT((ucp) + 1)
#define SSH_IPH4_LEN(ucp) SSH_GET_16BIT((ucp) + 2)
#define SSH_IPH4_ID(ucp) SSH_GET_16BIT((ucp) + 4)
#define SSH_IPH4_FRAGOFF(ucp) SSH_GET_16BIT((ucp) + 6) /* includes flags */
#define SSH_IPH4_TTL(ucp) SSH_GET_8BIT((ucp) + 8)
#define SSH_IPH4_PROTO(ucp) SSH_GET_8BIT((ucp) + 9)
#define SSH_IPH4_CHECKSUM(ucp) SSH_GET_16BIT((ucp) + 10)
#define SSH_IPH4_SRC(ipaddr, ucp) SSH_IP4_DECODE((ipaddr), (ucp) + 12)
#define SSH_IPH4_DST(ipaddr, ucp) SSH_IP4_DECODE((ipaddr), (ucp) + 16)

/* Macros for setting IPv4 packet header fields.  Values are in host
   byte order. */
#define SSH_IPH4_SET_VERSION(ucp, v) SSH_IPH_SET_VERSION(ucp, v)
#define SSH_IPH4_SET_HLEN(ucp, v) SSH_PUT_4BIT_LOW(ucp, (v))
#define SSH_IPH4_SET_TOS(ucp, v) SSH_PUT_8BIT((ucp) + 1, (v))
#define SSH_IPH4_SET_LEN(ucp, v) SSH_PUT_16BIT((ucp) + 2, (v))
#define SSH_IPH4_SET_ID(ucp, v) SSH_PUT_16BIT((ucp) + 4, (v))
#define SSH_IPH4_SET_FRAGOFF(ucp, v) SSH_PUT_16BIT((ucp) + 6, (v))
#define SSH_IPH4_SET_TTL(ucp, v) SSH_PUT_8BIT((ucp) + 8, (v))
#define SSH_IPH4_SET_PROTO(ucp, v) SSH_PUT_8BIT((ucp) + 9, (v))
#define SSH_IPH4_SET_CHECKSUM(ucp, v) SSH_PUT_16BIT((ucp) + 10, (v))
#define SSH_IPH4_SET_SRC(ipaddr, ucp) SSH_IP4_ENCODE((ipaddr), (ucp) + 12)
#define SSH_IPH4_SET_DST(ipaddr, ucp) SSH_IP4_ENCODE((ipaddr), (ucp) + 16)

/* Flags and offset mask for the fragoff field. */
#define SSH_IPH4_FRAGOFF_RF      0x8000 /* reserved flag */
#define SSH_IPH4_FRAGOFF_DF      0x4000 /* dont fragment flag */
#define SSH_IPH4_FRAGOFF_MF      0x2000 /* more fragments flag */
#define SSH_IPH4_FRAGOFF_OFFMASK 0x1fff /* mask for fragment offset */

/* Definitions for IPv4 option numbers. */
#define SSH_IPOPT_EOL           0  /* end of option list */
#define SSH_IPOPT_NOP           1  /* no operation */
#define SSH_IPOPT_RR            7  /* record route */
#define SSH_IPOPT_TS           68  /* timestamp */
#define SSH_IPOPT_BSO         130  /* basic security option */
#define SSH_IPOPT_ESO         133  /* extended security option? */
#define SSH_IPOPT_CIPSO       134  /* commercial? security option */
#define SSH_IPOPT_ROUTERALERT 148  /* router alert */
#define SSH_IPOPT_SNDMULTIDEST 149  /* sender directed multidest delivery */
#define SSH_IPOPT_SATID       136  /* SATNET id */
#define SSH_IPOPT_LSRR        131  /* loose source route */
#define SSH_IPOPT_SSRR        137  /* strict source route */
/* This evaluates to TRUE if the option should be copied on fragmentation. */
#define SSH_IPOPT_COPIED(o) (((o) & 0x80) != 0)

/****************** Definitions for IPv4 ICMP packets ***********************/

/* ICMP offsets to headers etc. (no generic HDRLEN since ICMP headers vary in
   size */

/* Minimum length of ICMP header for all ICMP messages. */
#define SSH_ICMPH_HEADER_MINLEN 2

/* Header length of an ICMP destination unreachable message. */
#define SSH_ICMPH_UNREACH_LEN   8

/* Header length of ICMP echo request/reply messages. */
#define SSH_ICMPH_ECHO_LEN      8

/* Offsets to generic ICMP header. */
#define SSH_ICMPH_OFS_TYPE      0
#define SSH_ICMPH_OFS_CODE      1
#define SSH_ICMPH_OFS_CHECKSUM  2

/* Accessing generic ICMP header fields. */
#define SSH_ICMPH_TYPE(icmp) SSH_GET_8BIT((icmp) + SSH_ICMPH_OFS_TYPE)
#define SSH_ICMPH_CODE(icmp) SSH_GET_8BIT((icmp) + SSH_ICMPH_OFS_CODE)
#define SSH_ICMPH_CHECKSUM(icmp) SSH_GET_16BIT((icmp) + SSH_ICMPH_OFS_CHECKSUM)

#define SSH_ICMPH_SET_TYPE(icmp,v) \
  SSH_PUT_8BIT((icmp) + SSH_ICMPH_OFS_TYPE, (v))
#define SSH_ICMPH_SET_CODE(icmp,v) \
  SSH_PUT_8BIT((icmp) + SSH_ICMPH_OFS_CODE, (v))
#define SSH_ICMPH_SET_CHECKSUM(icmp,v) \
  SSH_PUT_16BIT((icmp) + SSH_ICMPH_OFS_CHECKSUM, (v))

/* Offsets to ICMP Destination Unreachable Fragmentation needed header
   fields */
#define SSH_ICMPH_UNREACH_NEEDFRAG_OFS_MTU       6
#define SSH_ICMPH_UNREACH_NEEDFRAG_MTU(icmp) \
  SSH_GET_16BIT((icmp) + SSH_ICMPH_UNREACH_NEEDFRAG_OFS_MTU)

/* Offsets to ICMP echo request/reply header fields. */
#define SSH_ICMPH_ECHO_OFS_ID   4
#define SSH_ICMPH_ECHO_OFS_SEQ  6

/* Accessing ICMP echo request/reply header fields. */
#define SSH_ICMPH_ECHO_ID(icmp) SSH_GET_16BIT((icmp) + SSH_ICMPH_ECHO_OFS_ID)
#define SSH_ICMPH_ECHO_SEQ(icmp) SSH_GET_16BIT((icmp) + SSH_ICMPH_ECHO_OFS_SEQ)

/******************** Definitions for IPv6 ICMP packets *********************/

/* Header length of an ICMPv6 header. */
#define SSH_ICMP6H_HDRLEN       4

/* Header length of an ICMPv6 unreachable and too big messages. */
#define SSH_ICMP6H_UNREACH_LEN  8
#define SSH_ICMP6H_TOOBIG_LEN   8

/* Header length of ICMPv6 echo request/reply messages. */
#define SSH_ICMP6H_ECHO_LEN     8

/* Offsets of various fields in ICMPv6 headers. */
#define SSH_ICMP6H_OFS_TYPE     0
#define SSH_ICMP6H_OFS_CODE     1
#define SSH_ICMP6H_OFS_CHECKSUM 2

/* Macros for accessing ICMPv6 header fields. */
#define SSH_ICMP6H_TYPE(icmp) SSH_GET_8BIT((icmp) + SSH_ICMP6H_OFS_TYPE)
#define SSH_ICMP6H_CODE(icmp) SSH_GET_8BIT((icmp) + SSH_ICMP6H_OFS_CODE)
#define SSH_ICMP6H_CHECKSUM(icmp) SSH_GET_16BIT((icmp) + \
        SSH_ICMP6H_OFS_CHECKSUM)

/* Macros for setting ICMPv6 header fields. */
#define SSH_ICMP6H_SET_TYPE(icmp, v) \
  SSH_PUT_8BIT((icmp) + SSH_ICMP6H_OFS_TYPE, (v))
#define SSH_ICMP6H_SET_CODE(icmp, v) \
  SSH_PUT_8BIT((icmp) + SSH_ICMP6H_OFS_CODE, (v))
#define SSH_ICMP6H_SET_CHECKSUM(icmp, v) \
  SSH_PUT_16BIT((icmp) + SSH_ICMP6H_OFS_CHECKSUM, (v))

/* Offsets of ICMPv6 TOOBIG header fields */
#define SSH_ICMP6H_TOOBIG_OFS_MTU      4
#define SSH_ICMP6H_TOOBIG_MTU(icmp) \
  SSH_GET_32BIT((icmp) + SSH_ICMP6H_TOOBIG_OFS_MTU)

/* Offsets of various fields in ICMPv6 echo request/reply messages. */
#define SSH_ICMP6H_ECHO_OFS_ID  4
#define SSH_ICMP6H_ECHO_OFS_SEQ 6

/* Accessing ICMPv6 echo request/reply messages. */
#define SSH_ICMP6H_ECHO_ID(icmp) SSH_GET_16BIT((icmp) + SSH_ICMP6H_ECHO_OFS_ID)
#define SSH_ICMP6H_ECHO_SEQ(icmp) \
  SSH_GET_16BIT((icmp) + SSH_ICMP6H_ECHO_OFS_SEQ)


/**************** Definitions for IPv6 neighbor discovery ********************/

/* Offsets of various fields in ICMPv6 neighbor solicitation packets. */
#define SSH_ICMP6H_NS_OFS_RES         4
#define SSH_ICMP6H_NS_OFS_TARGETADDR  8

/* Macros for accessing ICMPv6 neighbor solicitation packets. */
#define SSH_ICMP6H_NS_TARGETADDR(targetaddr, icmp)                      \
  SSH_IP6_DECODE((targetaddr), (icmp) + SSH_ICMP6H_NS_OFS_TARGETADDR)

/* Macros for setting fields in ICMPv6 neighbor solicitation packets. */
#define SSH_ICMP6H_NS_SET_RES(icmp, v)                  \
  SSH_PUT_32BIT((icmp) + SSH_ICMP6H_NS_OFS_RES, (v))
#define SSH_ICMP6H_NS_SET_TARGETADDR(targetaddr, icmp)                  \
  SSH_IP6_ENCODE((targetaddr), (icmp) + SSH_ICMP6H_NS_OFS_TARGETADDR)


/* Flag values for ICMPv6 neighbor advertisement messages. */
#define SSH_ICMP6H_NA_FLAG_ROUTER     0x80
#define SSH_ICMP6H_NA_FLAG_SOLICITED  0x40
#define SSH_ICMP6H_NA_FLAG_OVERRIDE   0x20
#define SSH_ICMP6H_NA_FLAGMASK        0xe0

/* Offsets of various fields in ICMPv6 neighbor advertisement packets. */
#define SSH_ICMP6H_NA_OFS_FLAGS       4
#define SSH_ICMP6H_NA_OFS_RES         5
#define SSH_ICMP6H_NA_OFS_TARGETADDR  8

/* Macros for accessing ICMPv6 neighbor advertisement packets. */
#define SSH_ICMP6H_NA_FLAGS(icmp)                       \
  SSH_GET_8BIT((icmp) + SSH_ICMP6H_NA_OFS_FLAGS)
#define SSH_ICMP6H_NA_TARGETADDR(targetaddr, icmp)                      \
  SSH_IP6_DECODE((targetaddr), (icmp) + SSH_ICMP6H_NA_OFS_TARGETADDR)

/* Macros for setting fields in ICMPv6 neighbor advertisement packets. */
#define SSH_ICMP6H_NA_SET_FLAGS(icmp, v)                \
  SSH_PUT_8BIT((icmp) + SSH_ICMP6H_NA_OFS_FLAGS, (v))
#define SSH_ICMP6H_NA_SET_RES(icmp, v)                  \
  SSH_PUT_24BIT((icmp) + SSH_ICMP6H_NA_OFS_RES, (v))
#define SSH_ICMP6H_NA_SET_TARGETADDR(targetaddr, icmp)                  \
  SSH_IP6_ENCODE((targetaddr), (icmp) + SSH_ICMP6H_NA_OFS_TARGETADDR)


/* Offsets of various fields in ICMPv6 router solicitation packets. */
#define SSH_ICMP6H_RS_OFS_RES         4

/* Macros for setting fields in ICMPv6 router solicitation packets. */
#define SSH_ICMP6H_RS_SET_RES(icmp, v)                  \
  SSH_PUT_32BIT((icmp) + SSH_ICMP6H_NS_OFS_RES, (v))


/* Flag values for ICMPv6 router advertisement messages. */
#define SSH_ICMP6H_RA_FLAG_MANAGED  0x80  /* Managed address configuration */
#define SSH_ICMP6H_RA_FLAG_OTHER    0x40  /* Other stateful configuration */
#define SSH_ICMP6H_RA_FLAGMASK      0xc0

/* Offsets of various fields in ICMPv6 router advertisement packets. */
#define SSH_ICMP6H_RA_OFS_CUR_HOPLIMIT    4
#define SSH_ICMP6H_RA_OFS_FLAGS           5
#define SSH_ICMP6H_RA_OFS_ROUTER_LIFETIME 6
#define SSH_ICMP6H_RA_OFS_REACHABLE_TIME  8
#define SSH_ICMP6H_RA_OFS_RETRANS_TIMER   12

/* Macros for accessing ICMPv6 router advertisement packets. */
#define SSH_ICMP6H_RA_CUR_HOPLIMIT(icmp)                \
  SSH_GET_8BIT((icmp) + SSH_ICMP6H_RA_OFS_CUR_HOPLIMIT)
#define SSH_ICMP6H_RA_FLAGS(icmp)                       \
  SSH_GET_8BIT((icmp) + SSH_ICMP6H_RA_OFS_FLAGS)
#define SSH_ICMP6H_RA_ROUTER_LIFETIME(icmp)                     \
  SSH_GET_16BIT((icmp) + SSH_ICMP6H_RA_OFS_ROUTER_LIFETIME)
#define SSH_ICMP6H_RA_REACHABLE_TIME(icmp)                      \
  SSH_GET_32BIT((icmp) + SSH_ICMP6H_RA_OFS_REACHABLE_TIME)
#define SSH_ICMP6H_RA_RETRANS_TIMER(icmp)                       \
  SSH_GET_32BIT((icmp) + SSH_ICMP6H_RA_OFS_RETRANS_TIMER)

/* Macros for setting fields in ICMPv6 router advertisement packets. */
#define SSH_ICMP6H_RA_SET_CUR_HOPLIMIT(icmp, v)                 \
  SSH_PUT_8BIT((icmp) + SSH_ICMP6H_RA_OFS_CUR_HOPLIMIT, (v))
#define SSH_ICMP6H_RA_SET_FLAGS(icmp, v)                \
  SSH_PUT_8BIT((icmp) + SSH_ICMP6H_RA_OFS_FLAGS, (v))
#define SSH_ICMP6H_RA_SET_ROUTER_LIFETIME(icmp, v)              \
  SSH_PUT_16BIT((icmp) + SSH_ICMP6H_RA_OFS_ROUTER_LIFETIME, (v))
#define SSH_ICMP6H_RA_SET_REACHABLE_TIME(icmp, v)               \
  SSH_PUT_32BIT((icmp) + SSH_ICMP6H_RA_OFS_REACHABLE_TIME, (v))
#define SSH_ICMP6H_RA_SET_RETRANS_TIMER(icmp, v)                \
  SSH_PUT_32BIT((icmp) + SSH_ICMP6H_RA_OFS_RETRANS_TIMER, (v))


/* Options for ICMPv6 neighbor discovery messages. */
#define SSH_ICMP6H_ND_OPTION_HDRLEN           2

/* Offsets for common option header. */
#define SSH_ICMP6H_ND_OPTION_OFS_TYPE         0
#define SSH_ICMP6H_ND_OPTION_OFS_LEN          1

/* Offsets for SSH_ICMP6_NEIGHDISC_OPT_SOURCE_LINK_ADDRESS and
   SSH_ICMP6_NEIGHDISC_OPT_TARGET_LINK_ADDRESS option types. */
#define SSH_ICMP6H_ND_OPTION_LLADDR_OFS_ADDR  2

/* Accessing common option header. */
#define SSH_ICMP6H_ND_OPTION_TYPE(ucp)                  \
  SSH_GET_8BIT((ucp) + SSH_ICMP6H_ND_OPTION_OFS_TYPE)
#define SSH_ICMP6H_ND_OPTION_LEN(ucp)                   \
  SSH_GET_8BIT((ucp) + SSH_ICMP6H_ND_OPTION_OFS_LEN)
#define SSH_ICMP6H_ND_OPTION_LENB(ucp)          \
  (SSH_ICMP6H_ND_OPTION_LEN(ucp) * 8)

#define SSH_ICMP6H_ND_OPTION_SET_TYPE(ucp, v)                   \
  SSH_PUT_8BIT((ucp) + SSH_ICMP6H_ND_OPTION_OFS_TYPE, (v))
#define SSH_ICMP6H_ND_OPTION_SET_LEN(ucp, v)                    \
  SSH_PUT_8BIT((ucp) + SSH_ICMP6H_ND_OPTION_OFS_LEN, (v))


/* Length of SSH_ICMP6_NEIGHDISC_OPT_PREFIX_INFORMATION option type. */
#define SSH_ICMP6H_ND_OPTION_PREFIX_HDRLEN             32

/* Offsets for SSH_ICMP6_NEIGHDISC_OPT_PREFIX_INFORMATION option type. */
#define SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREFIXLEN      2
#define SSH_ICMP6H_ND_OPTION_PREFIX_OFS_FLAGS          3
#define SSH_ICMP6H_ND_OPTION_PREFIX_OFS_VALID_LIFETIME 4
#define SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREF_LIFETIME  8
#define SSH_ICMP6H_ND_OPTION_PREFIX_OFS_RES            12
#define SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREFIX         16

/* Accessing SSH_ICMP6_NEIGHDISC_OPT_PREFIX_INFORMATION option type. */
#define SSH_ICMP6H_ND_OPTION_PREFIX_FLAG_ONLINK        0x80
#define SSH_ICMP6H_ND_OPTION_PREFIX_FLAG_AUTONOMOUS    0x40
#define SSH_ICMP6H_ND_OPTION_PREFIX_FLAGMASK           0xc0

#define SSH_ICMP6H_ND_OPTION_PREFIX_PREFIXLEN(ucp) \
  SSH_GET_8BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREFIXLEN)
#define SSH_ICMP6H_ND_OPTION_PREFIX_FLAGS(ucp)                  \
  SSH_GET_8BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_FLAGS)
#define SSH_ICMP6H_ND_OPTION_PREFIX_VALID_LIFETIME(ucp)                 \
  SSH_GET_32BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_VALID_LIFETIME)
#define SSH_ICMP6H_ND_OPTION_PREFIX_PREF_LIFETIME(ucp)                  \
  SSH_GET_32BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREF_LIFETIME)
#define SSH_ICMP6H_ND_OPTION_PREFIX_PREFIX(addr, ucp)                   \
  SSH_IP6_DECODE((addr), (ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREFIX)

#define SSH_ICMP6H_ND_OPTION_PREFIX_SET_PREFIXLEN(ucp, v)               \
  SSH_PUT_8BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREFIXLEN, (v))
#define SSH_ICMP6H_ND_OPTION_PREFIX_SET_FLAGS(ucp, v)                   \
  SSH_PUT_8BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_FLAGS, (v))
#define SSH_ICMP6H_ND_OPTION_PREFIX_SET_VALID_LIFETIME(ucp, v)          \
  SSH_PUT_32BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_VALID_LIFETIME, (v))
#define SSH_ICMP6H_ND_OPTION_PREFIX_SET_PREF_LIFETIME(ucp, v)           \
  SSH_PUT_32BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREF_LIFETIME, (v))
#define SSH_ICMP6H_ND_OPTION_PREFIX_SET_RES(ucp, v)                     \
  SSH_PUT_32BIT((ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_RES, (v))
#define SSH_ICMP6H_ND_OPTION_PREFIX_SET_PREFIX(addr, ucp)               \
  SSH_IP6_ENCODE((addr), (ucp) + SSH_ICMP6H_ND_OPTION_PREFIX_OFS_PREFIX)


/* Offsets for SSH_ICMP6_NEIGHDISC_OPT_MTU option type. */
#define SSH_ICMP6H_ND_OPTION_MTU_OFS_RES 2
#define SSH_ICMP6H_ND_OPTION_MTU_OFS_MTU 4

/* Accessing SSH_ICMP6_NEIGHDISC_OPT_MTU option type. */
#define SSH_ICMP6H_ND_OPTION_MTU_MTU(ucp)                       \
  SSH_GET_16BIT((ucp) + SSH_ICMP6H_ND_OPTION_MTU_OFS_MTU)

#define SSH_ICMP6H_ND_OPTION_MTU_SET_RES(ucp, v)                \
  SSH_PUT_16BIT((ucp) + SSH_ICMP6H_ND_OPTION_MTU_OFS_RES, (v))
#define SSH_ICMP6H_ND_OPTION_MTU_SET_MTU(ucp, v)                \
  SSH_PUT_16BIT((ucp) + SSH_ICMP6H_ND_OPTION_MTU_OFS_MTU, (v))


/******************** Upper level protocols TCP and UDP *********************/

/* TCP header length, and offsets to header and pseudo-header */
#define SSH_TCPH_HDRLEN 20
#define SSH_TCP_HEADER_LEN SSH_TCPH_HDRLEN

#define SSH_TCPH_OFS_SRCPORT            0
#define SSH_TCPH_OFS_DSTPORT            2
#define SSH_TCPH_OFS_SEQ                4
#define SSH_TCPH_OFS_ACK                8
#define SSH_TCPH_OFS_DATAOFFSET         12
#define SSH_TCPH_OFS_FLAGS              13
#define SSH_TCPH_OFS_WINDOW             14
#define SSH_TCPH_OFS_CHECKSUM           16
#define SSH_TCPH_OFS_URGENT             18

#define SSH_TCPH_PSEUDO_OFS_SRC         0
#define SSH_TCPH_PSEUDO_OFS_DST         4
#define SSH_TCPH_PSEUDO_OFS_PTCL        9
#define SSH_TCPH_PSEUDO_OFS_TCPLEN      10
#define SSH_TCPH_PSEUDO_HDRLEN          12

/* TCP flag bits */
#define SSH_TCPH_FLAG_FIN               0x1
#define SSH_TCPH_FLAG_SYN               0x2
#define SSH_TCPH_FLAG_RST               0x4
#define SSH_TCPH_FLAG_PSH               0x8
#define SSH_TCPH_FLAG_ACK               0x10
#define SSH_TCPH_FLAG_URG               0x20

/* Macros for accessing TCP headers. */
#define SSH_TCPH_SRCPORT(ucp) SSH_GET_16BIT((ucp) + 0)
#define SSH_TCPH_DSTPORT(ucp) SSH_GET_16BIT((ucp) + 2)
#define SSH_TCPH_SEQ(ucp) SSH_GET_32BIT((ucp) + 4)
#define SSH_TCPH_ACK(ucp) SSH_GET_32BIT((ucp) + 8)
#define SSH_TCPH_DATAOFFSET(ucp) SSH_GET_4BIT_HIGH((ucp) + 12)
#define SSH_TCPH_FLAGS(ucp) SSH_GET_8BIT((ucp) + 13)
#define SSH_TCPH_WINDOW(ucp) SSH_GET_16BIT((ucp) + 14)
#define SSH_TCPH_CHECKSUM(ucp) SSH_GET_16BIT((ucp) + 16)
#define SSH_TCPH_URGENT(ucp) SSH_GET_16BIT((ucp) + 18)

#define SSH_TCPH_SET_SRCPORT(ucp, v) SSH_PUT_16BIT((ucp) + 0, (v))
#define SSH_TCPH_SET_DSTPORT(ucp, v) SSH_PUT_16BIT((ucp) + 2, (v))
#define SSH_TCPH_SET_SEQ(ucp, v) SSH_PUT_32BIT((ucp) + 4, (v))
#define SSH_TCPH_SET_ACK(ucp, v) SSH_PUT_32BIT((ucp) + 8, (v))
#define SSH_TCPH_SET_DATAOFFSET(ucp, v) SSH_PUT_4BIT_HIGH((ucp) + 12, (v))
#define SSH_TCPH_SET_FLAGS(ucp, v) SSH_PUT_8BIT((ucp) + 13, (v))
#define SSH_TCPH_SET_WINDOW(ucp, v) SSH_PUT_16BIT((ucp) + 14, (v))
#define SSH_TCPH_SET_CHECKSUM(ucp, v) SSH_PUT_16BIT((ucp) + 16, (v))
#define SSH_TCPH_SET_URGENT(ucp, v) SSH_PUT_16BIT((ucp) + 18, (v))

/********************* Definitions for IPv4 UDP packets *********************/

/* UDP header length, field offsets and pseudo-header offsets */
#define SSH_UDPH_HDRLEN 8
#define SSH_UDP_HEADER_LEN SSH_UDPH_HDRLEN

#define SSH_UDPH_OFS_SRCPORT            0
#define SSH_UDPH_OFS_DSTPORT            2
#define SSH_UDPH_OFS_LEN                4
#define SSH_UDPH_OFS_CHECKSUM           6

#define SSH_UDPH_PSEUDO_OFS_SRC         0
#define SSH_UDPH_PSEUDO_OFS_DST         4
#define SSH_UDPH_PSEUDO_OFS_PROTO       9
#define SSH_UDPH_PSEUDO_OFS_UDPLEN      10
#define SSH_UDPH_PSEUDO_HDRLEN          12

/* Macros for accessing UDP headers. */
#define SSH_UDPH_SRCPORT(ucp) SSH_GET_16BIT((ucp) + 0)
#define SSH_UDPH_DSTPORT(ucp) SSH_GET_16BIT((ucp) + 2)
#define SSH_UDPH_LEN(ucp) SSH_GET_16BIT((ucp) + 4)
#define SSH_UDPH_CHECKSUM(ucp) SSH_GET_16BIT((ucp) + 6)

#define SSH_UDPH_SET_SRCPORT(ucp, v) SSH_PUT_16BIT((ucp) + 0, (v))
#define SSH_UDPH_SET_DSTPORT(ucp, v) SSH_PUT_16BIT((ucp) + 2, (v))
#define SSH_UDPH_SET_LEN(ucp, v) SSH_PUT_16BIT((ucp) + 4, (v))
#define SSH_UDPH_SET_CHECKSUM(ucp, v) SSH_PUT_16BIT((ucp) + 6, (v))

/* Macros for accessing UDP-Lite headers. */
#define SSH_UDP_LITEH_CKSUM_COVERAGE(ucp) SSH_GET_16BIT((ucp) + 4)
#define SSH_UDP_LITEH_SET_CKSUM_COVERAGE(ucp, v) SSH_PUT_16BIT((ucp) + 4, (v))

/*********************** Definitions for IPv6 packets ***********************/

/* IPv6 header length. Extension headers are not counted in IPv6
   header */
#define SSH_IPH6_HDRLEN 40

#define SSH_IPH6_OFS_VERSION            0
#define SSH_IPH6_OFS_CLASS              0
#define SSH_IPH6_OFS_FLOW               1
#define SSH_IPH6_OFS_LEN                4
#define SSH_IPH6_OFS_NH                 6
#define SSH_IPH6_OFS_HL                 7
#define SSH_IPH6_OFS_SRC                8
#define SSH_IPH6_OFS_DST                24

#define SSH_IPH6_ADDRLEN        16

#define SSH_IPH6_VERSION(ucp) SSH_IPH_VERSION(ucp)
#define SSH_IPH6_CLASS(ucp) \
  ((SshUInt8)((SSH_GET_32BIT(ucp) & SSH_IPH6_CLASS_MASK) \
  >> SSH_IPH6_CLASS_SHIFT))
#define SSH_IPH6_FLOW(ucp) (SSH_GET_32BIT(ucp) & SSH_IPH6_FLOW_MASK)
#define SSH_IPH6_LEN(ucp) SSH_GET_16BIT((ucp) + SSH_IPH6_OFS_LEN)
#define SSH_IPH6_NH(ucp) SSH_GET_8BIT((ucp) + SSH_IPH6_OFS_NH)
#define SSH_IPH6_HL(ucp) SSH_GET_8BIT((ucp) + SSH_IPH6_OFS_HL)
#define SSH_IPH6_SRC(ipaddr, ucp) SSH_IP6_DECODE((ipaddr), \
                                                 (ucp) + SSH_IPH6_OFS_SRC)
#define SSH_IPH6_DST(ipaddr, ucp) SSH_IP6_DECODE((ipaddr), \
                                                 (ucp) + SSH_IPH6_OFS_DST)

#define SSH_IPH6_SET_VERSION(ucp, v) SSH_IPH_SET_VERSION(ucp, v)
#define SSH_IPH6_SET_CLASS(ucp, v)              \
  do {                                          \
    SSH_PUT_4BIT_LOW((ucp), ((v) >> 4) & 0xf);  \
    SSH_PUT_4BIT_HIGH((ucp) + 1, (v) & 0xf);    \
  } while (0)
#define SSH_IPH6_SET_FLOW(ucp, v)                       \
  do {                                                  \
    SSH_PUT_4BIT_LOW((ucp) + 1, ((v) >> 16) & 0xf);     \
    SSH_PUT_16BIT((ucp) + 2, (v) & 0xffff);             \
  } while (0)
#define SSH_IPH6_SET_LEN(ucp, v) SSH_PUT_16BIT((ucp) + SSH_IPH6_OFS_LEN, (v))
#define SSH_IPH6_SET_NH(ucp, v) SSH_PUT_8BIT((ucp) + SSH_IPH6_OFS_NH, (v))
#define SSH_IPH6_SET_HL(ucp, v) SSH_PUT_8BIT((ucp) + SSH_IPH6_OFS_HL, (v))
#define SSH_IPH6_SET_SRC(ipaddr, ucp) SSH_IP6_ENCODE((ipaddr), \
                                                     (ucp) + SSH_IPH6_OFS_SRC)
#define SSH_IPH6_SET_DST(ipaddr, ucp) SSH_IP6_ENCODE((ipaddr), \
                                                     (ucp) + SSH_IPH6_OFS_DST)

#define SSH_IPH6_CLASS_SHIFT            20
#define SSH_IPH6_CLASS_MASK             0xff00000
#define SSH_IPH6_FLOW_MASK              0x00fffff

/****************** Definitions for IPv6 extension headers ******************/

/* The common IPv6 extension header format. */

#define SSH_IP6_EXT_COMMON_HDRLEN       2

#define SSH_IP6_EXT_COMMON_OFS_NH       0
#define SSH_IP6_EXT_COMMON_OFS_LEN      1

#define SSH_IP6_EXT_COMMON_NH(ucp)      SSH_GET_8BIT((ucp))
#define SSH_IP6_EXT_COMMON_LEN(ucp)     SSH_GET_8BIT((ucp) + 1)
#define SSH_IP6_EXT_COMMON_LENB(ucp) \
  ((SSH_IP6_EXT_COMMON_LEN((ucp)) + 1) << 3)

#define SSH_IP6_EXT_COMMON_SET_NH(ucp, v)       SSH_PUT_8BIT((ucp), (v))
#define SSH_IP6_EXT_COMMON_SET_LEN(ucp, v)      SSH_PUT_8BIT((ucp) + 1, (v))

/* Predicate to check whether the `Next Header' `nh' can be parsed as
   common IPv6 extension header */
#define SSH_IP6_EXT_IS_COMMON(nh) \
  ((nh) == 0 || (nh) == SSH_IPPROTO_IPV6ROUTE || (nh) == SSH_IPPROTO_IPV6OPTS)


/* Common TLV option format for IPv6 extension headers. */
#define SSH_IP6_EXT_HDR_OPTION_HDRLEN          2

#define SSH_IP6_EXT_HDR_OPTION_OFS_TYPE        0
#define SSH_IP6_EXT_HDR_OPTION_OFS_LEN         1

#define SSH_IP6_EXT_HDR_OPTION_TYPE(ucp)                \
  SSH_GET_8BIT((ucp) + SSH_IP6_EXT_HDR_OPTION_OFS_TYPE)
#define SSH_IP6_EXT_HDR_OPTION_LENB(ucp)                \
  SSH_GET_8BIT((ucp) + SSH_IP6_EXT_HDR_OPTION_OFS_LEN)

#define SSH_IP6_EXT_HDR_OPTION_SET_TYPE(ucp, v)                 \
  SSH_PUT_8BIT((ucp) + SSH_IP6_EXT_HDR_OPTION_OFS_TYPE, (v))
#define SSH_IP6_EXT_HDR_OPTION_SET_LENB(ucp, v)                 \
  SSH_PUT_8BIT((ucp) + SSH_IP6_EXT_HDR_OPTION_OFS_LEN, (v))

/* Known option types */
#define SSH_IP6_EXT_HDR_OPTION_TYPE_PAD1          0
#define SSH_IP6_EXT_HDR_OPTION_TYPE_PADN          1

/* Mask for checking how unknown options are to be processed. */
#define SSH_IP6_EXT_HDR_OPTION_TYPE_SKIP_MASK     0xc0

/* Skip option */
#define SSH_IP6_EXT_HDR_OPTION_TYPE_SKIP          0x00
/* Discard packet */
#define SSH_IP6_EXT_HDR_OPTION_TYPE_DISCARD       0x40
/* Discard packet and send ICMP parameter problem. */
#define SSH_IP6_EXT_HDR_OPTION_TYPE_REJECT        0x80
/* Discard packet and send ICMP parameter problem if dst is not multicast. */
#define SSH_IP6_EXT_HDR_OPTION_TYPE_REJECT_UCAST  0xc0

/* Mask for checking if option data can change during transit. */
#define SSH_IP6_EXT_HDR_OPTION_TYPE_MUTABLE_MASK  0x20
#define SSH_IP6_EXT_HDR_OPTION_TYPE_NONMUTABLE    0x00
#define SSH_IP6_EXT_HDR_OPTION_TYPE_MUTABLE       0x20


/* Hop-by-Hop */

#define SSH_IP6_EXT_HOP_BY_HOP_HDRLEN           SSH_IP6_EXT_COMMON_HDRLEN

#define SSH_IP6_EXT_HOP_BY_HOP_OFS_NH           SSH_IP6_EXT_COMMON_OFS_NH
#define SSH_IP6_EXT_HOP_BY_HOP_OFS_LEN          SSH_IP6_EXT_COMMON_OFS_LEN

#define SSH_IP6_EXT_HOP_BY_HOP_NH(ucp)          SSH_IP6_EXT_COMMON_NH((ucp))
#define SSH_IP6_EXT_HOP_BY_HOP_LEN(ucp)         SSH_IP6_EXT_COMMON_LEN((ucp))
#define SSH_IP6_EXT_HOP_BY_HOP_LENB(ucp)        SSH_IP6_EXT_COMMON_LENB((ucp))

/* Routing */

#define SSH_IP6_EXT_ROUTING_HDRLEN              4

#define SSH_IP6_EXT_ROUTING_OFS_NH              SSH_IP6_EXT_COMMON_OFS_NH
#define SSH_IP6_EXT_ROUTING_OFS_LEN             SSH_IP6_EXT_COMMON_OFS_LEN
#define SSH_IP6_EXT_ROUTING_OFS_TYPE            2
#define SSH_IP6_EXT_ROUTING_OFS_SEGMENTS        3

#define SSH_IP6_EXT_ROUTING_NH(ucp)             SSH_IP6_EXT_COMMON_NH((ucp))
#define SSH_IP6_EXT_ROUTING_LEN(ucp)            SSH_IP6_EXT_COMMON_LEN((ucp))
#define SSH_IP6_EXT_ROUTING_LENB(ucp)           SSH_IP6_EXT_COMMON_LENB((ucp))
#define SSH_IP6_EXT_ROUTING_TYPE(ucp)           SSH_GET_8BIT((ucp) + 2)
#define SSH_IP6_EXT_ROUTING_SEGMENTS(ucp)       SSH_GET_8BIT((ucp) + 3)

#define SSH_IP6_EXT_ROUTING_SET_NH(ucp, v) \
  SSH_IP6_EXT_COMMON_SET_NH((ucp), (v))
#define SSH_IP6_EXT_ROUTING_SET_LEN(ucp, v) \
  SSH_IP6_EXT_COMMON_SET_LEN((ucp), (v))
#define SSH_IP6_EXT_ROUTING_SET_TYPE(ucp, v) \
  SSH_PUT_8BIT((ucp) + 2, (v))
#define SSH_IP6_EXT_ROUTING_SET_SEGMENTS(ucp, v) \
  SSH_PUT_8BIT((ucp) + 3, (v))

/* Fragment */

#define SSH_IP6_EXT_FRAGMENT_HDRLEN             8

#define SSH_IP6_EXT_FRAGMENT_OFS_NH             SSH_IP6_EXT_COMMON_OFS_NH
#define SSH_IP6_EXT_FRAGMENT_OFS_RESERVED1      1
#define SSH_IP6_EXT_FRAGMENT_OFS_OFFSET         2
#define SSH_IP6_EXT_FRAGMENT_OFS_ID             4

#define SSH_IP6_EXT_FRAGMENT_NH(ucp)            SSH_IP6_EXT_COMMON_NH((ucp))
#define SSH_IP6_EXT_FRAGMENT_RESERVED1(ucp)     SSH_GET_8BIT((ucp) + 1)
#define SSH_IP6_EXT_FRAGMENT_OFFSET(ucp)        (SSH_GET_16BIT((ucp) + 2) >> 3)
#define SSH_IP6_EXT_FRAGMENT_RESERVED2(ucp) \
  ((SSH_GET_8BIT((ucp) + 3) >> 1) & 0x3)
#define SSH_IP6_EXT_FRAGMENT_M(ucp)             (SSH_GET_8BIT((ucp) + 3) & 0x1)
#define SSH_IP6_EXT_FRAGMENT_ID(ucp)            SSH_GET_32BIT((ucp) + 4)

/* Destination Options */

#define SSH_IP6_EXT_DSTOPTS_HDRLEN      SSH_IP6_EXT_COMMON_HDRLEN

#define SSH_IP6_EXT_DSTOPTS_OFS_NH      SSH_IP6_EXT_COMMON_OFS_NH
#define SSH_IP6_EXT_DSTOPTS_OFS_LEN     SSH_IP6_EXT_COMMON_OFS_LEN

#define SSH_IP6_EXT_DSTOPTS_NH(ucp)     SSH_IP6_EXT_COMMON_NH((ucp))
#define SSH_IP6_EXT_DSTOPTS_LEN(ucp)    SSH_IP6_EXT_COMMON_LEN((ucp))
#define SSH_IP6_EXT_DSTOPTS_LENB(ucp)   SSH_IP6_EXT_COMMON_LENB((ucp))

/******************** Definitions for IPv6 Pseudo-Header ********************/

#define SSH_IP6_PSEUDOH_HDRLEN          40

#define SSH_IP6_PSEUDOH_OFS_SRC         0
#define SSH_IP6_PSEUDOH_OFS_DST         16
#define SSH_IP6_PSEUDOH_OFS_LEN         32
#define SSH_IP6_PSEUDOH_OFS_NH          39

#define SSH_IP6_PSEUDOH_SET_SRC(ipaddr, ucp)    \
  SSH_IP6_ENCODE((ipaddr), (ucp) + SSH_IP6_PSEUDOH_OFS_SRC)
#define SSH_IP6_PSEUDOH_SET_DST(ipaddr, ucp)    \
  SSH_IP6_ENCODE((ipaddr), (ucp) + SSH_IP6_PSEUDOH_OFS_DST)
#define SSH_IP6_PSEUDOH_SET_LEN(ucp, v) \
  SSH_PUT_32BIT((ucp) + SSH_IP6_PSEUDOH_OFS_LEN, (v))
#define SSH_IP6_PSEUDOH_SET_NH(ucp, v)  \
  SSH_PUT_8BIT((ucp) + SSH_IP6_PSEUDOH_OFS_NH, (v))

/*************************** Link definitions *******************************/

/* Reserved value for invalid interface index. */
#define SSH_INVALID_IFNUM       0xffffffff

/************************** AH and ESP definitions **************************/

#define SSH_ESPH_HDRLEN         8
#define SSH_ESPH_OFS_SPI        0
#define SSH_ESPH_OFS_SEQ        4

#define SSH_ESPH_SPI(ucp) SSH_GET_32BIT((ucp) + SSH_ESPH_OFS_SPI)
#define SSH_ESPH_SEQ(ucp) SSH_GET_32BIT((ucp) + SSH_ESPH_OFS_SEQ)

#define SSH_ESPH_SET_SPI(ucp, v) SSH_PUT_32BIT((ucp) + SSH_ESPH_OFS_SPI, (v))
#define SSH_ESPH_SET_SEQ(ucp, v) SSH_PUT_32BIT((ucp) + SSH_ESPH_OFS_SEQ, (v))

#define SSH_AHH_MINHDRLEN       12
#define SSH_AHH_OFS_NH          0
#define SSH_AHH_OFS_LEN         1
#define SSH_AHH_OFS_SPI         4
#define SSH_AHH_OFS_SEQ         8

#define SSH_AHH_NH(ucp) SSH_GET_8BIT((ucp) + SSH_AHH_OFS_NH)
#define SSH_AHH_LEN(ucp) SSH_GET_8BIT((ucp) + SSH_AHH_OFS_LEN)
#define SSH_AHH_SPI(ucp) SSH_GET_32BIT((ucp) + SSH_AHH_OFS_SPI)
#define SSH_AHH_SEQ(ucp) SSH_GET_32BIT((ucp) + SSH_AHH_OFS_SEQ)

#define SSH_AHH_SET_NH(ucp, v) SSH_PUT_8BIT((ucp) + SSH_AHH_OFS_NH, (v))
#define SSH_AHH_SET_LEN(ucp, v) SSH_PUT_8BIT((ucp) + SSH_AHH_OFS_LEN, (v))
#define SSH_AHH_SET_SPI(ucp, v) SSH_PUT_32BIT((ucp) + SSH_AHH_OFS_SPI, (v))
#define SSH_AHH_SET_SEQ(ucp, v) SSH_PUT_32BIT((ucp) + SSH_AHH_OFS_SEQ, (v))

/******************************* SCTP definitions ***************************/

#define SSH_SCTPH_HDRLEN        12

#define SSH_SCTPH_OFS_SRCPORT 0
#define SSH_SCTPH_OFS_DSTPORT 2
#define SSH_SCTPH_OFS_VERIFTAG 4
#define SSH_SCTPH_OFS_CHECKSUM 8

#define SSH_SCTPH_SRCPORT(ucp) SSH_GET_16BIT((ucp) + SSH_SCTPH_OFS_SRCPORT)
#define SSH_SCTPH_DSTPORT(ucp) SSH_GET_16BIT((ucp) + SSH_SCTPH_OFS_DSTPORT)
#define SSH_SCTPH_VERIFTAG(ucp) SSH_GET_32BIT((ucp) + SSH_SCTPH_OFS_VERIFTAG)
#define SSH_SCTPH_CHECKSUM(ucp) SSH_GET_32BIT((ucp) + SSH_SCTPH_OFS_CHECKSUM)

#define SSH_SCTPH_SET_SRCPORT(ucp, v) \
        SSH_PUT_16BIT((ucp) + SSH_SCTPH_OFS_SRCPORT, (v))
#define SSH_SCTPH_SET_DSTPORT(ucp, v) \
        SSH_PUT_16BIT((ucp) + SSH_SCTPH_OFS_DSTPORT, (v))
#define SSH_SCTPH_SET_VERIFTAG(ucp, v) \
        SSH_PUT_32BIT((ucp) + SSH_SCTPH_OFS_VERIFTAG, (v))
#define SSH_SCTPH_SET_CHECKSUM(ucp, v) \
        SSH_PUT_32BIT((ucp) + SSH_SCTPH_OFS_CHECKSUM, (v))

/********************************* Services *********************************/

/* Looks up the service (port number) by name and protocol.
   `protocol' must be either "tcp" or "udp".  Returns -1 if the
   service could not be found. */
int ssh_inet_get_port_by_service(const unsigned char *name,
                                 const unsigned char *proto);

/* Looks up the name of the service based on port number and protocol.
   `protocol' must be either "tcp" or "udp".  The name is stored in
   the given buffer; is the service is not found, the port number is
   stored instead (without the protocol specification).  The name will
   be truncated if it is too long. */
void ssh_inet_get_service_by_port(unsigned int port,
                                  const unsigned char *protocol,
                                  unsigned char *buf, size_t buflen);

/***************************** Helper functions *****************************/

/* Sets all rightmost bits after keeping `keep_bits' bits on the left
   to the value specified by `value'. */
void ssh_ipaddr_set_bits(SshIpAddr result, SshIpAddr ip,
                         unsigned int keep_bits, unsigned int value);

/* Merges the two IP addresses, so that leftmost `bits' bits are from left_ip,
   and the remaining bits from right_ip. */
void ssh_ipaddr_merge_bits(SshIpAddr result, SshIpAddr left_ip,
                           unsigned int bits, SshIpAddr right_ip);

/* Parses an IP address from the string to the internal representation. */
Boolean ssh_ipaddr_parse(SshIpAddr ip, const unsigned char *str);
Boolean ssh_ipaddr_parse_with_mask(SshIpAddr ip, const unsigned char *str,
                                   const unsigned char *mask);

/* Parses an IP address with an optional IPv6 link-local address scope
   ID.  The addresses with a scope ID are given as `ADDR%SCOPEID'.  On
   success, the function returns a pointer to the scope ID part of the
   address in `scope_id_return'.  The value returned in
   `scope_id_return' will point into the original input string `str'.
   If the string `str' does not contain the scope ID part, the
   `scope_id_return' is set to NULL. */
Boolean ssh_ipaddr_parse_with_scope_id(SshIpAddr ip, const unsigned char *str,
                                       unsigned char **scope_id_return);

#if defined(WITH_IPV6)
/* Resolve scope ID from string presentation into internal format. */
Boolean
ssh_ipaddr_resolve_scope_id(SshScopeId scope, const unsigned char *id);
#endif /* WITH_IPV6 */

/* Check if ipv6 address is just an ipv4 address mapped into ipv6 mask. */
Boolean ssh_inet_addr_is_ip6_mapped_ip4(SshIpAddr ip_addr);

/* Convert if ipv6 mapped ipv4 address to an ipv4 address, if possible. */
Boolean ssh_inet_convert_ip6_mapped_ip4_to_ip4(SshIpAddr ip_addr);

/* Prints the IP address into the buffer in string format.  If the buffer
   is too short, the address is truncated.  This returns `buf'. */
unsigned char *ssh_ipaddr_print(const SshIpAddr ip, unsigned char *buf,
                                size_t buflen);
unsigned char *ssh_ipaddr_print_with_mask(const SshIpAddr ip,
                                          unsigned char *buf, size_t buflen);

/* Rendering function (for ssh_e*printf %@ format) for IP
   addresses. Datum is SshIpAddr. */
int ssh_ipaddr_render(unsigned char *buf, int buf_size, int precision,
                      void *datum);

/* Prints the IP address into the buffer in string format.  If the buffer
   is too short, the address is truncated.  This returns `buf'. */
void ssh_ipaddr_ipv4_print(const unsigned char *data,
                           unsigned char *buf, size_t buflen);
void ssh_ipaddr_ipv6_print(const unsigned char *data,
                           unsigned char *buf, size_t buflen,
                           SshUInt32 scope);

/* Renders an IPv4 address. Datum is SshUInt32 value. */
int ssh_ipaddr4_uint32_render(unsigned char *buf, int buf_size, int precision,
                              void *datum);

/* Renders an IPv6 address. Datum is unsigned char[16] array. */
int ssh_ipaddr6_byte16_render(unsigned char *buf, int buf_size, int precision,
                              void *datum);

/* Rendering function for IP protocol numbers. Datum is SshUInt32. */
int ssh_ipproto_render(unsigned char *buf, int buf_size, int precision,
                       void *datum);

/* Rendering function for IP address masks. Datum is SshIpAddr*/
int ssh_ipmask_render(unsigned char *buf, int buf_size, int precision,
                      void *datum);

/* Rendering function for Ethernet MAC addresses. Datum is unsigned
 * char[6] array. */
int ssh_etheraddr_render(unsigned char *buf, int buf_size, int precision,
                         void *datum);

/* Compares two port number addresses, and returns <0 if port1 is
   smaller, 0 if they denote the same number (though possibly written
   differently), and >0 if port2 is smaller.  The result is zero if
   either address is invalid. */
int ssh_inet_port_number_compare(const unsigned char *port1,
                                 const unsigned char *port2,
                                 const unsigned char *proto);

/* Increment IP address by one. Return TRUE if success and
   FALSE if the IP address wrapped. */
Boolean ssh_ipaddr_increment(SshIpAddr ip);

/* Decrement IP address by one. Return TRUE if success and
   FALSE if the IP address wrapped. */
Boolean ssh_ipaddr_decrement(SshIpAddr ip);

/************************** Routing definitions *****************************/

/** Route precedence level. */
typedef enum {
  SSH_ROUTE_PREC_LOWEST = 0,
  SSH_ROUTE_PREC_BELOW_SYSTEM = 1,
  SSH_ROUTE_PREC_SYSTEM = 2,
  SSH_ROUTE_PREC_ABOVE_SYSTEM = 3,
  SSH_ROUTE_PREC_HIGHEST = 4
} SshRoutePrecedence;

/*************************** Internal definitions ***************************/

/* Some prototypes for internal functions. */
unsigned long ssh_ipaddr_hash(SshIpAddr ip);

Boolean ssh_ipaddr_mask_equal(SshIpAddr ip1, SshIpAddr masked_ip);
Boolean ssh_ipaddr_with_mask_equal(SshIpAddr ip1, SshIpAddr ip2,
                                   SshIpAddr mask);

#endif /* SSHINET_H */
