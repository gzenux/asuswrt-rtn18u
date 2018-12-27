/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Handling compatibility issues.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmCompat"


/************************** Types and definitions ***************************/

/* Registry item for a known vendor ID. */
struct SshPmKnownVendorIdRec
{
  const char *description;
  const char *vendor_id;
  size_t vendor_id_len;
  size_t vendor_id_cmp_len;
  SshUInt32 compat_flags;

  /* Optional selectors for vendor IDs were are sending as our own ID.
     If any of the conditions below is true, then the vendor ID is
     sent.  Note that if all of the masks below have the value 0, then
     the vendor ID is sent. */

  /* Optional selectors for tunnel flags.  If this field is non-zero,
     the Phase-1 negotiation's tunnel flags must contain one of these
     flags in order to send this vendor ID.  Also,
     `SshPmKnownVendorIdStruct.compat_flags' must contain
     `SSH_PM_COMPAT_OUR_ID_IKEV[1,2]' for the IKE version of
     this negotiation. */
  SshUInt32 tunnel_flags_mask;

  /* Optional selectors for tunnel flags.  If this field is non-zero,
     the Phase-1 negotiation's tunnel flags must not contain any of
     these flags in order to send this vendor ID.  Also,
     `SshPmKnownVendorIdStruct.compat_flags' must contain
     `SSH_PM_COMPAT_OUR_ID_IKEV[1,2]' for the IKE version of
     this negotiation. */
  SshUInt32 tunnel_flags_exclude_mask;

  /* Optional selectors for `compat_flags'.  If this field is
     non-zero, the Phase-1 negotiation's `compat_flags' must contain
     one of these flags in order to send this vendor ID.  Also,
     `SshPmKnownVendorIdStruct.compat_flags' must contain
     `SSH_PM_COMPAT_OUR_ID_IKEV[1,2]' for the IKE version of this
     negotiation. Note that the `p1->compat_flags' are set
     only for the responder.  Therefore, this selector can be used to
     select vendor IDs based on the initiator's vendor IDs. */
  SshUInt32 compat_flags_mask;
};

typedef struct SshPmKnownVendorIdRec SshPmKnownVendorIdStruct;
typedef struct SshPmKnownVendorIdRec *SshPmKnownVendorId;
typedef const struct SshPmKnownVendorIdRec *SshPmKnownVendorIdConst;


/************************** Compatiblity databases **************************/

/* Known vendor IDs. */
static const SshPmKnownVendorIdStruct known_vendor_ids[] =
{
  {"Ssh Communications Security IPSEC Express version 1.1.0",
   "\xfb\xf4\x76\x14\x98\x40\x31\xfa\x8e\x3b\xb6\x19\x80\x89\xb2\x23", 16, 16,
   0, 0, 0, 0},
  {"Ssh Communications Security IPSEC Express version 1.1.1",
   "\x19\x52\xdc\x91\xac\x20\xf6\x46\xfb\x01\xcf\x42\xa3\x3a\xee\x30", 16, 16,
   0, 0, 0, 0},
  {"Ssh Communications Security IPSEC Express version 1.1.2",
   "\xe8\xbf\xfa\x64\x3e\x5c\x8f\x2c\xd1\x0f\xda\x73\x70\xb6\xeb\xe5", 16, 16,
   0, 0, 0, 0},
  {"Ssh Communications Security IPSEC Express version 1.2.1",
   "\xc1\x11\x1b\x2d\xee\x8c\xbc\x3d\x62\x05\x73\xec\x57\xaa\xb9\xcb", 16, 16,
   0, 0, 0, 0},
  {"Ssh Communications Security IPSEC Express version 1.2.2",
   "\x09\xec\x27\xbf\xbc\x09\xc7\x58\x23\xcf\xec\xbf\xfe\x56\x5a\x2e", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 2.0.0",
   "\x7f\x21\xa5\x96\xe4\xe3\x18\xf0\xb2\xf4\x94\x4c\x23\x84\xcb\x84", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 2.1.0",
   "\x28\x36\xd1\xfd\x28\x07\xbc\x9e\x5a\xe3\x07\x86\x32\x04\x51\xec", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 2.1.1",
   "\xa6\x8d\xe7\x56\xa9\xc5\x22\x9b\xae\x66\x49\x80\x40\x95\x1a\xd5", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 2.1.2",
   "\x3f\x23\x72\x86\x7e\x23\x7c\x1c\xd8\x25\x0a\x75\x55\x9c\xae\x20", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 3.0.0",
   "\x0e\x58\xd5\x77\x4d\xf6\x02\x00\x7d\x0b\x02\x44\x36\x60\xf7\xeb", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 3.0.1",
   "\xf5\xce\x31\xeb\xc2\x10\xf4\x43\x50\xcf\x71\x26\x5b\x57\x38\x0f", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 4.0.0",
   "\xf6\x42\x60\xaf\x2e\x27\x42\xda\xdd\xd5\x69\x87\x06\x8a\x99\xa0", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 4.0.1",
   "\x7a\x54\xd3\xbd\xb3\xb1\xe6\xd9\x23\x89\x20\x64\xbe\x2d\x98\x1c", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 4.1.0",
   "\x9a\xa1\xf3\xb4\x34\x72\xa4\x5d\x5f\x50\x6a\xeb\x26\x0c\xf2\x14", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 4.1.1",
   "\x89\xf7\xb7\x60\xd8\x6b\x01\x2a\xcf\x26\x33\x82\x39\x4d\x96\x2f", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 4.2.0",
   "\x68\x80\xc7\xd0\x26\x09\x91\x14\xe4\x86\xc5\x54\x30\xe7\xab\xee", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 5.0",
   "\xb0\x37\xa2\x1a\xce\xcc\xb5\x57\x0f\x60\x25\x46\xf9\x7b\xde\x8c", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security IPSEC Express version 5.1.0",
   "\x45\xe1\x7f\x3a\xbe\x93\x94\x4c\xb2\x02\x91\x0c\x59\xef\x80\x6b", 16, 16,
   0, 0, 0, 0},

  {"SSH Sentinel",
   "\x05\x41\x82\xa0\x7c\x7a\xe2\x06\xf9\xd2\xcf\x9d\x24\x32\xc4\x82", 16, 16,
   0, 0, 0, 0},
  {"SSH Sentinel 1.1",
   "\xb9\x16\x23\xe6\x93\xca\x18\xa5\x4c\x6a\x27\x78\x55\x23\x05\xe8", 16, 16,
   0, 0, 0, 0},
  {"SSH Sentinel 1.2",
   "\x54\x30\x88\x8d\xe0\x1a\x31\xa6\xfa\x8f\x60\x22\x4e\x44\x99\x58", 16, 16,
   0, 0, 0, 0},
  {"SSH Sentinel 1.3",
   "\x7e\xe5\xcb\x85\xf7\x1c\xe2\x59\xc9\x4a\x5c\x73\x1e\xe4\xe7\x52", 16, 16,
   0, 0, 0, 0},
  {"SSH Sentinel 1.4",
   "\x63\xd9\xa1\xa7\x00\x94\x91\xb5\xa0\xa6\xfd\xeb\x2a\x82\x84\xf0", 16, 16,
   0, 0, 0, 0},
  {"SSH Sentinel 1.4.1",
   "\xeb\x4b\x0d\x96\x27\x6b\x4e\x22\x0a\xd1\x62\x21\xa7\xb2\xa5\xe6", 16, 16,
   0, 0, 0, 0},

  {"SSH Communications Security QuickSec 0.9.0",
   "\x37\xeb\xa0\xc4\x13\x61\x84\xe7\xda\xf8\x56\x2a\x77\x06\x0b\x4a", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security QuickSec 1.1.0",
   "\x5d\x72\x92\x5e\x55\x94\x8a\x96\x61\xa7\xfc\x48\xfd\xec\x7f\xf9", 16, 16,
   0, 0, 0, 0},

  {"SSH Communications Security QuickSec 1.1.1",
   "\x77\x7f\xbf\x4c\x5a\xf6\xd1\xcd\xd4\xb8\x95\xa0\x5b\xf8\x25\x94", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security QuickSec 1.1.2",
   "\x2c\xdf\x08\xe7\x12\xed\xe8\xa5\x97\x87\x61\x26\x7c\xd1\x9b\x91", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security QuickSec 1.1.3",
   "\x59\xe4\x54\xa8\xc2\xcf\x02\xa3\x49\x59\x12\x1f\x18\x90\xbc\x87", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security QuickSec 2.0.0",
   "\x40\x2f\x7b\x24\x7b\x5a\x50\x66\xc1\xfb\x9f\x53\xf4\x80\xc9\xf5", 16, 16,
   0, 0, 0, 0},
  {"SSH Communications Security QuickSec 2.1.0",
   "\x8f\x9c\xc9\x4e\x01\x24\x8e\xcd\xf1\x47\x59\x4c\x28\x4b\x21\x3b", 16, 16,
   0, 0, 0, 0},

  {"SafeNet QuickSec",
   "\xf7\x58\xf2\x26\x68\x75\x0f\x03\xb0\x8d\xf6\xeb\xe1\xd0\x05\x10", 16, 14,
   0, 0, 0, 0},

  {"AuthenTec QuickSec",
   "\x2c\x18\x29\x2c\x67\x5f\xbf\x1c\x9c\xad\x0e\x9f\xea\x7c\x05\x10", 16, 14,
   0, 0, 0, 0},

  {"INSIDE Secure QuickSec",
   "\x4f\x85\x58\x17\x1d\x21\xa0\x8d\x69\xcb\x5f\x60\x9b\x3c\x06\x00", 16 , 14,
   SSH_PM_COMPAT_OUR_ID_IKEV1 | SSH_PM_COMPAT_OUR_ID_IKEV2, 0, 0, 0},

  {"draft-stenberg-ipsec-nat-traversal-01",
   "\x27\xba\xb5\xdc\x01\xea\x07\x60\xea\x4e\x31\x90\xac\x27\xc0\xd0", 16, 16,
   0, 0, 0, 0},
  {"draft-stenberg-ipsec-nat-traversal-02",
   "\x61\x05\xc4\x22\xe7\x68\x47\xe4\x3f\x96\x84\x80\x12\x92\xae\xcd", 16, 16,
   0, 0, 0, 0},
  {"draft-huttunen-ipsec-esp-in-udp-00.txt",
   "\x6a\x74\x34\xc1\x9d\x7e\x36\x34\x80\x90\xa0\x23\x34\xc9\xc8\x05", 16, 16,
   0, 0, 0, 0},
  {"draft-huttunen-ipsec-esp-in-udp-01.txt", /* MD5(ESPThruNAT) */
   "\x50\x76\x0f\x62\x4c\x63\xe5\xc5\x3e\xea\x38\x6c\x68\x5c\xa0\x83", 16, 16,
   0, 0, 0, 0},
  {"draft-ietf-ipsec-nat-t-ike-00",
   "\x44\x85\x15\x2d\x18\xb6\xbb\xcd\x0b\xe8\xa8\x46\x95\x79\xdd\xcc", 16, 16,
   0, 0, 0, 0},
  {"draft-ietf-ipsec-nat-t-ike-02",
   "\xcd\x60\x46\x43\x35\xdf\x21\xf8\x7c\xfd\xb2\xfc\x68\xb6\xa4\x48", 16, 16,
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
   SSH_PM_COMPAT_OUR_ID_IKEV1
   | SSH_PM_COMPAT_NAT_T
   | SSH_PM_COMPAT_NAT_T_AGGR_MODE
   | SSH_PM_COMPAT_NAT_T_IETF
   | SSH_PM_COMPAT_NAT_T_PORT_FLOAT
   | SSH_PM_COMPAT_NAT_T_DRAFT_02,
#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */
   0,
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
   0, SSH_PM_T_DISABLE_NATT, 0},
  {"draft-ietf-ipsec-nat-t-ike-02",
   "\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f", 16, 16,
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
   SSH_PM_COMPAT_OUR_ID_IKEV1
   | SSH_PM_COMPAT_NAT_T
   | SSH_PM_COMPAT_NAT_T_AGGR_MODE
   | SSH_PM_COMPAT_NAT_T_IETF
   | SSH_PM_COMPAT_NAT_T_PORT_FLOAT
   | SSH_PM_COMPAT_NAT_T_DRAFT_02,
#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */
   0,
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
   0, SSH_PM_T_DISABLE_NATT, 0},
  {"draft-ietf-ipsec-nat-t-ike-03",
   "\x7d\x94\x19\xa6\x53\x10\xca\x6f\x2c\x17\x9d\x92\x15\x52\x9d\x56", 16, 16,
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
   SSH_PM_COMPAT_OUR_ID_IKEV1
   | SSH_PM_COMPAT_NAT_T
   | SSH_PM_COMPAT_NAT_T_AGGR_MODE
   | SSH_PM_COMPAT_NAT_T_IETF
   | SSH_PM_COMPAT_NAT_T_PORT_FLOAT
   | SSH_PM_COMPAT_NAT_T_DRAFT_03,
#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */
   0,
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
   0, SSH_PM_T_DISABLE_NATT, 0},
  {"RFC 3947 (NAT-Traversal)",
   "\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f", 16, 16,
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
   SSH_PM_COMPAT_OUR_ID_IKEV1
   | SSH_PM_COMPAT_NAT_T
   | SSH_PM_COMPAT_NAT_T_AGGR_MODE
   | SSH_PM_COMPAT_NAT_T_IETF
   | SSH_PM_COMPAT_NAT_T_PORT_FLOAT
   | SSH_PM_COMPAT_NAT_T_RFC,
#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */
   0,
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
   0, SSH_PM_T_DISABLE_NATT, 0},

#ifdef SSHDIST_IKE_XAUTH
  {"draft-beaulieu-ike-xauth-02",
   /* MD5(draft-ietf-ipsra-isakmp-xauth-06.txt) */
   "\x09\x00\x26\x89\xdf\xd6\xb7\x12\x80\xa2\x24\xde\xc3\x3b\x81\xe5", 8, 8,
   SSH_PM_COMPAT_OUR_ID_IKEV1 | SSH_PM_COMPAT_XAUTH_BEAULIEU_00,
   SSH_PM_T_XAUTH_METHODS,
   0,
   SSH_PM_COMPAT_XAUTH_BEAULIEU_00},
#endif /* SSHDIST_IKE_XAUTH */

  {"FRAGMENTATION",             /* Microsoft implementations send this. */
   "\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3", 16, 16,
   /* This implementation seems to send an `invalid SPI' notification
      if it receives a delete notification for an IPSec SA that it
      does not know anything about.  So, let's not sent IPSec SA
      delete notifications for this implementation. */
   SSH_PM_COMPAT_NO_IPSEC_DELETE_NOTIFICATIONS, 0, 0, 0},

  {"Vid-Initial-Contact",       /* Microsoft implementations send this. */
   "\x26\x24\x4d\x38\xed\xdb\x61\xb3\x17\x2a\x36\xe3\xd0\xcf\xb8\x19", 16, 16,
   0, 0, 0, 0},
#ifdef SSHDIST_IKEV1
  {"RFC 3706 (Dead Peer Detection)", /* Unknown digest. */
   "\xAF\xCA\xD7\x13\x68\xA1\xF1\xC9\x6B\x86\x96\xFC\x77\x57\x01\x00", 16, 16,
   SSH_PM_COMPAT_OUR_ID_IKEV1 | SSH_PM_COMPAT_REMOTE_DPD,
   0, 0, 0},
#endif /* SSHDIST_IKEV1 */
  {"IKE Challenge/Response for Authenticated Cryptographic Keys",
   "\xba\x29\x04\x99\xc2\x4e\x84\xe5\x3a\x1d\x83\xa0\x5e\x5f\x00\xc9", 16, 16,
   0, 0, 0, 0},
  {"IKE Challenge/Response for Authenticated Cryptographic Keys",
   /* Unknown digest. */
   "\x0d\x33\x61\x1a\x5d\x52\x1b\x5e\x3c\x9c\x03\xd2\xfc\x10\x7e\x12", 16, 16,
   0, 0, 0, 0},
  {"IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)",
   "\xad\x32\x51\x04\x2c\xdc\x46\x52\xc9\xe0\x73\x4c\xe5\xde\x4c\x7d", 16, 16,
   0, 0, 0, 0},
  {"IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)",
   /* Unknown digest. */
   "\x01\x3f\x11\x82\x3f\x96\x6f\xa9\x19\x00\xf0\x24\xba\x66\xa8\x6b", 16, 16,
   0, 0, 0, 0},
  {"A GSS-API Authentication Method for IKE",
   "\xb4\x6d\x89\x14\xf3\xaa\xa3\xf2\xfe\xde\xb7\xc7\xdb\x29\x43\xca", 16, 16,
   0, 0, 0, 0},
  {"A GSS-API Authentication Method for IKE",
   "\xad\x2c\x0d\xd0\xb9\xc3\x20\x83\xcc\xba\x25\xb8\x86\x1e\xc4\x55", 16, 16,
   0, 0, 0, 0},
  {"GSSAPI",
   "\x62\x1b\x04\xbb\x09\x88\x2a\xc1\xe1\x59\x35\xfe\xfa\x24\xae\xee", 16, 16,
   0, 0, 0, 0},
  {"MS NT5 ISAKMPOAKLEY",
   "\x1e\x2b\x51\x69\x05\x99\x1c\x7d\x7c\x96\xfc\xbf\xb5\x87\xe4\x61", 16, 16,
   SSH_PM_COMPAT_NAT_T_FQDN_PROXY_ID, 0, 0, 0},
#ifdef SSH_IPSEC_TCPENCAP
  {"Unknown vendor ID - Cisco TCP encapsulation 1.0",
   "\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00", 16, 16,
   SSH_PM_COMPAT_OUR_ID_IKEV1 | SSH_PM_COMPAT_OUR_ID_IKEV2
   | SSH_PM_COMPAT_TCPENCAP, SSH_PM_T_TCPENCAP, 0, SSH_PM_COMPAT_TCPENCAP},
#endif /* SSH_IPSEC_TCPENCAP */
  {"Cisco VPN Concentrator",
   "\x1f\x07\xf7\x0e\xaa\x65\x14\xd3\xb0\xfa\x96\x54\x2a\x50\x01\x00", 16, 16,
   0, 0, 0, 0},
  {"CISCO-UNITY",
   "\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x02\xd4", 16, 14,
   SSH_PM_COMPAT_OUR_ID_IKEV1 | SSH_PM_COMPAT_CISCO_UNITY,
   0, 0, SSH_PM_COMPAT_CISCO_UNITY},
  {"SafeNet SoftRemote LT 10.0.0",
   "\x47\xbb\xe7\xc9\x93\xf1\xfc\x13\xb4\xe6\xd0\xdb\x56\x5c\x68\xe5", 16, 14,
   SSH_PM_COMPAT_NO_CERT_CHAINS | SSH_PM_COMPAT_SET_ACK_CFG |
   SSH_PM_COMPAT_DONT_INITIATE,
   0, 0, 0},
  {"Openswan",
   "\x4f\x45\x60\x6c\x50\x48\x7c\x56\x62\x70\x75\x75", 12, 12,
   0,
   0, 0, 0},
  {"SonicWall",
   "\x40\x4b\xf4\x39\x52\x2c\xa3\xf6", 8, 8,
   0, 0, 0, 0},
  {"Nortel Contivity VPN Client", /* Unknown digest. */
   "\x4e\x61\x54\x2d\x53\x49\x58\xc0\xaa\x65\x9b\xae\x60\xb2\x3f\xf8"
   "\x99\x0f\x0b\xde\xc4", 21, 16,
   0, 0, 0, 0},
  {"draft-ietf-ipsec-antireplay-00.txt",
   "\x32\x5d\xf2\x9a\x23\x19\xf2\xdd", 8, 8,
   0, 0, 0, 0},
  {"draft-ietf-ipsec-heartbeats-00.txt",
   "\x8D\xB7\xA4\x18\x11\x22\x16\x60", 8, 8,
   0, 0, 0, 0},
  {"strongSwan 4.2.10",
   "\x1a\xa1\x58\xae\x7f\x11\xe7\x7d\x75\xec\x80\x1d\xb5\x3f\x7e\xc5", 16, 16,
   0, 0, 0, 0},
  {"Heartbeat Notify",
   "\x48\x65\x61\x72\x74\x42\x65\x61\x74\x5f\x4e\x6f\x74\x69\x66"
   "\x79\x38\x6b\x01 00", 20, 20, 0, 0, 0, 0},
};

/* The number of known vendor IDs. */
static const unsigned int num_known_vendor_ids =
(sizeof(known_vendor_ids) / sizeof(known_vendor_ids[0]));


/*********************** IKE PAD functions ***********************/

/* Function to receive vendor ID payloads sent by the remote. These
   identities are used to fetch compatiblity flags and parameters into
   negotiation context so one may later decide what kind of extensions
   or features are usable. */
void
ssh_pm_ike_received_vendor_id(SshSADHandle sad_handle,
                              SshIkev2ExchangeData ed,
                              const unsigned char *vendor_id,
                              size_t vendor_id_len)
{
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
#ifdef DEBUG_LIGHT
  char buf[64];
#endif /* DEBUG_LIGHT */
  int i;

  SSH_PM_ASSERT_P1(p1);
  if (!SSH_PM_P1_USABLE(p1))
    return;

  for (i = 0; i < num_known_vendor_ids; i++)
    {
      if (known_vendor_ids[i].vendor_id_cmp_len <= vendor_id_len
          && memcmp(known_vendor_ids[i].vendor_id, vendor_id,
                    known_vendor_ids[i].vendor_id_cmp_len) == 0)
        {
#ifdef DEBUG_LIGHT
          size_t leftovers;

          leftovers = vendor_id_len - known_vendor_ids[i].vendor_id_cmp_len;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("The remote server IKE server %@:%d has sent vendor "
                     "id %s%s%s",
                     ssh_ipaddr_render, p1->ike_sa->remote_ip,
                     p1->ike_sa->remote_port,
                     known_vendor_ids[i].description,
                     leftovers ? " " : "",
                     ssh_pm_util_data_to_hex(
                                buf, sizeof(buf),
                                vendor_id +
                                known_vendor_ids[i].vendor_id_cmp_len,
                                leftovers)));
#endif /*  DEBUG_LIGHT */

          /* Set compatibility flags. */
          p1->compat_flags |= known_vendor_ids[i].compat_flags;
          return;
        }
    }

  /* We have no clue.  Let's just print its vendor ID in hex. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Received vendor id `%s' (%@:%d)",
             ssh_pm_util_data_to_hex(buf, sizeof(buf),
                                     vendor_id, vendor_id_len),
             ssh_ipaddr_render, p1->ike_sa->remote_ip,
             p1->ike_sa->remote_port));
}

static
SshUInt32 ssh_pm_narrow_natt_compat_flags(SshIkev2ExchangeData ed)
{
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshUInt32 natt_compat_flags = 0;

  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      natt_compat_flags |= SSH_PM_COMPAT_NAT_T_RFC
        | SSH_PM_COMPAT_NAT_T_DRAFT_03
        | SSH_PM_COMPAT_NAT_T_DRAFT_02;

      return natt_compat_flags;
    }

  if (p1->compat_flags & SSH_PM_COMPAT_CISCO_UNITY)
    {
      /* The Cisco ASA 55XX sends all draft_02 & draft_03 and RFC.
         The Cisco IOS sends only RFC, and in that case fall through
         to normal narrowing of the natt compat flags. */
      if (p1->compat_flags & SSH_PM_COMPAT_NAT_T_DRAFT_02)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Cisco UNITY, NAT-T draft 02 selected"));

          p1->compat_flags |= SSH_PM_COMPAT_FORCE_NAT_T_DRAFT_02;
          natt_compat_flags |= SSH_PM_COMPAT_NAT_T_DRAFT_02;
          return natt_compat_flags;
        }
    }

  if (p1->compat_flags & SSH_PM_COMPAT_FORCE_NAT_T_DRAFT_02)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Forcing NAT-T draft 02"));

      natt_compat_flags |= SSH_PM_COMPAT_NAT_T_DRAFT_02;
      return natt_compat_flags;
    }

  if (p1->compat_flags & SSH_PM_COMPAT_NAT_T_RFC)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("NAT-T RFC selected"));

      natt_compat_flags |= SSH_PM_COMPAT_NAT_T_RFC;
    }
  else if (p1->compat_flags & SSH_PM_COMPAT_NAT_T_DRAFT_03)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("NAT-T DRAFT 03 selected"));

      natt_compat_flags |= SSH_PM_COMPAT_NAT_T_DRAFT_03;
    }
  else if (p1->compat_flags & SSH_PM_COMPAT_NAT_T_DRAFT_02)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("NAT-T DRAFT 02 selected"));

      natt_compat_flags |= SSH_PM_COMPAT_NAT_T_DRAFT_02;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Selected NAT-T flags to 0x%x", natt_compat_flags));

  return natt_compat_flags;
}

/* This function returns the vendor ID payload contents to send to the
   remote peer. */
SshOperationHandle
ssh_pm_ike_request_vendor_id(SshSADHandle sad_handle,
                             SshIkev2ExchangeData ed,
                             SshIkev2PadAddVendorIDCB reply_callback,
                             void *reply_callback_context)
{
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  Boolean ikev2 = TRUE;
  SshUInt32 natt_compat_flags = 0;
  int i;

  /* Only send vendor ID's for the IKE initial exchange. */
  if (ed->state != SSH_IKEV2_STATE_IKE_INIT_SA
      && (p1->n == NULL || p1->n->vid_requested))
    {
     (*reply_callback)(SSH_IKEV2_ERROR_OK, NULL, 0, reply_callback_context);
      return NULL;
    }

  if (ssh_pm_get_status(sad_handle->pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, NULL, 0,
                        reply_callback_context);
      return NULL;
    }

  /* Mark that we have now sent the vendor ID's */
  SSH_PM_ASSERT_P1N(p1);
  p1->n->vid_requested = 1;

#ifdef SSHDIST_IKEV1
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    ikev2 = FALSE;

  /* Select a tunnel for the IKEv1 reponder if not already done */
  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
      (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
    {
      SshIkev2Error error;

      error = ssh_pm_select_ike_responder_tunnel(sad_handle->pm, p1, ed);
      if (error != SSH_IKEV2_ERROR_OK)
        {
          (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                            NULL, 0, reply_callback_context);
          return NULL;
        }
    }
#endif /* SSHDIST_IKEV1 */

  /* Do a down select of the compat flags, especially beneficial in
     responder. */
  natt_compat_flags = ssh_pm_narrow_natt_compat_flags(ed);

  if (!p1->n->tunnel)
    {
      /* If tunnel is not specified (for existing IKEv2 SA's), do not
         bother sending vendor ID's. We've already told them to the
         peer while doing the initial exchange. */
      (*reply_callback)(SSH_IKEV2_ERROR_OK, NULL, 0, reply_callback_context);
      return NULL;
    }

  for (i = 0; i < num_known_vendor_ids; i++)
    if (((ikev2 &&
          (known_vendor_ids[i].compat_flags & SSH_PM_COMPAT_OUR_ID_IKEV2)) ||
         (!ikev2 &&
          (known_vendor_ids[i].compat_flags & SSH_PM_COMPAT_OUR_ID_IKEV1)))
        && ((known_vendor_ids[i].compat_flags & SSH_PM_COMPAT_NAT_T) == 0
            || (known_vendor_ids[i].compat_flags & natt_compat_flags) != 0))
      {
        SshPmKnownVendorIdConst vid = &known_vendor_ids[i];

        /* Check the optional tunnel or compat flags selectors of this
           vendor ID. */
        if ((vid->tunnel_flags_mask == 0
             && vid->tunnel_flags_exclude_mask == 0
             && vid->compat_flags_mask == 0)
            || (vid->tunnel_flags_mask & p1->n->tunnel->flags
                || (vid->tunnel_flags_exclude_mask
                 && ((vid->tunnel_flags_exclude_mask & p1->n->tunnel->flags)
                        == 0))
                || vid->compat_flags_mask & p1->compat_flags))
          {
            /* All selectors match.  Let's send this vendor ID as our
               ID. */
            SSH_DEBUG(SSH_D_NICETOKNOW, ("Sending vendor ID %s",
                                         known_vendor_ids[i].description));


            (*reply_callback)(SSH_IKEV2_ERROR_OK, vid->vendor_id,
                              vid->vendor_id_len, reply_callback_context);
          }
      }

  (*reply_callback)(SSH_IKEV2_ERROR_OK, NULL, 0, reply_callback_context);
  return NULL;
}

#ifdef SSHDIST_IKEV1
/** Filter p1 compat flags for new IKEv1 SA based on information from
    previously created peer entry. This is used for IKEv1 only. */
void pm_ike_sa_filter_v1_compat_flags(SshPm pm, SshPmP1 p1)
{
  SshPmPeer peer;

  if (p1 == NULL || p1->n == NULL || p1->n->tunnel == NULL)
    return;

  /* Lookup matching peer by IP addresses and ports. */
  for (peer = ssh_pm_peer_by_local_address(pm, p1->ike_sa->server->ip_address);
       peer != NULL;
       peer = ssh_pm_peer_next_by_local_address(pm, peer))
    {
      if (peer->use_ikev1 != 0
          && peer->local_port ==  SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa)
          && SSH_IP_EQUAL(peer->remote_ip, p1->ike_sa->remote_ip)
          && peer->remote_port == p1->ike_sa->remote_port)
        break;
    }
  if (peer == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Could not find matching peer"));
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Found matching peer 0x%lx remote %@:%d local %@:%d",
                          (unsigned long) peer->peer_handle,
                  ssh_ipaddr_render, peer->remote_ip, (int) peer->remote_port,
                  ssh_ipaddr_render, peer->local_ip, (int) peer->local_port));

  if (peer->ikev1_force_natt_draft_02 != 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Forcing IKEv1 NAT-T draft 02"));
      p1->compat_flags |= SSH_PM_COMPAT_FORCE_NAT_T_DRAFT_02;
    }
}
#endif /* SSHDIST_IKEV1 */
