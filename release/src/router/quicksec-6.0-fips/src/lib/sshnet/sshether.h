/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Ethernet specific definitions.  This file also contains functions
   and macros for manipulating ethernet frames.
*/

#ifndef SSHETHER_H
#define SSHETHER_H

/*************************** Ethernet definitions ***************************/

/* Etherenet header size */
#define SSH_ETHERH_HDRLEN       14
#define SSH_SNAPH_HDRLEN        22

/* Field offsets for ethernet header */
#define SSH_ETHERH_OFS_DST      0
#define SSH_ETHERH_OFS_SRC      6
#define SSH_ETHERH_OFS_TYPE     12

/* Size of ethernet address */
#define SSH_ETHERH_ADDRLEN      6

/* Known values for the ethernet type field.  The same values are used for
   both ethernet (rfc894) and IEEE 802 encapsulation (the type will just
   be in a different position in the header). */
#define SSH_ETHERTYPE_IP        0x0800 /* IPv4, as per rfc894 */
#define SSH_ETHERTYPE_ARP       0x0806 /* ARP, as per rfc826 */
#define SSH_ETHERTYPE_IPv6      0x86dd /* IPv6, as per rfc1972 */
#define SSH_ETHERTYPE_REVARP    0x8035 /* Reverse ARP */
#define SSH_ETHERTYPE_NS        0x0600 /* Xerox NS (IPX, SPX, etc.) */
#define SSH_ETHERTYPE_APPLETALK 0x809b /* Appletalk */
#define SSH_ETHERTYPE_ATARP     0x80f3 /* Appletalk ARP */
#define SSH_ETHERTYPE_MACSEC    0x88e5 /* MACsec, ieee802.1ae */
#define SSH_ETHERTYPE_PAE       0x888e /* PAE EAPOL, ieee801.1af */
#define SSH_ETHERTYPE_VLAN      0x8100 /* VLAN, ieee802.1q */

/* This returns true if the given address is a hardware ethernet multicast or
   broadcast address. */
#define SSH_ETHER_IS_MULTICAST(addr) (*(addr) & 0x01)

/* Macro for accessing ethertype fields */
#define SSH_ETHERH_TYPE(ucp) SSH_GET_16BIT((ucp) + SSH_ETHERH_OFS_TYPE)

/* Macro for setting ethertype fields */
#define SSH_ETHERH_SET_TYPE(ucp, v) \
   SSH_PUT_16BIT((ucp) + SSH_ETHERH_OFS_TYPE, (v))

/*************************** 802.1Q VLAN ************************************/

/* VLAN tag size */
#define SSH_VLANH_HDRLEN          4

/* Field offsets for VLAN tag */
#define SSH_VLANH_OFS_TCI         0
#define SSH_VLANH_OFS_TYPE        2      /* Encapsulated ethertype */

/* Masks and flag values for TCI field */
#define SSH_VLANH_TCI_PCP_MASK    0xe000 /* Mask for PCP field */
#define SSH_VLANH_TCI_CFI         0x1000 /* CFI flag */
#define SSH_VLANH_TCI_VLANID_MASK 0x0fff /* Mask for VLAN ID field */

/* Macros for accessing VLAN tag fields */
#define SSH_VLANH_PCP(ucp) \
   (SSH_GET_16BIT((ucp) + SSH_VLANH_OFS_TCI) & SSH_VLANH_TCI_PCP_MASK)
#define SSH_VLANH_CFI(ucp) \
   (SSH_GET_16BIT((ucp) + SSH_VLANH_OFS_TCI) & SSH_VLANH_TCI_CFI_MASK)
#define SSH_VLANH_VLANID(ucp) \
   (SSH_GET_16BIT((ucp) + SSH_VLANH_OFS_TCI) & SSH_VLANH_TCI_VLANID_MASK)
#define SSH_VLANH_TYPE(ucp) SSH_GET_16BIT((ucp) + SSH_VLANH_OFS_TYPE)

/* Macros for setting VLAN tag fields */
#define SSH_VLANH_SET_TCI(ucp, v) \
   SSH_PUT_16BIT((ucp) + SSH_VLANH_OFS_TCI, (v))
#define SSH_VLANH_SET_TYPE(ucp, v) \
   SSH_PUT_16BIT((ucp) + SSH_VLANH_OFS_TYPE, (v))

/*************************** MACsec *****************************************/

/* MACsec tag size */
#define SSH_MACSECH_HDRLEN      8

/* Optional MACsec Secure Channel Identifier size */
#define SSH_MACSECH_SCILEN      8

/* Field offsets for MACsec tag */
#define SSH_MACSECH_OFS_TYPE    0
#define SSH_MACSECH_OFS_TCIAN   2
#define SSH_MACSECH_OFS_SL      3
#define SSH_MACSECH_OFS_PN      4
#define SSH_MACSECH_OFS_SCI     8

/* MACsec trailer */
#define SSH_MACSECH_TRAILER_LEN 16

/* Mask of TCI bits in the TCIAN octet */
#define SSH_MACSECH_TCI_MASK    0xfc

/* Flags for the TCI field */
#define SSH_MACSECH_TCI_VER     0x80   /* Version */
#define SSH_MACSECH_TCI_ES      0x40   /* End Station */
#define SSH_MACSECH_TCI_SC      0x20   /* Secure Channel identifier present */
#define SSH_MACSECH_TCI_SCB     0x10   /* Single Copy Broadcast */
#define SSH_MACSECH_TCI_E       0x08   /* Encrypt */
#define SSH_MACSECH_TCI_C       0x04   /* Changed Text */

/* Mask of AN bits in the TCIAN octet */
#define SSH_MACSECH_AN_MASK     0x03

/* Macros for accessing MACsec tag fields */
#define SSH_MACSECH_TYPE(ucp) \
   SSH_GET_16BIT((ucp) + SSH_MACSECH_OFS_TYPE)
#define SSH_MACSECH_TCI(ucp) \
   (SSH_GET_8BIT((ucp) + SSH_MACSECH_OFS_TCIAN) & SSH_MACSECH_TCI_MASK)
#define SSH_MACSECH_AN(ucp) \
   (SSH_GET_8BIT((ucp) + SSH_MACSECH_OFS_TCIAN) & SSH_MACSECH_AN_MASK)
#define SSH_MACSECH_SL(ucp) \
   SSH_GET_8BIT((ucp) + SSH_MACSECH_OFS_SL)
#define SSH_MACSECH_PN(ucp) \
   SSH_GET_32BIT((ucp) + SSH_MACSECH_OFS_PN)

/* Macros for setting MACsec tag fields */
#define SSH_MACSECH_SET_TYPE(ucp, v) \
   SSH_PUT_16BIT((ucp) + SSH_MACSECH_OFS_TYPE, (v))
#define SSH_MACSECH_SET_TCIAN(ucp, v) \
   SSH_PUT_8BIT((ucp) + SSH_MACSECH_OFS_TCIAN, (v))
#define SSH_MACSECH_SET_SL(ucp, v) \
   SSH_PUT_8BIT((ucp) + SSH_MACSECH_OFS_SL, (v))
#define SSH_MACSECH_SET_PN(ucp, v) \
   SSH_PUT_32BIT((ucp) + SSH_MACSECH_OFS_PN, (v))

#endif /* SSHETHER_H */
