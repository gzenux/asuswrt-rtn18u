/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   L2TP header and AVP parsing.
*/

#ifndef SSHL2TP_PARSE_H
#define SSHL2TP_PARSE_H

/*************************** L2TP header parsing ****************************/

/* Minimum length of an L2TP header. */
#define SSH_L2TPH_MIN_HDRLEN    6
#define SSH_L2TPH_CTRL_HDRLEN   12

/* Offsets of various fields in L2TP headers. */
#define SSH_L2TPH_OFS_BITS      0
#define SSH_L2TPH_OFS_VERSION   0

/* Macros for accessing L2TP header fields.  Any returned values will
   be in host byte order. */
#define SSH_L2TPH_BITS(ucp) (SSH_GET_16BIT((ucp)) >> 4)
#define SSH_L2TPH_VERSION(ucp) (SSH_GET_16BIT((ucp)) & 0x0f)

#define SSH_L2TPH_SET_VERSION_AND_BITS(ucp, v, b) \
  SSH_PUT_16BIT((ucp), (((v) & 0x000f) | ((b) << 4)))

/* L2TP header bits. */
#define SSH_L2TPH_F_PRIORITY    0x010
#define SSH_L2TPH_F_OFFSET      0x020
#define SSH_L2TPH_F_SEQUENCE    0x080
#define SSH_L2TPH_F_LENGTH      0x400
#define SSH_L2TPH_F_TYPE        0x800

#define SSH_L2TPH_F_RESERVED    0x34f

/* The supported L2TP data message header version.  Version number 1
   means L2F [RFC2341]. */
#define SSH_L2TP_DATA_MESSAGE_HEADER_VERSION 2


/**************************** AVP header parsing ****************************/

/* Minimum length of an L2TP AVP header. */
#define SSH_L2TP_AVP_HDRLEN 6

/* Offsets of various fields in L2TP AVP headers. */
#define SSH_L2TP_AVP_OFS_BITS                   0
#define SSH_L2TP_AVP_OFS_LENGTH                 0
#define SSH_L2TP_AVP_OFS_VENDOR_ID              2
#define SSH_L2TP_AVP_OFS_ATTRIBUTE_TYPE         4
#define SSH_L2TP_AVP_OFS_ATTRIBUTE_VALUE        6

/* Macros for accessing L2TP AVP header fields.  Any returned values
   will be in host byte order. */
#define SSH_L2TP_AVP_BITS(ucp) (SSH_GET_16BIT((ucp)) >> 10)
#define SSH_L2TP_AVP_LENGTH(ucp) (SSH_GET_16BIT((ucp)) & 0x03ff)
#define SSH_L2TP_AVP_VENDOR_ID(ucp) SSH_GET_16BIT((ucp) + 2)
#define SSH_L2TP_AVP_ATTRIBUTE_TYPE(ucp) SSH_GET_16BIT((ucp) + 4)

/* Macros for setting L2TP AVP header fields.  Values are in host byte
   order. */
#define SSH_L2TP_AVP_SET_BITS(ucp, v) \
  SSH_PUT_16BIT((ucp), (SSH_GET_16BIT((ucp)) & 0x03ff) | ((v) << 10))
#define SSH_L2TP_AVP_SET_LENGTH(ucp, v) \
  SSH_PUT_16BIT((ucp), (SSH_GET_16BIT((ucp)) & 0xfc00) | ((v) & 0x03ff))
#define SSH_L2TP_AVP_SET_VENDOR_ID(ucp, v) SSH_PUT_16BIT((ucp) + 2, (v))
#define SSH_L2TP_AVP_SET_ATTRIBUTE_TYPE(ucp, v) SSH_PUT_16BIT((ucp) + 4, (v))

/* AVP header bits. */
#define SSH_L2TP_AVP_F_MANDATORY        0x20
#define SSH_L2TP_AVP_F_HIDDEN           0x10
#define SSH_L2TP_AVP_F_RESERVED         0x0f

/************************* SSH defined private AVPs *************************/

/* Private enterprise code for SSH Communications Security as defined
   in `SMI Network Management Private Enterprise Codes' registry. */
#define SSH_PRIVATE_ENTERPRISE_CODE     4449

/* SSH defined AVP types.  These AVPs are valid for AVPs which have
   the SSH_PRIVATE_ENTERPRISE_CODE in the Vendor ID field in the AVP
   header. */
typedef enum
{
  /* The index of the IPsec transform that protected this message. */
  SSH_L2TP_SSH_AVP_TRANSFORM_INDEX      = 0,

  SSH_L2TP_SSH_AVP_NUM_TYPES
} SshL2tpSshAvpType;

#endif /* not SSHL2TP_PARSE_H */
