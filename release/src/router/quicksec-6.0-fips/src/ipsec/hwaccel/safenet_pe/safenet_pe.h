/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Prototypes and function declarations for the Safenet Packet Engine (PE)
   API.

   This PE API is purposed to be used in the QuickSec glue layer for
   look-aside hardware accelerators, namely for those that use either UDM
   driver or SLAD driver to communicate with particular hardware.
   So the whole picture should look like this:

                      Transform
                          |
                          |
                         \|/
      QS HW accelerator API (engine_accel.h) interface
                         /_\
                         / \
                        /   \
                       /     \
                      /       \
      look-aside glue layer   other glue layers
           using PE API        for other boards or older implementations
           (safenet_la.c)             |
              /         \             |
            \//         \\/           |
    PE API interface (safenet_pe.h)   |
            /             \           |
         405EX.c          440EPX.c    |
   (implementation of        \        |
     PE API for 405EX board)  \       |
           |                   \      |
          \|/                  \\/   \|/
        SLAD driver            UDM driver
           |                        |
           |                        |
       405EX board            440EPX board (for example)


   The implementation of PE API functions is board-dependent and can
   be found in the "hwaccel/safenet_pe" source code directory under
   board specific names, such as 405EX.c, 440EPX.c.

   The main idea behind the introduction and use of PE API is that
   the file safenet_la.c includes calls to the PE API interface using
   "know when, but don't know how" principle.
   405EX.c implementation "knows how" for the 405EX board using SLAD driver.
*/

#ifndef SAFENET_PE_H
#define SAFENET_PE_H

#include "sshincludes.h"

/* Packet Engine operation result codes */
typedef enum
{
  PE_PKT_STATUS_OK          = 0x0000, /** All fine */
  PE_PKT_STATUS_CONGESTED   = 0x0001, /** Congestion or no space */
  PE_PKT_STATUS_ICV_FAILURE = 0x0002, /** ICV check for packet failed */
  PE_PKT_STATUS_PAD_FAILURE = 0x0004, /** Self describing padding is invalid */
  PE_PKT_STATUS_SEQ_FAILURE = 0x0008, /** Packet was replayed */
  PE_PKT_STATUS_UNSUPPORTED = 0x0010, /** Unsupported operation */
  PE_PKT_STATUS_FAILURE     = 0x8000  /** Catch all failure. */
} PE_PKT_STATUS;


/* Packet Engine options for building correct SAs */
typedef enum
{
 PE_FLAGS_ESP        =   0x0001, /* format SA for ESP transform */
 PE_FLAGS_AH         =   0x0002, /* format SA for AH transform  */
 PE_FLAGS_TUNNEL     =   0x0004, /* construct outer IP header if required */
 PE_FLAGS_IPV6       =   0x0008, /* require IPv6 support */
 PE_FLAGS_OUTBOUND   =   0x0010,
 /* format SA for outbound packets (encapsulate) */
 PE_FLAGS_AES        =   0x0020,
 PE_FLAGS_NATT       =   0x0040,
 PE_FLAGS_ANTIREPLAY =   0x0080,
 PE_FLAGS_DF_SET     =   0x0100,
 PE_FLAGS_DF_CLEAR   =   0x0200,
 PE_FLAGS_AES_CBC    =   0x0400,
 PE_FLAGS_DES_CBC    =   0x0800,
} PE_FLAGS;


/******** Packet Engine common packet descriptor **********/

/* This structure defines a common packet descriptor format,
   which is used for passing a packet for processing to Packet Engine
   with safenet_pe_pktput and safenet_pe_pktget functions.
   Note:
   Here in fields descriptions:
   in - means that a field should be set when calling the safenet_pe_pktput()
   function.
   out - means that a field can be read after calling the safenet_pe_pktget()
   function.
*/
typedef struct
{
  /* in / out: protocol ID of the next header of the packet */
  uint32_t next_header;

  /* out: status of the processed packet */
  PE_PKT_STATUS status;

  /* in / out: starting address for the packet to be processed */
  void *src;

  /* in / out: total source (src) packet length (bytes) */
  size_t src_len;

  /* in / out: specifies the starting address to write the result packet data
     from the requested operation */
  void *dst;

  /* in / out: total result (dst) packet length (bytes) */
  size_t dst_len;

  /* in: pointer to sa (and other sa-related data) for this packet */
  void *sa_data;

  /* in: length of the sa and related data */
  size_t sa_data_len;

  /* in: copy of flags from the current transform context */
  PE_FLAGS flags;

  /* in / out: free-form user data, not touched by PE API */
  void *user_handle;

  /* Copy of IV and ICV sizes of current transform context */
  uint16_t iv_size;
  uint16_t icv_size;
} PE_PKT_DESCRIPTOR;

#define PE_MAX_DEVICES 2


/* Packet-is-ready notification structure */
typedef struct
{
  /* for USER MODE of Packet Engine software */
  uint32_t process_id;
  uint32_t signal_number;
  /* for KERNEL MODE of Packet Engine software */
  void (*callback) (int );
} PE_NOTIFY;


/* Device initialization data */
typedef struct
{
  PE_NOTIFY device_callback;
  int found;
  uint32_t device_number;
} PE_DEVICE_INIT;

/******** PE INIT/DEINIT **********/

/* Accelerator-specific initialization function.
   Finds all accelerators, builds corresponding init blocks and initializes
   the driver.

   device_init - an array of glue layer callback functions, which should be
   called when
   packets are processed by the Packet Engine and ready to be received.

   device_count - as input is an expected number of accelerator devices and
   the size of the device_init[],
   this value should be big enough to possibly provide callbacks for a
   maximum number of devices.

   device_count - as output is a number of actually found accelerator devices.

   Returns TRUE if at least one accelerator device is found and there are no
   errors.
*/
Boolean
safenet_pe_init(PE_DEVICE_INIT device_init[], SshUInt32 *device_count);

/* Accelerator-specific de-initialization function. */
void
safenet_pe_uninit(SshUInt32 device_num);


/******** SA ALLOC API **********/

/* SA formats supported by Packet Engine */
typedef enum
{
  PE_SA_TYPE_AH,
  PE_SA_TYPE_ESP
} PE_SA_TYPE;

/* Cipher algorithms supported by Packet Engine
*/
typedef enum
{
  PE_CIPHER_ALG_DES = 0x00000000,
  PE_CIPHER_ALG_TDES = 0x00000001,
  PE_CIPHER_ALG_ARC4 = 0x00000002,
  PE_CIPHER_ALG_AES = 0x00000003,
  PE_CIPHER_ALG_AES_CTR = 0x00000004,
  PE_CIPHER_ALG_NULL = 0x0000000f
} PE_CIPHER_ALG;


/* Hash algorithms supported by Packet Engine
*/
typedef enum
{
  PE_HASH_ALG_MD5 = 0x00000000,
  PE_HASH_ALG_SHA1 = 0x00000001,
  PE_HASH_ALG_SHA256 = 0x00000003,
  PE_HASH_ALG_SHA384 = 0x00000004,
  PE_HASH_ALG_SHA512 = 0x00000005,
  PE_HASH_ALG_GHASH = 0x0000000c,

  /* The following algorithm is needed to support
     the AES-GCM (Galois/Counter Mode) variant with
     64-bit Integrity Check Value (ICV) as
     the encryption algorithm.*/
  PE_HASH_ALG_GHASH_64 = 0x0000001c,

  PE_HASH_ALG_GMAC = 0x0000000d,
  PE_HASH_ALG_NULL = 0x0000000f
} PE_HASH_ALG;


/* SA parameters supported by Packet Engine
*/
typedef struct
{
  uint32_t spi;             /* security parameters index for this SA */
  uint32_t seq;
  /* initial ESP sequence number to be set in the SA */
  PE_CIPHER_ALG ciph_alg;   /* cipher algorithm (see PE_CIPHER_ALG) */
  PE_HASH_ALG hash_alg;     /* hash algorithm (see PE_HASH_ALG) */
  unsigned char *ciph_key;  /* cipher key */
  size_t ciph_key_len;      /* cipher key length */
  unsigned char *mac_key;   /* key for an authentication algorithm */
  size_t mac_key_len;
  /* length of the key for an authentication algorithm */
  /* if using counter mode encryption, the cipher nonce is contained in
    the 'esp_iv' buffer. For cbc mode of encryption , 'esp_iv' should be
    ignored.*/
  unsigned char *esp_iv;
  size_t esp_ivlen;
} PE_SA_PARAMS;


/* Allocates memory and builds SAs and related data for AH or ESP transforms
  type      - in: for which transforms to build the SA (AH, ESP)
  flags     - in: transform options for building the SA
  sa_params - in: parameters for building the SA (algorithms, keys,
              other items), see PE_SA_PARAMS
  sa_data   - out: pointer to a memory block with initialized SA data
  Returns TRUE if successful.
*/
Boolean
safenet_pe_build_sa(int device_num, PE_SA_TYPE type,
		    PE_FLAGS flags, PE_SA_PARAMS *sa_params,
		    void** sa_data);

/* Frees any memory allocated with safenet_pe_build_sa for SAs
   and related data for AH or ESP transforms
   sa_data   - in: pointer to a memory block with SA data
*/
void
safenet_pe_destroy_sa(const void* sa_data);

/******** PKTGET/PKTPUT API **********/

/* Use this to put packets to be processed to the Packet Engine
   pkt points to a PE_PKT_DESCRIPTOR array for the packet
   to be sent to the Packet Engine for processing.
   Returns a number of packets sucessfully sent to the Packet Engine.
*/
int
safenet_pe_pktput(int device_num, PE_PKT_DESCRIPTOR pkt[], SshUInt32 count);

/* Use this to get completed packets from the Packet Engine
   The function returns PE_PKT_DESCRIPTOR objects in pkt if the
   packets were successfully processed by the Packet Engine and available for
   receiving.
   pcount is an output parameter and is the number of packets received.
   Returns FALSE if the packets cannot be received because of the Packet
   Engine error.
*/
Boolean
safenet_pe_pktget(int device_num, PE_PKT_DESCRIPTOR pkt[], SshUInt32 *pcount);

#endif /*SAFENET_PE_H*/


