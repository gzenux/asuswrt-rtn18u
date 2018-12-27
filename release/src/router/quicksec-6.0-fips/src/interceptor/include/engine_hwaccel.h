/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Prototypes and function declarations for the hardware accelerator
   API.

   File: engine_hwaccel.h

   Description:

   The implementation of these functions is platform-dependent and can
   be found from the "interceptor" source code directory. The stub
   routines are located in the hwaccel_stubs.c file.


   * About implementing hardware accelerator drivers *

   There are two levels of possible hardware accelerator API
   abstractions

   1. The ipsec-transform
   2. The combined-transform

   The ipsec-transform (1) should be used when the accelerator chip
   does only the de/encryption and/or MAC calculation, eg. 3DES, SHA-1
   or MD5.

   The combined-transform (2) should only be used when the hardware
   accelerator does the entire IPsec transformation, including the
   ESP/AH/IPIP header and trailer processing for the packet.

   If you are writing a hardware accelerator from scratch, you will
   need to implement only a subset of the API functions described in
   this header, depending whether the driver implements (1) or (2).
   Other functions should return NULL (or should not be reached).

   The hardware acceleration operations are all totally controlled by
   Engine, so that when a call to the ssh_hwaccel_alloc_ipsec() (1) is
   made by Engine, the driver should setup a HW session with the
   chip and return an accelerator-specific hardware accelerator
   context.

   The call to ssh_hwaccel_alloc_ipsec() is followed by an arbitrary
   number of (0 - n) calls to the ssh_hwaccel_perform_ipsec()
   function. A packet is passed with this function call to the
   driver, which should process the packet 3DES, SHA-1, etc... and
   call the completion callback when finished.  The driver should
   implement the necessary queuing mechanisms or locking and the
   interrupt handling for the packets.

   (For PCI bus prototyping, there is a convenient API available for
   this purpose in the the ipsec/hwaccel/sshpcihw.h header file
   with implementations for VxWorks 5.4 BSP.)

   The session is destroyed by Engine when it calls the
   ssh_hwaccel_free() function. Engine implements reference
   counting so that there cannot be any packets in the accelerator
   driver when a call to this function is made. The driver should free
   all the resources related to this HW session allocated by the
   ssh_hwaccel_alloc_ipsec() call.

   Example drivers are available in the ipsec/hwaccel directory.
*/

#ifndef ENGINE_HWACCEL_H
#define ENGINE_HWACCEL_H

#include "interceptor.h"

/*  Definitions for possible HW accelerator operation result codes. */
typedef enum {
  SSH_HWACCEL_OK          = 0x0000, /** All fine. */
  SSH_HWACCEL_CONGESTED   = 0x0001, /** Congestion or no space. */
  SSH_HWACCEL_ICV_FAILURE = 0x0002, /** ICV check for packet failed. */
  SSH_HWACCEL_PAD_FAILURE = 0x0004, /** Self describing padding is invalid. */
  SSH_HWACCEL_SEQ_FAILURE = 0x0008, /** Packet was replayed. */
  SSH_HWACCEL_UNSUPPORTED = 0x0010, /** Unsupported operation. */
  SSH_HWACCEL_FAILURE     = 0x8000  /** Catch-all failure. */
} SshHWAccelResultCode;


/** This type represents a hardware acceleration context.  Such a
    context is allocated when a transform data object is created for a
    transform and hardware acceleration is supported for the transform.
    The implementation of the context is platform-specific. */
typedef struct SshHWAccelRec *SshHWAccel;


/* Combined hardware acceleration flags. */
/** Hardware acceleration flag: decapsulate. */
#define SSH_HWACCEL_COMBINED_FLAG_DECAPSULATE  0x0001
/** Hardware acceleration flag: encapsulate. */
#define SSH_HWACCEL_COMBINED_FLAG_ENCAPSULATE  0x0002
/** Hardware acceleration flag: require IPv6. */
#define SSH_HWACCEL_COMBINED_FLAG_REQUIRE_IPV6 0x0004
/** Hardware acceleration flag: Authentication Header. */
#define SSH_HWACCEL_COMBINED_FLAG_AH           0x0010
/** Hardware acceleration flag: Encapsulating Security Payload. */
#define SSH_HWACCEL_COMBINED_FLAG_ESP          0x0020
/** Hardware acceleration flag: IP Payload Compression Protocol. */
#define SSH_HWACCEL_COMBINED_FLAG_IPCOMP       0x0040
/** Hardware acceleration flag: IPIP. */
#define SSH_HWACCEL_COMBINED_FLAG_IPIP         0x0080
/** Hardware acceleration flag: long seq. */
#define SSH_HWACCEL_COMBINED_FLAG_LONGSEQ      0x0100
/** Hardware acceleration flag: NAT-Traversal. */
#define SSH_HWACCEL_COMBINED_FLAG_NATT         0x0200
/** Hardware acceleration flag: antireplay. */
#define SSH_HWACCEL_COMBINED_FLAG_ANTIREPLAY   0x0400
/** Hardware acceleration flag:  set the DF bit on encapsulation. */
#define SSH_HWACCEL_COMBINED_FLAG_DF_SET       0x0800
/** Hardware acceleration flag:  clear the DF bit on encapsulation. */
#define SSH_HWACCEL_COMBINED_FLAG_DF_CLEAR     0x1000

/** Allocate a hardware acceleration context for combination of IPsec
    transformations.

    The 'flags' parameter determines whether the instance is to be
    used for decapsulation or encapsulation, as well as the types of
    transforms to perform. The order of transforms is fixed, in
    decryption order NATT-AH->ESP->IPcomp->IPIP (and reverse
    encryption order).

    The 'flags_return' parameter indicates which of the requested
    services were provided. Ones that were not provided need to be
    taken care at the software before/after the the combined transform
    has been applied, or the returned accelerated transform must be
    dropped.

    The {ah,esp,ipcomp,ipip}_ parameters should be used only if
    the relevant bit is set in the 'flags' bitmask.

    If using counter mode encryption, the cipher nonce is contained in
    the 'esp_iv' buffer. For cbc mode of encryption , 'esp_iv' should be
    ignored.

    If the `seq_num_low' is non-zero, the initial 32-bit ESP sequence
    number should be set to the value given by the parameter. If the
    hw-accelerator cannot set the initial ESP sequence number to the
    given value (other than zero) this function should return NULL. For
    64-bit seq-numbers the `seq_num_high' represents the higher 32 bits
    of the 64-bit sequence number. The `seq_num_high' should be ignored
    if the flag SSH_HWACCEL_COMBINED_FLAG_LONGSEQ is not set.

    If the flag SSH_HWACCEL_COMBINED_FLAG_NATT is set, NAT traversal
    encapsulation as defined in RFC 3948 should be performed. The
    destination port in the UDP header is 'natt_remote_port', the source
    port is always 4500. If transport mode is being used, then the original
    addresses used for updating upper layer checksums are encoded in
    'natt_oa_l' and 'natt_oa_r'. The number of bytes in 'natt_oa_l' and
    'natt_oa_r' is 16 for IPv6 and 4 for IPv4. */

SshHWAccel ssh_hwaccel_alloc_combined(SshInterceptor interceptor,

                                      SshUInt32 flags,
                                      SshUInt32 *flags_return,

                                      SshUInt32 ah_spi,
                                      const char *ah_macname,
                                      const unsigned char *ah_authkey,
                                      size_t ah_authkeylen,

                                      SshUInt32 esp_spi,
                                      const char *esp_macname,
                                      const char *esp_ciphname,
                                      const unsigned char *esp_authkey,
                                      size_t esp_authkeylen,
                                      const unsigned char *esp_ciphkey,
                                      size_t esp_ciphkeylen,
                                      const unsigned char *esp_iv,
                                      size_t esp_ivlen,

                                      SshUInt32 ipcomp_cpi,
                                      const char *ipcomp_compname,

                                      SshIpAddr ipip_src, SshIpAddr ipip_dst,
                                      SshUInt32 seq_num_low,
                                      SshUInt32 seq_num_high,

                                      SshUInt16 natt_remote_port,
                                      const unsigned char *natt_oa_l,
                                      const unsigned char *natt_oa_r);


/** Free the combined hardware acceleration context.  The engine
    guarantees that no operations will be in progress using the context
    when this is called. */
void ssh_hwaccel_free_combined(SshHWAccel accel);


/** This function is called to update information in the transform
    context 'accel'. This function is called by the engine code when it is
    detected that the SA's tunnel IP addresses or remote NAT-T port has
    changed. The new IP addresses and remote NAT-T port are provided as
    parameters to this call. It is legal for this call to change the address
    family of the tunnel headers i.e. a change from IPv4 to IPv6. It is also
    legal that this call may change the NAT-T status of this tunnel. If NAT-T
    UDP encapsulation should not be enabled for the updated SA the
    'natt_remote_port' parameter is zero.

    Returns SSH_HWACCEL_OK if the transform context was successfully
    updated. */
SshHWAccelResultCode
ssh_hwaccel_update_combined(SshHWAccel accel,
                            SshIpAddr ipip_src,
                            SshIpAddr ipip_dst,
                            SshUInt16 natt_remote_port);


/** Allocate a hardware acceleration context for IPsec transformations
    (or more generally, encryption and/or message authentication
    transformations).  The allocated context can be used for
    encryption/decryption, message authentication, or both in a single
    operation.  If both are performed in a single operation, encryption
    is always performed before message authentication, and decryption
    after message authentication.

    If using counter mode encryption, the cipher nonce is contained in
    the 'cipher_nonce' buffer. For cbc mode of encryption ,
    'cipher_nonce' should be ignored.

    @return
    Returns a hardware acceleration context (platform-specific), or
    NULL if no hardware acceleration is available for the supplied
    combination of parameters.

    */









SshHWAccel ssh_hwaccel_alloc_ipsec(SshInterceptor interceptor,
                                   Boolean  encrypt,
                                   const char * cipher_name,
                                   const unsigned char * cipher_key,
                                   size_t cipher_key_len,
                                   const unsigned char * cipher_nonce,
                                   size_t cipher_nonce_len,
                                   Boolean ah_style_mac,
                                   const char * mac_name,
                                   const unsigned char * mac_key,
                                   size_t mac_key_len);

/** Allocate a hardware acceleration context for
    compression/decompression using algorithm specified at
    'compression_name'. This context is assumed to be used for the
    IPCOMP transformation.

    Compression operations can change the length of the packet.
    Accelerated compression operations are supposed to modify the
    length of the packet object; however, they are not expected to
    modify fields of the IPsec header etc. - such modifications will be
    performed by the callback function after the hardware accelerated
    operation completes.

    @return
    Returns a hardware acceleration context, or NULL if no hardware
    acceleration is available for the specified algorithm.

    */

SshHWAccel ssh_hwaccel_alloc_ipcomp(SshInterceptor interceptor,
                                    Boolean compress,
                                    const char *compression_name);

/** Free the hardware acceleration context. The engine guarantees that
    no operations will be in progress using the context when this is
    called. */

void ssh_hwaccel_free(SshHWAccel accel);

/** A function of this type must be called to complete the processing
    of a hardware acceleration request.  This callback function must
    be called regardless of whether hardware acceleration was
    successful or not.

    This function continues the processing of the packet and
    eventually arranges to free the packet (e.g., by sending it to the
    network).

    The platform-specific code that calls this function must be
    careful to ensure that this function is only called in an
    environment that is compatible with the concurrency control
    mechanisms used in the rest of the engine. */

typedef void (*SshHWAccelCompletion)(SshInterceptorPacket pp,
                                     SshHWAccelResultCode status,
                                     void *context);

/* Performs hardware-accelerated processing of a set of IPsec
   transforms and calls the provided callback to indicate result. See
   function ssh_hwaccel_alloc_combined for details. */

void ssh_hwaccel_perform_combined(SshHWAccel accel,
                                  SshInterceptorPacket pp,
                                  SshHWAccelCompletion completion,
                                  void *completion_context);


/** Perform hardware-accelerated processing for an IPsec
    transformation.  This function is called for each packet if a
    hardware acceleration context has been successfully allocated for
    the transform.  The hardware acceleration context 'accel' stores
    the algorithms, keys, and other relevant information for processing
    the individual packets.  The hardware acceleration context also
    specifies whether encryption or decryption is to be performed.

    On chips that store multiple contexts directly on the chip (e.g.,
    multiple key schedules and IVs), the hardware acceleration context
    may contain an index to the appropriate hardware context.  The
    software implementing this API must manage the loading and
    offloading of contexts to/from the hardware.

    Conceptually this function arranges for 'pp' to be freed.
    Typically this happens by calling the completion function, which
    will arrange for the packet to be eventually freed. Calling the
    completion function is always mandatory; if the packet is freed in
    this function, then the completion function must be called with
    NULL as the packet.

    If the hardware is capable of generating the IV, it should place the
    IV in the first cipher block at the offset specified by
    'encrypt_iv_offset'. If the hardware is not capable of generating a
    unpredictable IV, an acceptable alternative is to generate the IV by
    encrypting the first cipher block at the offset specified by
    'encrypt_iv_offset'. It is guaranteed that this cipher block is
    unique for each packet and it contains some weak entropy, thus
    encrypting this block will give a unpredictable IV.

    The callback function can be called either immediately before this
    function returns, or at some later time asynchronously with other
    operations.  However, it must be called at an execution level
    compatible with the rest of the code used in the TCP/IP stack and
    the packet processing Engine to ensure that concurrency control
    assumptions in the rest of the code are not violated.

    Note: The implementation should be careful to cope with all
    possible alignments and segmentations of data within the
    platform-specific packet structure. */

void ssh_hwaccel_perform_ipsec(SshHWAccel accel,
                               SshInterceptorPacket pp,
                               size_t encrypt_iv_offset,
                               size_t encrypt_len_incl_iv,
                               size_t mac_start_offset,
                               size_t mac_len,
                               size_t icv_offset,
                               SshHWAccelCompletion completion,
                               void *completion_context);


/** Perform hardware-accelerated compression/decompression.  This
    function compresses/decompresses a portion of 'pp' as specified by
    the hardware acceleration context.  As a result of the
    compression/decompression operation, the specified portion of the
    packet is replaced by the compressed/decompressed version.  This
    changes the total length of the packet.

    This function is only expected to perform the
    compression/decompression operation.  This should not attempt to
    modify the IP header or any other data outside the range to be
    processed.

    The callback function can be called either immediately before this
    function returns, or at some later time asynchronously with other
    operations.  However, it must be called at an execution level
    compatible with the rest of the code used in the TCP/IP stack and
    the packet processing Engine to ensure that concurrency control
    assumptions in the rest of the code are not violated.

    Note: On some platforms, the internal packet structure may
    consists of multiple segments (and may even contain empty
    segments).  The implementation must be careful not to make any
    assumptions about the layout of the packet (except what is
    guaranteed by the platform-specific packet structure
    implementation).

    Typically the range to be compressed/decompressed will cover
    almost all of the packet.  It may be desirable to implement this
    function so that it creates a new packet object, copies data up to
    the specified into it, then compresses/decompresses data into the
    new packet, and finally appends any data from the original packet
    beyond the portion that was compressed/decompressed.  Finally, the
    original packet would be freed and the new packet passed to the
    completion function. */

void ssh_hwaccel_perform_ipcomp(SshHWAccel accel,
                                SshInterceptorPacket pp,
                                size_t offset,
                                size_t len,
                                SshHWAccelCompletion completion,
                                void *completion_context);




/** Structure for storing big integers. */
typedef struct SshHWAccelBigIntRec
{
  /** A pointer to the value array. */
  SshUInt32 *v;
  /** The size in bytes. */
  SshUInt32 size;
  /** The size in bits of the integer. */
  SshUInt32 size_in_bits;
} *SshHWAccelBigInt, SshHWAccelBigIntStruct;

/** This callback will be called when the ssh_hwaccel_perform_modexp()
    operation completes, with the result and the callback_context.

    The result will be only available for the duration of the callback
    function. The callback function must make a copy of the result if
    further processing is required.

    @return
    If the operation fails the result will be NULL.

    */
typedef void (*SshHWAccelModPCompletion)(const SshHWAccelBigInt result,
                                         void *callback_context);

/** Perform the hardware accelerated modexp operation.

    If the operation succeeds, the completion callback will be called
    with the result and the callback context. The caller is
    responsible for freeing all the required structures passed as
    parameter to this function.

   */
void ssh_hwaccel_perform_modp(const SshHWAccelBigInt b,
                              const SshHWAccelBigInt e,
                              const SshHWAccelBigInt m,
                              SshHWAccelModPCompletion callback,
                              void *callback_context);


/** This callback will be called when the ssh_hwaccel_get_random_bytes
    operation completes, with the random bytes returned in the buffer
    'random_bytes'.

    The random bytes will be only available for the duration of the
    callback function. The callback function must make a copy of the
    random bytes if further processing is required.

    @return
    If the operation fails the random_bytes buffer will be NULL.

   */
typedef void
(*SshHWAccelRandomBytesCompletion)(const unsigned char *random_bytes,
                                   size_t random_bytes_length,
                                   void *callback_context);


/** Attempts to get 'bytes_requested' random bytes from the hardware
    accelerator. The caller must supply the callback which
    is called when the provider has obtained the random bytes.

    Note: The number of random bytes returned in the callback may be
    less than 'bytes_requested'.

   */
void ssh_hwaccel_get_random_bytes(size_t bytes_requested,
                                  SshHWAccelRandomBytesCompletion callback,
                                  void *callback_context);


/** Load the hardware accelerator driver during module load and IPsec
    startup.

    @return
    Returns TRUE on success, FALSE on failure.

    */
Boolean ssh_hwaccel_init(void);

/** Unload the hardware accelerator driver during module unload and
    IPsec shutdown. */
void ssh_hwaccel_uninit(void);
#endif /* ENGINE_HWACCEL_H */
