/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for IKE/IPsec algorithm functionality.
*/

#ifndef UTIL_ALGORITHMS_INTERNAL_H
#define UTIL_ALGORITHMS_INTERNAL_H


/** A cipher algorithm. */
struct SshPmCipherRec
{
  /** Bit mask, using the values from the `quicksec_pm.h' for selecting this
     encryption algorithm. */
  SshUInt32 mask_bits;

  /** The name of the algorithm. */
  char *name;

  /** The allowed minimum and maximum key sizes (in bits) for the
     algorithm. */
  SshUInt32 min_key_size;
  SshUInt32 max_key_size;

  /** The default key size (in bits) we use when we are initiating
     using this algorithm. */
  SshUInt32 default_key_size;

  /** They increment of the key size for variable key size algorithms.
     This has the value 0 for fixed key size ciphers. */
  SshUInt32 key_increment;

  /** The cipher block size (in bits). This is used for calculating the
      padding length for outbound packets. For counter mode and NULL
      algorithms this is the pad boundary required by ESP. For other
      algorithms this is the cipher output block size. */
  SshUInt32 block_size;

  /** The size (in bits) of the cipher iv that is sent on the wire. For cbc
     mode this is always equal to the cipher block size. For counter mode,
     the iv size is usually less than the cipher block size. */
  SshUInt32 iv_size;

  /** The size in bits of the nonce that this cipher may use. Only non-zero
     for counter mode encryption.  */
  SshUInt32 nonce_size;

  /** The IKE ESP transform identifiers for this encryption
     algorithm. */
  SshIkev2TransformID esp_transform_id;

  /** The IKE encryption algorithm identifier for this cipher. */
  SshIkev2TransformID ike_encr_transform_id;
};

typedef struct SshPmCipherRec SshPmCipherStruct;
typedef struct SshPmCipherRec *SshPmCipher;

/** A MAC algorithm. */
struct SshPmMacRec
{
  /** Bit mask, using the values from the `quicksec_pm.h' for selecting this
     MAC algorithm. Use array element 0 for ESP/IKE and array element 1
     for AH. */
  SshUInt32 mask_bits[2];

  /** The name of the algorithm. */
  char *name;

  /* The digest size in bits of the MAC */
  SshUInt32 digest_size;

  /** The allowed minimum and maximum key sizes (in bits) for the
     algorithm. */
  SshUInt32 min_key_size;
  SshUInt32 max_key_size;

  /** The default key size (in bits) we use when we are initiating
     using this algorithm. */
  SshUInt32 default_key_size;

  /** The increment of the key size for variable key size algorithms.
     This has the value 0 for fixed key size MACs. */
  SshUInt32 key_increment;

  /** The size (in bits) of the iv that is sent on the wire. Only non-zero
      for counter mode macs. */
  SshUInt32 iv_size;

  /** The size in bits of the nonce that this mac may use. Only non-zero
      for counter mode macs.  */
  SshUInt32 nonce_size;

  /** The IPsec transform identifier for this MAC algorithm. */
  SshIkev2TransformID ipsec_transform_id;

  /** The IKE Integrity transform identifier for this MAC algorithm. */
  SshIkev2TransformID ike_auth_transform_id;

  /** The IKE authentication algorithm identifier for this MAC
     algorithms. */
  SshIkev2TransformID ike_prf_transform_id;

  /** Is there more IPsec transform identifiers for this
      MAC algorithms? (MAC algorithms are layed out so that
      first one does not contain identifier at all
      (as there is no common identifier for MAC, but separate
      identifiers for each possible keysize), but
      only size range, then the next entries contain
      identifiers for different sizes). */
  Boolean more_ipsec_transform_ids;

  /* Is this super entry possibly containing some children or standalone entry.
     Subentries of super entry have this flag set as false. */
  Boolean master_flag;
};

typedef struct SshPmMacRec SshPmMacStruct;
typedef struct SshPmMacRec *SshPmMac;

/** A compression algorithm. */
struct SshPmCompressionRec
{
  /** Bit mask, using the values from the `quicksec_pm.h' for selecting this
     compression algorithm. */
  SshUInt32 mask_bits;

  /** The name of the algorithm. */
  char *name;

  /** The IKE IPComp transform identifier for this compression
     algorithm. */
  SshIkev2IPCompTypes ipcomp_transform_id;
};

typedef struct SshPmCompressionRec SshPmCompressionStruct;
typedef struct SshPmCompressionRec *SshPmCompression;

/** A Diffie-Hellman group. */
struct SshPmDHGroupRec
{
  /** Bit mask, using the values from the `quicksec_pm.h' for selecting this
     Diffie-Hellman group. */
  SshUInt32 mask_bits;

  /** The IKE group description number. 0xffff is end of array marker. */
  SshUInt16 group_desc;

  /** The group size in bits. */
  SshUInt16 group_size;

 /** The preference value for this group. */
  SshUInt8 preference;
};

typedef struct SshPmDHGroupRec SshPmDHGroupStruct;
typedef struct SshPmDHGroupRec *SshPmDHGroup;

/** Algorithm properties. */
struct SshPmAlgorithmPropertiesRec
{
  struct SshPmAlgorithmPropertiesRec *next;

  /** Algorithm specifier and usage flags for this properties structure. */
  SshUInt32 algorithm;

  /** Properties. */
  SshUInt32 min_key_size;
  SshUInt32 max_key_size;
  SshUInt32 default_key_size;
};

typedef struct SshPmAlgorithmPropertiesRec SshPmAlgorithmPropertiesStruct;
typedef struct SshPmAlgorithmPropertiesRec *SshPmAlgorithmProperties;


/* ******************************* Algorithms ********************************/

/** Check if the group represented by the integer 'group' is known to the
   system. Known groups are of the form SSH_PM_DH_GROUP_* as defined in
   ipsec_pm.h. Returns TRUE if the group is known and FALSE otherwise. */
Boolean ssh_pm_dh_group_is_known(SshUInt32 group);

/** Count the number of algorithms the tunnel attributes `algorithms'
   and `dhflags' specify for IKE SA.  The function returns TRUE if all
   algorithms were known and FALSE otherwise. */
Boolean ssh_pm_ike_num_algorithms(SshPm pm,
                                  SshUInt32 algorithms, SshUInt32 dhflags,
                                  SshUInt32 *num_ciphers_return,
                                  SshUInt32 *num_hashes_return,
                                  SshUInt32 *num_dh_groups_return);

/** Count the number of algorithms the transform `transform' specifies
   for IPSec SA.  The function returns TRUE if all algorithms were
   known and FALSE otherwise. */
Boolean ssh_pm_ipsec_num_algorithms(SshPm pm,
                                    SshPmTransform transform,
                                    SshUInt32 dhflags,
                                    SshUInt32 *num_ciphers_return,
                                    SshUInt32 *num_macs_return,
                                    SshUInt32 *num_compressions_return,
                                    SshUInt32 *num_dh_return);

/** Return the `index'th IKE encryption algorithm matching the algorithm
   specification `algorithms'. */
SshPmCipher ssh_pm_ike_cipher(SshPm pm, SshUInt32 index, SshUInt32 algorithms);

/** Return the `index'th IPSec encryption algorithm matching the algorithm
   specification `algorithms'. */
SshPmCipher ssh_pm_ipsec_cipher(SshPm pm, SshUInt32 index,
                                SshUInt32 algorithms);

/* Return the `index'th IPSec encryption algorithm matching the transform id
   `id'. */
SshPmCipher ssh_pm_ipsec_cipher_by_id(SshPm pm, SshIkev2TransformID id);


/** Return the `index'th IKE MAC algorithm matching the algorithm
   specification `algorithm'. */
SshPmMac ssh_pm_ike_mac(SshPm pm, SshUInt32 index, SshUInt32 algorithm);

/** Return the `index'th IPSec MAC algorithm matching the algorithm
   specification `algorithm'. */
SshPmMac ssh_pm_ipsec_mac(SshPm pm, SshUInt32 index, SshUInt32 algorithm);

/** Return the `index'th IPSec MAC algorithm matching the transform ID `id'. */
SshPmMac ssh_pm_ipsec_mac_by_id(SshPm pm, SshIkev2TransformID id);

/** Return the `index'th compression algorithm matching the transform
   specification `transform'. */
SshPmCompression ssh_pm_compression(SshPm pm,
                                    SshUInt32 index, SshPmTransform transform);

/** Return the `index'th Diffie-Hellman group matching DH flags
   `dhflags'. */
SshPmDHGroup ssh_pm_dh_group(SshPm pm, SshUInt32 index, SshUInt32 dhflags);

/** Return the size of the Diffie-Hellman group `group_desc'. */
SshUInt16 ssh_pm_dh_group_size(SshPm pm, SshUInt16 group_desc);

/** A predicate to check if the cipher has fixed key length. */
Boolean ssh_pm_cipher_is_fixed_key_length(SshPmCipher cipher);

/** A predicate to check if the mac has fixed key length. */
Boolean ssh_pm_mac_is_fixed_key_length(SshPmMac mac);

/** Return the cipher key sizes for the tunnel `tunnel'.  If any of the
   `{min,max,default,increment}_key_size_return' is NULL, the corresponding
   value is not returned. */
void ssh_pm_cipher_key_sizes(SshPmTunnel tunnel,
                             SshPmCipher cipher,
                             SshUInt32 scope,
                             SshUInt32 *min_key_size_return,
                             SshUInt32 *max_key_size_return,
                             SshUInt32 *increment_key_size_return,
                             SshUInt32 *default_key_size_return);

/** Return the MAC key sizes for the tunnel `tunnel'.  If any of the
   `{min,max,default,increment}_key_sizes_return' is NULL, the corresponding
   value is not returned. */
void ssh_pm_mac_key_sizes(SshPmTunnel tunnel,
                          SshPmMac mac,
                          SshUInt32 scope,
                          SshUInt32 *min_key_size_return,
                          SshUInt32 *max_key_size_return,
                          SshUInt32 *increment_key_size_return,
                          SshUInt32 *default_key_size_return);

/** Return IPSec Authentication algorithm ID for given MAC and key_size.
    If no such algorithm is found, zero is returned. */
SshIkev2TransformID
ssh_pm_mac_auth_id_for_keysize(SshPmMac mac, SshUInt32 key_size);

/** Return IKE Authentication algorithm ID for given MAC and key_size.
    If no such algorithm is found, zero is returned. */
SshIkev2TransformID
ssh_pm_mac_ike_auth_id_for_keysize(SshPmMac mac, SshUInt32 key_size);

/** Return IKE PRF algorithm ID for given MAC and key_size.
    If no such algorithm is found, zero is returned. */
SshIkev2TransformID
ssh_pm_mac_ike_prf_id_for_keysize(SshPmMac mac, SshUInt32 key_size);

/** Computes the maxiumum number of bytes that the IPsec transform
    (as specified by the input parameters 'transform', 'is_ipv6',
    'cipher' and 'mac') adds to packets when performing outbound
    transforms. */
SshUInt8
ssh_pm_compute_trd_packet_enlargement(SshPm pm,
                                      SshPmTransform transform,
                                      Boolean is_ipv6,
                                      SshPmCipher cipher,
                                      SshPmMac mac);

#endif /* not UTIL_ALGORITHMS_INTERNAL_H */
