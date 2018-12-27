/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Object Identifier routines.
*/

#ifndef OID_H
#define OID_H

#include "x509.h"

/* The basic Object Identifier structure.
 */
typedef struct SshOidRec
{
  /* The object identifier in usual dot separated notation. That is,
     OIDs are sequences of numbers alike 1.2.3.4.5.6.7 where each
     number is separated by a dot. There can be any number of
     numbers. Strings are used to keep the comparison of OIDs easy.

     Remember the terminating null character at the end of a OID. */
  const char    *oid;

  /* A standard X.509 name for the OID. */
  const char    *std_name;

  /* A alternate name used in some occasions. */
  const char    *name;

  /* Some type specific data. */
  const void    *extra;
  int            extra_int;
} *SshOid, SshOidStruct;

/* SshOid 'extra' data types. */
typedef struct SshOidPkRec
{
  SshX509PkAlgorithm alg_enum;
  SshX509UsageFlags  key_usage;
  SshX509UsageFlags  ca_key_usage;
} *SshOidPk, SshOidPkStruct;

typedef struct SshOidPkcs5Rec
{
  char   *hash;   /* Crypto library name for hash */
  char   *cipher; /* Crypto library name for cipher */
  size_t  keylen; /* Cipher key length in bytes */
} *SshOidPkcs5, SshOidPkcs5Struct;

typedef struct SshOidListingRec
{
  int type;
  /* The type numbers, please choose them in monotonically increasing order
     for quick retrieval of correct list from a table.                */
#define SSH_OID_PK             0  /* Public key method information.  */
#define SSH_OID_SIG            1  /* Signature method information.  */
#define SSH_OID_DN             2  /* Distinguished name            */
#define SSH_OID_EXT            3  /* Certificate extension info.  */
#define SSH_OID_CRL_EXT        4  /* CRL extension information.  */
#define SSH_OID_CRL_ENTRY_EXT  5  /* CRL extension information. */
#define SSH_OID_PKCS9          6  /* PKCS-9 identifiers        */
#define SSH_OID_CAT            7  /* Microsoft CAT extensions */
#define SSH_OID_HOLD_INST      8  /* Hold instruction codes. */
#define SSH_OID_POLICY         9  /* Policy qualifiers.     */
#define SSH_OID_PKCS7         10  /* PKCS-7 identifiers    */
#define SSH_OID_HASH          11  /* Hash algorithms.     */
#define SSH_OID_MAC           12  /* Hash algorithms.    */
#define SSH_OID_CIPHER        13  /* Secret key encipherment methods.  */
#define SSH_OID_EXT_KEY_USAGE 14  /* Extended key usage information.  */
#define SSH_OID_CONTROLS      15  /* CRMF controls   */
#define SSH_OID_CMP           16  /* CMP controls   */
#define SSH_OID_PKCS5         17  /* PKCS5 pbe1    */
#define SSH_OID_PKCS12        18  /* PKCS#12      */
#define SSH_OID_DIRECTORYATTR 19  /* SubjectDirectoryAttributes  */
#define SSH_OID_OTHERNAME     20  /* OtherNames                 */
#define SSH_OID_UCL           21  /* UCL directory pilot       */
#define SSH_OID_QCSTATEMENT   22  /* Qualified cert statement */
#define SSH_OID_ECP_CURVE     23  /* Elliptic curves modulo a prime \
                                     fixed  curves*/
#define SSH_OID_CURVE_FIELD   24  /* Elliptic curve field type */
#define SSH_OID_NONE          25  /* No extra information.   */

  const SshOidStruct *oid_list;
} *SshOidListing, SshOidListingStruct;

/* Prototypes. */

/* Find the given Object Identifier definition and returns it
   if it is known. If not known then returns NULL.
   */
const SshOidStruct *ssh_oid_find_by_oid(const char *oid);

/* Tries to find by Object Identifier which is of some type. The types
   are defined within the SshOid definition. */
const SshOidStruct *ssh_oid_find_by_oid_of_type(const unsigned char *oid,
                                                int type);

/* Tries to find by the standard X.509 name. */
const SshOidStruct *ssh_oid_find_by_std_name(const char *name);

/* Tries to find by the standard X.509 name. */
const SshOidStruct *ssh_oid_find_by_std_name_of_type(const char *name,
                                                     int type);

/* Tries to find by alternate name which might be anything. */
const SshOidStruct *ssh_oid_find_by_alt_name_of_type(const char *name,
                                                     int type);

const SshOidStruct *ssh_oid_find_by_alt_name(const char *name);

/* Tries to find by extra name, which is not necessarily present, but
   with some types might be. */
const SshOidStruct *ssh_oid_find_by_ext_name(const char *name);

/* Tries to find by extra name, which is not necessarily present, but
   with some types might be. */
const SshOidStruct *ssh_oid_find_by_ext_name_of_type(const char *name,
                                                     int type);

/* Find oid by the identifier amongs oids of type. (for example when
   SshX509PkAlgorithm is known the corresponding oid can be found). */
const SshOidStruct *ssh_oid_find_by_ext_ident_of_type(int ident, int type);

/* Checks if oid is syntaxically valid. Returns TRUE if valid, FALSE
   otherwise. */
Boolean ssh_oid_check_str(const unsigned char *oid_str);

#endif /* OID_H */
