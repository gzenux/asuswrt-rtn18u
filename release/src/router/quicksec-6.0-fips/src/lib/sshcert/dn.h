/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Distinguished name encoding/decoding interface.
*/

#ifndef DN_H
#define DN_H

#include "sshstr.h"
#include "sshasn1.h"

#ifndef SSH_DNIO_CHARSET
/* The default distinguished name I/O charset is ISO latin-1, as most
   western operating systems are aware of it. We apologize for the bias
   towards western (and especially European) character sets.

   Hopefully in future we can all use UTF-8.
   */
/* Map teletex character set to... */
#define SSH_DNIO_TELETEX_MAP_TO SSH_CHARSET_T61

/* Define this if you really want to use visible strings in distinguished
   names. If this is present the library will attempt always first to
   convert output to visible strings than to BMP or UTF8. If this
   define is not available then visible strinsg and decoded properly, but
   will not be encoded. */
/*
#define SSH_DN_USE_VISIBLE
*/

#endif

/* Internal representation of a Relative Distinguished Name. */
typedef struct SshRDNRec
{
  struct SshRDNRec *next;

  /* The object identifier. */
  unsigned char *oid;

  /* The contents. */
  SshStr         c;
} *SshRDN, SshRDNStruct;

/* Internal representation of a Distinguished Name. */
typedef struct SshDNRec
{
  unsigned int rdn_count;
  SshRDN      *rdn;

  /* Original is stored here if available. This means that
     no conversions need to be done, and at most once anyway. */
  char          *ldap;
  unsigned char *der;
  size_t         der_len;
} *SshDN, SshDNStruct;

/* Routine for handling distinguished names. */

/* Initialization of a DN. This should be called before any DN operations
   with 'dn'. */
void ssh_dn_init(SshDN dn);

/* Clearing of the data structures of a DN. This should be called
   after 'dn' is not used anymore to free the acquired memory. */
void ssh_dn_clear(SshDN dn);

/* Routine to check the validity of an DN. If DN is not valid that is it
   is not really conformant with X.521 then it returns 0. However, you
   might aswell ignore it because most implementations do not care
   about being valid in this sense.

   All names that you generate should pass this tests to keep the
   internet from going into total chaos! */
int ssh_dn_is_valid(SshDN dn);

/* Check whether the DN is defined (or is empty). */
int ssh_dn_empty(SshDN dn);

/* Own comparison function for allowing both lower and upper case to
   pass. */
int ssh_dn_memcmp(const unsigned char *a, const unsigned char *b, size_t len);

/* Basic Distinguished name functions. */

/* Within LDAP DN routines as well as DER DN's we always keep the
   original order of the DN. (Although alterations might appear within
   DER encodings because of sorting within SET's, but this is unavoidable.)

   Hope here is to have generic DN handling for all use.

   It is recommended that applications use LDAP DN's for simplicity and
   because their more nicer out look (and the fact that they can express
   all DN's).
   */

/* Following functions return 0 in case of an error and non-zero in
   case of success. */

/* Decoding of a LDAP DN into C data structure DN. */
int ssh_dn_decode_ldap(const unsigned char *ldap_dn, SshDN dn);

/* Decode LDAP DN given in SshStr structure. */
int ssh_dn_decode_ldap_str(const SshStr str, SshDN dn);

/* Decode LDAP DN given in specific character set. */
int ssh_dn_decode_ldap_cs(SshCharset cs, const unsigned char *ldap_dn,
                          SshDN dn);

/* Encoding of an C data structure DN into LDAP DN. */
int ssh_dn_encode_ldap(SshDN dn, char **ldap_dn);

/* Convert DN structure into UTF-8 SshStr string. */
int ssh_dn_encode_ldap_str(SshDN dn, SshStr *str);

/* Convert DN structure into C string in given character set. */
int ssh_dn_encode_ldap_cs(SshDN dn, SshCharset cs, char **ldap_dn);

/* Decode and encode DER DN's. */
int ssh_dn_decode_der(const unsigned char *der, size_t der_len,
                      SshDN dn,
                      SshX509Config config);

int ssh_dn_encode_der(SshDN dn, unsigned char **der, size_t *der_len,
                      SshX509Config config);
int ssh_dn_encode_der_canonical(SshDN dn,
                                unsigned char **der, size_t *der_len,
                                SshX509Config config);

/* Switch between the LDAP order and the BER order. */
void ssh_dn_reverse(SshDN dn);

/* Routines which handle separate RDN's e.g. in ASN.1 DER. */

/* Decode a RDN from ASN.1. */
int ssh_dn_decode_rdn(SshAsn1Context context,
                      SshAsn1Node data,
                      SshRDN *rdn,
                      SshX509Config config);
/* Encode a RDN to ASN.1. */
SshAsn1Node
ssh_dn_encode_rdn(SshAsn1Context context,
                  SshRDN rdn,
                  Boolean canonical,
                  SshX509Config config);

/* Allocation of a RDN, given suitable amount of extra information.
   This can build only a RDN containing one part, multi-part RDN's are
   also possible. */
SshRDN ssh_rdn_alloc(unsigned char *oid,
                     SshCharset charset,
                     unsigned char *c, size_t c_len);
/* Free a RDN. */
void ssh_rdn_free(SshRDN rdn);

/* Routines for handling the last RDN which is sometimes needed in
   applications. The RDN is not allocate again, thus a care needs to be
   taken here. */
Boolean ssh_dn_put_rdn(SshDN dn, SshRDN rdn);
SshRDN ssh_dn_take_last_rdn(SshDN dn);

SshRDN ssh_rdn_copy(SshRDN rdn);

/* Find RDN by the oid. Oid must be in the number format (i.e 1.2.3.4, not as
   string "SN"). Returns NULL if there is no entry matching to oid. The SshRDN
   returned is shared with the SshDN and it is valid as long as dn given to
   this function is valid and is not modified. */
SshRDN ssh_find_rdn_by_oid(SshDN dn, const char *oid);

/* Convert to the representation wanted and after that return a ASN.1 DER
   encoded blob. */
Boolean ssh_str_get_der(SshAsn1Context context,
                        SshStr str, SshCharset charset,
                        SshAsn1Node *node);

/* Create DN from given BER encoding at 'der'. Use configuration
   'config' when parsing the encoding (allows bug compatibility on
   strings) */
SshDN ssh_dn_create(const unsigned char *der, size_t der_len,
                    SshX509Config config);

/* Compare two ASN1 encoded buffers based on the contents of their
   string representations. Return 0 on match and -1 in case of error
   or mismatch. */
int ssh_dn_char_str_cmp(unsigned char *first_buffer,
                        size_t first_buffer_size,
                        unsigned char *second_buffer,
                        size_t second_buffer_size);
#endif /* DN_H */
