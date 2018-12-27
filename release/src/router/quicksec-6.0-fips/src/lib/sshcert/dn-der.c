/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Distinguished name DER presentation encoding and decoding.
*/

#include "sshincludes.h"

#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshasn1.h"
#include "x509.h"
#include "dn.h"
#include "sshstr.h"
#include "sshglobals.h"

#include <ctype.h>

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertDNDer"

SSH_GLOBAL_DECLARE(SshX509ConfigStruct, ssh_x509_library_configuration);
#define ssh_x509_library_configuration \
  SSH_GLOBAL_USE(ssh_x509_library_configuration);


int ssh_dn_decode_rdn(SshAsn1Context context,
                      SshAsn1Node data,
                      SshRDN *rdn,
                      SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node rdn_comp, value;
  SshRDN prev_rdn, temp_rdn = NULL, first = NULL;
  SshCharset charset;
  unsigned char *temp_str = NULL;
  size_t temp_str_length;
  unsigned int which;

  if (config == NULL)
    config = &ssh_x509_library_configuration;

  status =
    ssh_asn1_read_node(context, data,
                       "(set (*)"
                       "  (any ()))", /* list of RDN components. */
                       &rdn_comp);

  if (status != SSH_ASN1_STATUS_OK || rdn_comp == NULL)
    goto failed;

  for (prev_rdn = NULL; rdn_comp; rdn_comp = ssh_asn1_node_next(rdn_comp))
    {
      /* Allocate new RDN for the simple C style structure system. */
      if ((temp_rdn = ssh_rdn_alloc(NULL, SSH_CHARSET_PRINTABLE, NULL, 0))
          == NULL)
        goto failed;

      /* Try to parse the ASN.1 */
      status =
        ssh_asn1_read_node(context, rdn_comp,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (any ()))",
                           &temp_rdn->oid,
                           &value);
      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_rdn_free(temp_rdn);
          goto failed;
        }

      /* Parse the string! Although I have become to the understanding that
         using this syntax is not optimal, it is rather robust. Perhaps
         faster implementation would choose to take the tag numbers of
         the node directly? */
      status =
        ssh_asn1_read_node(context, value,
                           "(choice"
                           "  (printable-string ())"
                           "  (teletex-string ())"
                           "  (bmp-string ())"
                           "  (universal-string ())"
                           "  (utf8-string ())"
                           "  (ia5-string ())"
                           "  (bit-string ())"
                           "  (visible-string ()))",
                           &which,
                           &temp_str, &temp_str_length,
                           &temp_str, &temp_str_length,
                           &temp_str, &temp_str_length,
                           &temp_str, &temp_str_length,
                           &temp_str, &temp_str_length,
                           &temp_str, &temp_str_length,
                           &temp_str, &temp_str_length,
                           &temp_str, &temp_str_length);

      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_rdn_free(temp_rdn);
          goto failed;
        }

      /* The following types conform the PKIX draft standard and allows
         some extensions be also used. */

      switch (which)
        {
        case 0:
          /* We allow Latin1 characters in printable string input, as
             many systems generate such. We do not. */
          if (config->cs.treat_printable_as_latin1)
            charset = SSH_CHARSET_ISO_8859_1;
          else
            charset = SSH_CHARSET_PRINTABLE;
          break;
        case 1:
          if (config->cs.treat_t61_as_latin1)
            charset = SSH_CHARSET_ISO_8859_1;
          else
            charset = SSH_CHARSET_T61;
          break;
        case 2:
          charset = SSH_CHARSET_BMP;
          break;
        case 3:
          charset = SSH_CHARSET_UNIVERSAL;
          break;
        case 4:
          charset = SSH_CHARSET_UTF8;
          break;
        case 5:
          charset = SSH_CHARSET_ISO_8859_1;
          break;
        case 6:
          if (config->cs.enable_printable_within_bitstring)
            {
#define SSH_VRK_UID "2.5.4.45"

              charset = SSH_CHARSET_ISO_8859_1;
              if (ssh_usstrcmp(temp_rdn->oid, SSH_VRK_UID) == 0)
                {
                  SshAsn1Tree tree;

                  if ((status =
                       ssh_asn1_decode(context,
                                       (const unsigned char *)temp_str,
                                       (temp_str_length + 7) / 8,
                                       &tree)) == SSH_ASN1_STATUS_OK)
                    {
                      if ((status =
                           ssh_asn1_read_tree(context, tree,
                                              "(printable-string ())",
                                              &temp_str,
                                              &temp_str_length))
                          == SSH_ASN1_STATUS_OK)
                        {
                          charset = SSH_CHARSET_PRINTABLE;
                          break;
                        }
                    }
                  ssh_free(temp_str);
                  ssh_rdn_free(temp_rdn);
                  goto failed;
                }
            }
          else
            {
              charset = SSH_CHARSET_ISO_8859_1;
              temp_str_length = (temp_str_length + 7)/8;
              break;
            }
          break;

        case 7:
          charset = SSH_CHARSET_VISIBLE;
          break;
        default:
          ssh_free(temp_str);
          ssh_rdn_free(temp_rdn);
          goto failed;
        }

      if ((temp_rdn->c =
           ssh_str_make(charset, temp_str, temp_str_length))
          ==  NULL)
        {
          if (temp_str_length > 0)
            {
              ssh_rdn_free(temp_rdn);
              goto failed;
            }
        }

      /* Link to the previous rdn. */
      if (prev_rdn)
        prev_rdn->next = temp_rdn;
      else
        first = temp_rdn;

      prev_rdn = temp_rdn;
    }

  *rdn = first;
  return 1;
failed:

  ssh_rdn_free(first);
  return 0;
}

/* This should work by just using the ASN.1 code. */
int
ssh_dn_decode_der(const unsigned char *der, size_t der_len, SshDN dn,
                  SshX509Config config)
{
  SshAsn1Context context;
  SshAsn1Tree    dn_tree;
  SshAsn1Node    rdn_node;
  SshAsn1Status  status;
  SshRDN first;
  Boolean found;
  int rv = 0;

  /* Initialize the ASN.1 parser context. */
  context = ssh_asn1_init();
  if (context == NULL)
    return 0;

  /* Decode the Distinguished name. */
  status = ssh_asn1_decode(context, der, der_len, &dn_tree);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  /* Decode the higher layer. */
  status =
    ssh_asn1_read_tree(context, dn_tree,
                       "(sequence (*)"
                       "  (optional"
                       "    (any ())))", /* The list of RDN's. */
                       &found, &rdn_node);

  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  if (found == FALSE)
    {
      ssh_dn_clear(dn);
      goto success;
    }

  first = NULL;
  for (; rdn_node; rdn_node = ssh_asn1_node_next(rdn_node))
    {
      if (ssh_dn_decode_rdn(context, rdn_node, &first, config) == 0)
        {
          if (first)
            ssh_rdn_free(first);
          ssh_dn_clear(dn);
          goto failed;
        }

      /* Now add to the main DN. */
      if (first)
        {
          if (!ssh_dn_put_rdn(dn, first))
            {
              ssh_rdn_free(first);
              goto failed;
            }
        }
      first = NULL;
    }
success:
  rv = 1;

failed:
  ssh_asn1_free(context);
  return rv;
}

typedef struct SshRdnPreferredCharsetRec
{
  const char *oid;
  SshCharset charset;
} SshRdnPreferredCharset;

const SshRdnPreferredCharset ssh_rdn_preferred_charsets[] =
{
  { "1.2.840.113549.1.9.1", SSH_CHARSET_US_ASCII },      /* MAILTO */
  { "1.2.840.113549.1.9.2", SSH_CHARSET_US_ASCII },      /* unstructuredName */
  { "0.9.2342.19200300.100.1.3", SSH_CHARSET_US_ASCII }, /* uclMailTo */
  { "0.9.2342.19200300.100.1.25", SSH_CHARSET_US_ASCII },/* domainComponent */
  { "1.2.840.113549.1.9.7", SSH_CHARSET_PRINTABLE },     /* challengePassword*/
  { "2.5.4.5", SSH_CHARSET_PRINTABLE},                   /* serialNumber */
  { "2.5.4.46", SSH_CHARSET_PRINTABLE },                 /* DNQ */
  { NULL }
};

SshCharset ssh_dn_charset_get_by_oid(const unsigned char *oid)
{
  int i;
    for (i = 0; ssh_rdn_preferred_charsets[i].oid != NULL; i++)
    {
      if (ssh_usstrcmp(oid, ssh_rdn_preferred_charsets[i].oid) == 0)
        return ssh_rdn_preferred_charsets[i].charset;
    }
    return SSH_CHARSET_ANY;
}

/* Figure out the string type of the given string, e.g. the smallest set of
   characters it can be fit into.

   Returns a newly allocated string which contains the original string
   converted to the new charset. The set of charsets where to convert
   is taken from PKIX, and is supported due following reasons;

     Printable set is compact and easy to print.
     BMP set is only 2 octets wide an reasonably simple
     UTF-8 set is compact for most sets and spans the full UCS-4 range.

   Only necessary is the UTF-8 which always should be
   available. However, if that fails then there is a bug in the
   library.  */
SshStr ssh_dn_string_convert(SshStr str,
                             SshCharset preferred,
                             SshX509Config config)
{
  SshStr converted;

  if (preferred != SSH_CHARSET_ANY)
    {
      converted = ssh_str_charset_convert(str, preferred);
      return converted;
    }

  converted = ssh_str_charset_convert(str, SSH_CHARSET_PRINTABLE);
  if (converted)
    return converted;

  if (config->cs.enable_visible_string)
    {
      converted = ssh_str_charset_convert(str, SSH_CHARSET_VISIBLE);
      if (converted)
        return converted;
    }
  if (config->cs.enable_bmp_string)
    {
      converted = ssh_str_charset_convert(str, SSH_CHARSET_BMP);
      if (converted)
        return converted;
    }

  converted = ssh_str_charset_convert(str, SSH_CHARSET_UTF8);
  if (converted)
    return converted;

  SSH_DEBUG(SSH_D_FAIL,
            ("String was not of the claimed character set (a guess)."));
  return NULL;
}


SshAsn1Node ssh_dn_encode_rdn(SshAsn1Context context,
                              SshRDN rdn,
                              Boolean canonical,
                              SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node rdn_node, rdn_comp, string_node = NULL, rdn_out;
  SshRDN temp_rdn;
  SshStr  converted;
  unsigned char *temp_str;
  size_t temp_str_length;
  SshCharset preferred;

  if (config == NULL)
    config = &ssh_x509_library_configuration;

  for (temp_rdn = rdn, rdn_node = NULL;
       temp_rdn;
       temp_rdn = temp_rdn->next)
    {
      /* Convert to suitable representation. */
      preferred = ssh_dn_charset_get_by_oid(temp_rdn->oid);
      converted = ssh_dn_string_convert(temp_rdn->c, preferred, config);
      if (converted == NULL)
        goto failed;

      if (!canonical)
        temp_str = ssh_str_get(converted, &temp_str_length);
      else
        temp_str = ssh_str_get_canonical(converted, &temp_str_length);

      if (temp_str == NULL)
        {
          ssh_str_free(converted);
          goto failed;
        }

      /* Find the ASN.1 representation. */
      switch (ssh_str_charset_get(converted))
        {
        case SSH_CHARSET_PRINTABLE:
          status =
            ssh_asn1_create_node(context, &string_node,
                                 "(printable-string ())",
                                 temp_str, temp_str_length);
          break;
        case SSH_CHARSET_VISIBLE:
          if (config->cs.enable_visible_string)
            status =
              ssh_asn1_create_node(context, &string_node,
                                   "(visible-string ())",
                                   temp_str, temp_str_length);
          else
            status = SSH_ASN1_STATUS_UNKNOWN_COMMAND;
          break;
        case SSH_CHARSET_US_ASCII:
          status =
            ssh_asn1_create_node(context, &string_node,
                                 "(ia5-string ())",
                                 temp_str, temp_str_length);
          break;
        case SSH_CHARSET_BMP:
          if (config->cs.enable_visible_string)
            status =
              ssh_asn1_create_node(context, &string_node,
                                   "(bmp-string ())",
                                   temp_str, temp_str_length);
          else
            status = SSH_ASN1_STATUS_UNKNOWN_COMMAND;
          break;
        case SSH_CHARSET_UTF8:
          status =
            ssh_asn1_create_node(context, &string_node,
                                 "(utf8-string ())",
                                 temp_str, temp_str_length);
          break;
        default:
          ssh_str_free(converted);
          ssh_free(temp_str);
          goto failed;
          break;
        }

      if (config->cs.enable_printable_within_bitstring)
        {
          /* FOR Finnish authority VRK pilot cards, made using Swedish ID2
             PKI platform. They put printable-strings within bit-strings,
             and even worse, the printable strings can contain actual
             latin1 characters. */
          if (ssh_usstrcmp(temp_rdn->oid, SSH_VRK_UID) == 0)
            {
              unsigned char *another_str;
              size_t another_str_len;

              if (ssh_str_charset_get(converted) != SSH_CHARSET_PRINTABLE)
                {
                  ssh_str_free(converted);
                  ssh_free(temp_str);
                  goto failed;
                }

              status = ssh_asn1_node_get_data(string_node,
                                              &another_str, &another_str_len);
              if (status != SSH_ASN1_STATUS_OK)
                {
                  ssh_str_free(converted);
                  ssh_free(temp_str);
                  goto failed;
                }

              status =
                ssh_asn1_create_node(context, &string_node,
                                     "(bit-string ())",
                                     another_str, another_str_len*8);
              ssh_free(another_str);

              if (status != SSH_ASN1_STATUS_OK)
                {
                  ssh_str_free(converted);
                  ssh_free(temp_str);
                  goto failed;
                }
            }
        }

      /* Free data not necessary to keep. */
      ssh_str_free(converted);
      ssh_free(temp_str);

      /* Check for error in ASN.1 code. */
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      status =
        ssh_asn1_create_node(context, &rdn_comp,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (any ()))",
                             temp_rdn->oid,
                             string_node);

      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      /* Now insert the new component into the RDN set. */
      if (rdn_node != NULL)
        /* Add to the list. */
        ssh_asn1_add_list(rdn_node, rdn_comp);
      else
        rdn_node = rdn_comp;
    }
  /* We should now have nice rdn_node available. */
  if ((status = ssh_asn1_create_node(context, &rdn_out,
                                     "(set () (any ()))", rdn_node))
      != SSH_ASN1_STATUS_OK)
    goto failed;

  return rdn_out;
failed:
  return NULL;
}

static int
dn_encode_der_internal(SshDN dn,
                       Boolean canonical,
                       unsigned char **der, size_t *der_len,
                       SshX509Config config)
{
  SshAsn1Context context;
  SshAsn1Node    rdn, dn_rdns, dn_name;
  SshAsn1Status  status;
  int rv, i;

  /* Initialize the ASN.1 memory allocation context. */
  if ((context = ssh_asn1_init()) == NULL)
    return 0;

  /* Lets prepare for the worst. */
  *der = NULL;
  *der_len = 0;
  rv = 0;

  for (dn_rdns = NULL, i = 0; i < dn->rdn_count; i++)
    {
      rdn = ssh_dn_encode_rdn(context, dn->rdn[i], canonical, config);
      if (rdn == NULL)
        goto failed;

      /* Add to the list of sets. */
      if (dn_rdns != NULL)
        ssh_asn1_add_list(dn_rdns, rdn);
      else
        dn_rdns = rdn;
    }
  /* Now finalize the Distinguished Name! */
  status =
    ssh_asn1_create_node(context, &dn_name,
                         "(sequence ()"
                         "  (any ()))",
                         dn_rdns);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  status =
    ssh_asn1_encode_node(context, dn_name);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  status = ssh_asn1_node_get_data(dn_name, der, der_len);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  /* Everything was a success, happily so. */
  rv = 1;
failed:
  ssh_asn1_free(context);

  return rv;
}

int ssh_dn_encode_der_canonical(SshDN dn,
                                unsigned char **der, size_t *der_len,
                                SshX509Config config)
{
  return dn_encode_der_internal(dn, TRUE, der, der_len, config);
}

int ssh_dn_encode_der(SshDN dn,
                      unsigned char **der, size_t *der_len,
                      SshX509Config config)
{
  return dn_encode_der_internal(dn, FALSE, der, der_len, config);
}
#endif /* SSHDIST_CERT */
