/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DN name encoding and decoding.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "oid.h"

#ifdef SSHDIST_CERT

SshX509Status
ssh_x509_decode_dn_name(SshAsn1Context context,
                        SshAsn1Node data,
                        SshX509NameType type,
                        SshX509Name *names,
                        SshX509Config config)
{
  SshX509Name dn_name;
  SshStr      str_ldap = NULL;
  unsigned char *ber;
  size_t ber_len;
  SshDN dn;

  if (data == NULL)
    return SSH_X509_OK;

  /* Get ber, and get LDAP name. */
  if (ssh_asn1_node_get_data(data, &ber, &ber_len) != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILURE;

  if ((dn = ssh_dn_create(ber, ber_len, config)) == NULL)
    {
      ssh_free(ber);
      return SSH_X509_FAILURE;
    }

  if (ssh_dn_empty(dn))
    {
      ssh_dn_clear(dn);
      ssh_free(ber);
      ssh_free(dn);
      return SSH_X509_OK;
    }

#if 0
  /* Do not pre-compute this information, it is not typically needed
     that much and is pretty costly. */
  if (ssh_dn_encode_ldap_str(dn, &str_ldap) == 0 || str_ldap == NULL)
    {
      ssh_dn_clear(dn);
      ssh_free(ber);
      ssh_free(dn);
      return SSH_X509_FAILURE;
    }
#endif

  dn_name = ssh_x509_name_alloc(type,
                                dn, str_ldap,
                                NULL, 0,
                                ber, ber_len);

  ssh_x509_name_push(names, dn_name);
  return SSH_X509_OK;
}

/* Decode general name */
SshX509Status
ssh_x509_decode_general_name(SshAsn1Context context,
                             SshAsn1Node    name,
                             SshX509Name   *names,
                             SshX509Config  config)
{
  SshAsn1Status status;
  SshStr namestr;
  unsigned char *str = NULL, *der = NULL, *data;
  char *tmp_oid = NULL;
  size_t str_len, derlen, datalen;
  unsigned int which;
  SshAsn1Node other_name, x400_name, directory_name, edi_party_name;
  char *registered_id;
  SshX509Name new_name;
  SshDN dn;
  SshX509NameType type = SSH_X509_NAME_OTHER;

  /* Get here for easy reference. */
  ssh_asn1_node_get_data(name, &der, &derlen);

  /* See if we can decode the value correctly. Another approach,
     which would be faster, is where we just see the tag for a
     fit. Implement later if need arises, or performance seems
     poor. */
  status =
    ssh_asn1_read_node(context, name,
                       "(choice"
                       "  (any (0))"
                       "  (ia5-string (1))"
                       "  (ia5-string (2))"
                       "  (any (3))"
                       "  (any (e 4))"
                       "  (any (5))"
                       "  (ia5-string (6))"
                       "  (octet-string (7))"
                       "  (object-identifier (8)))",
                       &which,
                       &other_name,
                       &str, &str_len,
                       &str, &str_len,
                       &x400_name,
                       &directory_name,
                       &edi_party_name,
                       &str, &str_len,
                       &str, &str_len,
                       &registered_id);

  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_free(der);
      return SSH_X509_FAILED_ASN1_DECODE;
    }

  dn = NULL;
  namestr = NULL;
  data = NULL; datalen = 0;
  new_name = NULL;

  /* This is not perhaps the best way to implement this. */
  switch (which)
    {
    case 0:
      /* First check whether this is the only OtherName case which
       * we can handle properly: the Microsoftian Principal Name */
      type = SSH_X509_NAME_OTHER;
      status = ssh_asn1_read_node(context, name,
                                  "(sequence (0)"
                                  " (object-identifier ())"
                                  " (utf8-string (e 0)))",
                                  &tmp_oid,
                                  &str, &str_len);
      if (status == SSH_ASN1_STATUS_OK)
        {
          SshStr upn;
          const SshOidStruct *upn_oid =
            ssh_oid_find_by_std_name_of_type("UPN", SSH_OID_OTHERNAME);

          upn = ssh_str_make(SSH_CHARSET_UTF8, str, str_len);

          if (upn_oid &&
              (strcmp(tmp_oid, upn_oid->oid) == 0) &&
              upn != NULL)
            {
              ssh_free(tmp_oid);
              tmp_oid = NULL;
              ssh_free(der);
              namestr = upn;
              der = NULL; derlen = 0;
              type = SSH_X509_NAME_PRINCIPAL_NAME;
              break;
            }

          ssh_free(tmp_oid);
          tmp_oid = NULL;
          ssh_free(upn);
        }

      /* Other Microsoft OtherName: Global Unique Identifier. */
      status = ssh_asn1_read_node(context, name,
                                  "(sequence (0)"
                                  " (object-identifier ())"
                                  " (octet-string (e 0)))",
                                  &tmp_oid,
                                  &str, &str_len);
      if (status == SSH_ASN1_STATUS_OK)
        {
          const SshOidStruct *oid =
            ssh_oid_find_by_std_name_of_type("GUID", SSH_OID_OTHERNAME);

          if (oid && (strcmp(tmp_oid, oid->oid) == 0))
            {
              ssh_free(tmp_oid);
              tmp_oid = NULL;
              ssh_free(der);
              data = str; datalen = str_len;
              der = NULL; derlen = 0;
              type = SSH_X509_NAME_GUID;
              break;
            }
          else
            {
              ssh_free(tmp_oid);
              tmp_oid = NULL;
              ssh_free(str);
              /* Fallthru */
            }
        }

      /* This is some otherName unknown to us. */
      status = ssh_asn1_read_node(context, name,
                                  "(sequence (0)"
                                  " (object-identifier ())"
                                  " (any (e 0)))",
                                  &tmp_oid, &other_name);
      if (status == SSH_ASN1_STATUS_OK)
        {
          namestr = ssh_str_make(SSH_CHARSET_US_ASCII,
                              (unsigned char *)tmp_oid, strlen(tmp_oid));
          ssh_asn1_node_get_data(other_name, &data, &datalen);
        }
      else
        {
          ; /* Make othername from der at tmp */
        }
      break;
    case 1:
      type = SSH_X509_NAME_RFC822;
      namestr = ssh_str_make(SSH_CHARSET_US_ASCII, str, str_len);
      break;
    case 2:
      type = SSH_X509_NAME_DNS;
      namestr = ssh_str_make(SSH_CHARSET_US_ASCII, str, str_len);
      break;
    case 3: type = SSH_X509_NAME_X400; break;
    case 4:
      type = SSH_X509_NAME_DN;
      ssh_free(der); der = NULL;
      if (ssh_x509_decode_dn_name(context,
                                  directory_name,
                                  type,
                                  &new_name,
                                  config)
          != SSH_X509_OK)
        {
          return SSH_X509_FAILURE;
        }
      break;
    case 5: type = SSH_X509_NAME_EDI; break;
    case 6:
      type = SSH_X509_NAME_URI;
      namestr = ssh_str_make(SSH_CHARSET_US_ASCII, str, str_len);
      break;
    case 7:
      type = SSH_X509_NAME_IP;
      data = str; datalen = str_len;
      break;
    case 8:
      type = SSH_X509_NAME_RID;
      data = (unsigned char *)registered_id;
      datalen = 0;
      break;
    default:
      ssh_free(der); der = NULL;
      return SSH_X509_FAILURE;
      /* Error */
    }

  if (new_name == NULL && which != 4)
    new_name = ssh_x509_name_alloc(type,
                                   dn, namestr,
                                   data, datalen,
                                   der, derlen);

  ssh_x509_name_push(names, new_name);
  return SSH_X509_OK;
}


SshX509Status
ssh_x509_decode_general_name_list(SshAsn1Context context,
                                  SshAsn1Node    name,
                                  SshX509Name   *names,
                                  SshX509Config  config)
{
  SshAsn1Node list;
  for (list = name; list; list = ssh_asn1_node_next(list))
    {
      if (ssh_x509_decode_general_name(context, list, names, config)
          != SSH_X509_OK)
        return SSH_X509_FAILURE;
    }
  return SSH_X509_OK;
}

/* Decode general names */
SshX509Status
ssh_x509_decode_general_names(SshAsn1Context context,
                              SshAsn1Node    data,
                              SshX509Name   *names,
                              SshX509Config  config)
{
  SshAsn1Status status;
  SshAsn1Node   names_node;

  status =
    ssh_asn1_read_node(context, data,
                       "(sequence (*)"
                       "  (any ()))",
                       &names_node);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  if (ssh_x509_decode_general_name_list(context, names_node, names, config)
      != SSH_X509_OK)
    return SSH_X509_FAILURE;
  return SSH_X509_OK;
}
#endif /* SSHDIST_CERT */
