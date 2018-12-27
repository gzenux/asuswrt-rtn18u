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
SshAsn1Node ssh_x509_encode_dn_name(SshAsn1Context context,
                                    SshX509NameType type,
                                    SshX509Name names,
                                    SshX509Config config)
{
  SshAsn1Tree tree;
  SshAsn1Node node;
  SshAsn1Status status;
  SshX509Name dn;

  /* Return a node to the distinguished name. */
  dn = ssh_x509_name_find(names, type);
  if (dn == NULL)
    {
      status =
        ssh_asn1_create_node(context, &node,
                             "(sequence ())");
      if (status != SSH_ASN1_STATUS_OK)
        return NULL;

      return node;
    }

  if (dn->ber == NULL)
    {
      SshDNStruct dn_name;
      unsigned char *ascii;
      size_t ascii_len;
      unsigned char *der;
      size_t der_len;

      if (dn->name == NULL)
        {
          status =
            ssh_asn1_create_node(context, &node,
                                 "(sequence ())");
          if (status != SSH_ASN1_STATUS_OK)
            return NULL;

          return node;
        }

      ascii = ssh_str_get(dn->name, &ascii_len);

      ssh_dn_init(&dn_name);
      if (ssh_dn_decode_ldap(ascii, &dn_name) == 0)
        {
          ssh_free(ascii);
          return NULL;
        }
      ssh_free(ascii);

      if (ssh_dn_encode_der(&dn_name, &der, &der_len, config) == 0)
        return NULL;
      ssh_dn_clear(&dn_name);

      if (ssh_asn1_decode(context, der, der_len, &tree) != SSH_ASN1_STATUS_OK)
        {
          ssh_free(der);
          return NULL;
        }
      dn->ber = der;
      dn->ber_len = der_len;
    }
  else
    {
      if (ssh_asn1_decode(context, dn->ber,
                          dn->ber_len, &tree) != SSH_ASN1_STATUS_OK)
        return NULL;
    }
  return ssh_asn1_get_root(tree);
}
/* Encode general name */
SshAsn1Node ssh_x509_encode_general_name(SshAsn1Context context,
                                         SshX509Name names,
                                         SshX509Config config)
{
  SshAsn1Node node, tmp;
  SshAsn1Status status = SSH_ASN1_STATUS_OPERATION_FAILED;
  unsigned char *ascii;
  size_t ascii_len;

  if (names == NULL)
    return NULL;

  node = NULL;
  switch (names->type)
    {
    case SSH_X509_NAME_RFC822:
      ascii = ssh_str_get(names->name, &ascii_len);
      status = ssh_asn1_create_node(context, &node,
                                    "(ia5-string (1))",
                                    ascii, ascii_len);
      ssh_free(ascii);
      break;
    case SSH_X509_NAME_DNS:
      ascii = ssh_str_get(names->name, &ascii_len);
      status = ssh_asn1_create_node(context, &node,
                                    "(ia5-string (2))",
                                    ascii, ascii_len);
      ssh_free(ascii);
      break;
    case SSH_X509_NAME_URI:
      ascii = ssh_str_get(names->name, &ascii_len);
      status = ssh_asn1_create_node(context, &node,
                                    "(ia5-string (6))",
                                    ascii, ascii_len);
      ssh_free(ascii);
      break;
    case SSH_X509_NAME_IP:
      status = ssh_asn1_create_node(context, &node,
                                    "(octet-string (7))",
                                    names->data, names->data_len);
      break;
    case SSH_X509_NAME_DISTINGUISHED_NAME:
    case SSH_X509_NAME_DN:
      tmp = ssh_x509_encode_dn_name(context, names->type, names, config);
      status = ssh_asn1_create_node(context, &node, "(any (e 4))", tmp);
      break;
    case SSH_X509_NAME_RID:
      status = ssh_asn1_create_node(context, &node,
                                    "(object-identifier (8))",
                                    names->data);
      break;
    case SSH_X509_NAME_PRINCIPAL_NAME:
      {
        const SshOidStruct *upn_oid =
          ssh_oid_find_by_std_name_of_type("UPN",
                                           SSH_OID_OTHERNAME);

        if (upn_oid == NULL)
          return NULL;

        ascii = ssh_str_get(names->name, &ascii_len);
        status = ssh_asn1_create_node(context, &node,
                                      "(sequence (0)"
                                      "  (object-identifier ())"
                                      "  (utf8-string (e 0)))",
                                      upn_oid->oid,
                                      ascii, ascii_len);
      }
    break;
    case SSH_X509_NAME_GUID:
      {
        const SshOidStruct *oid =
          ssh_oid_find_by_std_name_of_type("GUID", SSH_OID_OTHERNAME);

        if (oid == NULL)
          return NULL;

        status = ssh_asn1_create_node(context, &node,
                                      "(sequence (0)"
                                      "  (object-identifier ())"
                                      "  (octet-string (e 0)))",
                                      oid->oid, names->data, names->data_len);
      }
    break;
    case SSH_X509_NAME_OTHER:
    case SSH_X509_NAME_EDI:
    case SSH_X509_NAME_X400:
    case SSH_X509_NAME_UNIQUE_ID:
      /* Not yet implemented. */
      return NULL;
      break;
    }

  if (status != SSH_ASN1_STATUS_OK)
    return NULL;

  /* Return the node found. */
  return node;
}

SshAsn1Node ssh_x509_encode_general_name_list(SshAsn1Context context,
                                              SshX509Name names,
                                              SshX509Config config)
{
  SshAsn1Node list, node;

  list = NULL;
  for (; names; names = names->next)
    {
      node = ssh_x509_encode_general_name(context, names, config);
      if (node == NULL)
        continue;

      list = ssh_asn1_add_list(list, node);
    }
  return list;
}

/* Encode general names */
SshAsn1Node ssh_x509_encode_general_names(SshAsn1Context context,
                                          SshX509Name names,
                                          SshX509Config config)
{
  SshAsn1Node gen_names, node;
  SshAsn1Status status;

  if (names == NULL)
    return NULL;

  gen_names = ssh_x509_encode_general_name_list(context, names, config);
  if (gen_names == NULL)
    return NULL;

  status =
    ssh_asn1_create_node(context, &node,
                         "(sequence ()"
                         "  (any ()))",
                         gen_names);
  if (status != SSH_ASN1_STATUS_OK)
    return NULL;
  return node;
}
#endif /* SSHDIST_CERT */
