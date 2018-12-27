/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements PKCS#6 handling. It is intented to be used only
   with PKCS#7.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshasn1.h"
#include "x509.h"
#include "oid.h"
#include "x509internal.h"
#include "pkcs6.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshPkcs6"

void ssh_pkcs6_crl_init(SshPkcs6Crl crl)
{
  crl->crl = ssh_x509_crl_allocate();
  crl->ber_buf = NULL;
  crl->ber_length = 0;
}

void ssh_pkcs6_crl_free(SshPkcs6Crl crl)
{
  ssh_x509_crl_free(crl->crl);
  ssh_free(crl->ber_buf);
  ssh_free(crl);
}

void ssh_pkcs6_cert_init(SshPkcs6Cert cert)
{
  cert->extended    = FALSE;
  cert->certificate = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  cert->attr        = ssh_glist_allocate();
  cert->signature   = NULL;
  cert->signature_length = 0;
  cert->ber_buf     = NULL;
  cert->ber_length  = 0;
  cert->signature_algorithm = NULL;
  cert->issuer_pk_type = SSH_X509_PKALG_UNKNOWN;
}

void
ssh_glist_free_pkcs6_attr(SshGList list)
{
  SshGListNode node;
  SshX509Attribute attr;

  if (list == NULL)
    return;

  for (node = list->head; node; node = node->next)
    {
      attr = node->data;
      ssh_free(attr->oid);

      switch (attr->type)
        {
        case SSH_X509_ATTR_UNKNOWN:
          if (attr->data && attr->len > 0)
            {
              ssh_free(attr->data);
            }
          break;
        default:
          break;
        }
      ssh_free(attr);
    }
  ssh_glist_free(list);
}

void ssh_pkcs6_cert_free(SshPkcs6Cert cert)
{
  SSH_DEBUG(6, ("X.509 Certificate free."));
  ssh_x509_cert_free(cert->certificate);
  SSH_DEBUG(6, ("Attribute free."));
  ssh_glist_free_pkcs6_attr(cert->attr);
  SSH_DEBUG(6, ("Signature free."));
  ssh_free(cert->signature);
  SSH_DEBUG(6, ("Ber buffer free."));
  ssh_free(cert->ber_buf);
  ssh_free(cert);
}

/* This code implements that attribute encoding and decoding. */

SshPkcs6Status
ssh_pkcs6_attr_add(SshPkcs6Cert cert, SshX509Attribute attr)
{
  ssh_glist_add_item(cert->attr, attr, SSH_GLIST_TAIL);
  return SSH_PKCS6_OK;
}

SshPkcs6Status
ssh_pkcs6_attr_encode_asn1(SshAsn1Context context,
                           SshGList glist, SshAsn1Node *node_return)
{
  SshAsn1Status status;
  SshAsn1Node   list, node, tmp;
  SshGListNode  gnode;

  list = NULL;
  for (gnode = glist->head; gnode; gnode = gnode->next)
    {
      SshX509Attribute attr = gnode->data;

      node = NULL;
      switch (attr->type)
        {
          /* This case is the most common, e.g. the explicit details
             of the attribute values are unknown. */
        case SSH_X509_ATTR_UNKNOWN:
          /* Decode the BER of the data. */
          status = ssh_asn1_decode_node(context,
                                        attr->data, attr->len,
                                        &tmp);
          if (status != SSH_ASN1_STATUS_OK)
            return SSH_PKCS6_ASN1_DECODING_FAILED;

          /* Make the attribute thing. */
          status = ssh_asn1_create_node(context, &node,
                                        "(sequence ()"
                                        " (object-identifier ())"
                                        " (any ()))",
                                        attr->oid,
                                        tmp);
          if (status != SSH_ASN1_STATUS_OK)
            return SSH_PKCS6_ASN1_ENCODING_FAILED;
          break;

        default:
          ssh_fatal("ssh_pkcs6_attr_encode_asn1: "
                    "attribute type has no valid value.");
          break;
        }

      /* Add the node to the list. */
      list = ssh_asn1_add_list(list, node);
    }

  list = ssh_asn1_sort_list(context, list);

  /* Encode the sequence of attributes. */
  status = ssh_asn1_create_node(context, &node,
                                "(set ()"
                                " (any ()))",
                                list);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_PKCS6_ASN1_ENCODING_FAILED;

  *node_return = node;

  /* The encoding seems to be ok. */
  return SSH_PKCS6_OK;
}

SshPkcs6Status
ssh_pkcs6_attr_encode(SshGList attr,
                      unsigned char **ber, size_t *ber_length)
{
  SshPkcs6Status rv;
  SshAsn1Status  status;
  SshAsn1Context context;
  SshAsn1Node    node;

  /* Initialize the ASN.1 module and encode attributes. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_PKCS6_FAILURE;

  rv = ssh_pkcs6_attr_encode_asn1(context, attr, &node);
  if (rv != SSH_PKCS6_OK)
    {
      ssh_asn1_free(context);
      return rv;
    }

  /* Create the blob. */
  ssh_asn1_encode_node(context, node);
  status = ssh_asn1_node_get_data(node, ber, ber_length);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(context);
      return SSH_PKCS6_ASN1_ENCODING_FAILED;
    }

  ssh_asn1_free(context);
  return SSH_PKCS6_OK;
}

SshPkcs6Status
ssh_pkcs6_attr_decode_asn1(SshAsn1Context context,
                           SshAsn1Node node_input,
                           SshGList *list_return)
{
  SshAsn1Status status;
  SshAsn1Node   node, list;
  SshGList      glist;
  SshGListNode  gnode;
  SshX509Attribute attr, prev = NULL;

  /* First decode the higher structure. */
  status = ssh_asn1_read_node(context, node_input,
                              "(set (*)"
                              " (any ()))",
                              &list);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_PKCS6_ASN1_DECODING_FAILED;

  /* Allocate a temporary list. */
  glist = ssh_glist_allocate();
  for (; list; list = ssh_asn1_node_next(list))
    {
      char *oid;

      status = ssh_asn1_read_node(context, list,
                                  "(sequence ()"
                                  " (object-identifier ())"
                                  " (any ()))",
                                  &oid, &node);
      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_glist_free_pkcs6_attr(glist);
          return SSH_PKCS6_ASN1_DECODING_FAILED;
        }

      /* Allocate attribute. This code puts all under unknown types for
         now. Let the application handle oids. */
      if ((attr = ssh_malloc(sizeof(*attr))) != NULL)
        {
          attr->next = NULL;
          attr->type = SSH_X509_ATTR_UNKNOWN;
          attr->oid  = oid;
        }
      else
        {
          ssh_glist_free_pkcs6_attr(glist);
          ssh_free(oid);
          return SSH_PKCS6_FAILURE;
        }

      /* Remember the ber. */
      status = ssh_asn1_node_get_data(node, &attr->data, &attr->len);
      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_glist_free_pkcs6_attr(glist);
          ssh_free(attr);
          ssh_free(oid);
          return SSH_PKCS6_ASN1_DECODING_FAILED;
        }

      /* Make a list. */
      if ((gnode = ssh_glist_allocate_n(glist)) != NULL)
        {
          if (prev)
            prev->next = attr;

          gnode->data = attr;
          ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
        }
      else
        {
          ssh_glist_free_pkcs6_attr(glist);
          ssh_free(oid);
          ssh_free(attr);
          return SSH_PKCS6_FAILURE;
        }

      prev = attr;
    }
  *list_return = glist;
  return SSH_PKCS6_OK;
}

SshPkcs6Status
ssh_pkcs6_attr_decode(unsigned char *ber, size_t ber_length,
                      SshGList *attr)
{
  SshPkcs6Status rv;
  SshAsn1Status  status;
  SshAsn1Context context;
  SshAsn1Node    node;

  /* Initialize the ASN.1 module and decode the node. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_PKCS6_FAILURE;

  status = ssh_asn1_decode_node(context, ber, ber_length, &node);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(context);
      return SSH_PKCS6_ASN1_DECODING_FAILED;
    }

  /* Decode the BER data. */
  rv = ssh_pkcs6_attr_decode_asn1(context, node, attr);

  ssh_asn1_free(context);
  return rv;
}



/* And the following routines implement decoding of extended certificate. */
SshPkcs6Status
ssh_pkcs6_cert_decode_asn1(SshAsn1Context context, SshAsn1Node node,
                           SshPkcs6Cert cert)
{
  SshAsn1Status status;
  SshAsn1Node cert_info, sign_method, cert_node, attr_node;
  unsigned char *bs_signature;
  size_t bs_signature_len;
  SshPkcs6Status rv;

  status =
    ssh_asn1_read_node(context, node,
                       "(sequence ()"
                       "(any ())"
                       "(any ())"
                       "(bit-string ()))",
                       &cert_info, &sign_method,
                       &bs_signature, &bs_signature_len);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_PKCS6_ASN1_DECODING_FAILED;

  /* Now work with the signature. */

  /* Find the signature algorithm. */
  cert->signature_algorithm = ssh_x509_find_algorithm(context,
                                                      sign_method,
                                                      &cert->issuer_pk_type);
  /* Deduce the format for the signature method. */
  cert->signature = ssh_x509_decode_signature(context,
                                              bs_signature,
                                              bs_signature_len,
                                              cert->issuer_pk_type,
                                              &cert->signature_length);
  ssh_free(bs_signature);

  if (cert->signature == NULL)
    return SSH_PKCS6_SIGNATURE_NOT_DEFINED;


  /* Work through the certificate information. */
  status =
    ssh_asn1_read_node(context, cert_info,
                       "(sequence ()"
                       "(integer ())"
                       "(any ())"
                       "(any ()))",
                       &cert_node, &attr_node);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_PKCS6_ASN1_DECODING_FAILED;

  /* Quickly decode attributes... */
  rv = ssh_pkcs6_attr_decode_asn1(context, attr_node, &cert->attr);
  if (rv != SSH_PKCS6_OK)
    return rv;

  if (ssh_x509_cert_decode_asn1(context, cert_node, cert->certificate)
      != SSH_X509_OK)
    {
      return SSH_PKCS6_CERTIFICATE_DECODE_FAILED;
    }

  /* It seems that everything went well. */
  return SSH_PKCS6_OK;
}
#endif /* SSHDIST_CERT */
