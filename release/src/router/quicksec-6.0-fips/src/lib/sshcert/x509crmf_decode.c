/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the certificate request message formats, as
   described in RFC-2511, March 1999.
*/

#include "sshincludes.h"
#include "sshasn1.h"
#include "oid.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertCrmf"

/* Decoding. */

static SshX509Status
ssh_x509_crmf_decode_null(SshAsn1Context context,
                          SshAsn1Node null_node,
                          SshX509Pop pop)
{
  SshAsn1Status status;

  status = ssh_asn1_read_node(context, null_node,
                              "(null (0))");
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  pop->ra_verified = TRUE;
  return SSH_X509_OK;
}

static SshX509Status
ssh_x509_crmf_decode_pop_signing_key(SshAsn1Context context,
                                     SshAsn1Node templatep,
                                     SshAsn1Node signature,
                                     SshX509Pop pop,
                                     SshX509Config config)
{
  SshAsn1Status status;
  SshAsn1Node sigalg, key_input;
  Boolean key_input_found;
  unsigned char *sig;
  size_t         sig_len;
  SshX509Status  rv;

  /* Decode POPOSigningKey */
  status =
    ssh_asn1_read_node(context, signature,
                       "(sequence (*)"
                       "  (optional (any (0)))" /* signing key input */
                       "  (any ())"
                       "  (bit-string ()))",
                       &key_input_found, &key_input,
                       &sigalg,
                       &sig, &sig_len);

  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  /* Find out the type and mode of the signature algorithm. */
  pop->signature.pk_algorithm =
    ssh_x509_find_algorithm(context, sigalg, &pop->signature.pk_type);

  /* Manipulate the signature if necessary. */
  pop->signature.signature =
    ssh_x509_decode_signature(context,
                              sig,
                              sig_len,
                              pop->signature.pk_type,
                              &pop->signature.signature_len);

  if (pop->signature.signature == NULL)
    {
      ssh_free(sig);
      return SSH_X509_FAILED_SIGNATURE_CHECK;
    }
  ssh_free(sig);

  /* Get the proved message. */
  if (key_input_found)
    {
      ssh_asn1_node_get_data(key_input, &pop->proved_message,
                             &pop->proved_message_len);
    }
  else
    {
      ssh_asn1_node_get_data(templatep, &pop->proved_message,
                             &pop->proved_message_len);
    }

  /* Handle the signing key input. If this is found, the signed part
     is the key input. If not found, the signature is calculated over
     the DER coded CertReqMessages certReq part. */
  if (key_input_found)
    {
      unsigned int which;
      SshAsn1Node pkmac_alg, sender, pubkey;
      unsigned char *pkmac_value;
      size_t pkmac_value_len;

      status =
        ssh_asn1_read_node(context, key_input,
                           "(sequence (*)"
                           "  (choice"
                           "    (any (0))"
                           "    (sequence ()"
                           "      (any ())"
                           "      (bit-string ())))"
                           "  (any ()))",
                           &which, &sender, &pkmac_alg,
                           &pkmac_value, &pkmac_value_len,
                           &pubkey);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_DECODE;

      /* Check which. */
      switch (which)
        {
        case 0:
          rv = ssh_x509_decode_general_names(context,
                                             sender, &pop->sender,
                                             config);
          if (rv != SSH_X509_OK)
            return rv;
          break;
        case 1:
          /* Set the mac value. */
          pop->mac.value     = pkmac_value;
          pop->mac.value_len = pkmac_value_len/8;
          pop->mac.pswbmac = ssh_pswbmac_decode_param(context, pkmac_alg);
          break;
        default:
          return SSH_X509_FAILED_ASN1_DECODE;
          break;
        }

      /* Handle the public key. */
      if (pubkey &&
          ssh_x509_decode_asn1_public_key(context, pubkey, &pop->pkey)
          != SSH_X509_OK)
        return SSH_X509_FAILED_PUBLIC_KEY_OPS;
    }

  return SSH_X509_OK;
}

static SshX509Status
ssh_x509_crmf_decode_pop_private_key(SshAsn1Context context,
                                     SshAsn1Node prv_info,
                                     SshX509Pop pop)
{
  SshAsn1Status status;
  unsigned int which;

  /* Decode the main level. */
  status =
    ssh_asn1_read_node(context, prv_info,
                       "(choice"
                       "  (bit-string    (0))"
                       "  (integer-short (1))"
                       "  (bit-string    (2)))",
                       &which,
                       &pop->this_message, &pop->this_message_len,
                       &pop->subsequent_message,
                       &pop->mac.value, &pop->mac.value_len);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  switch (which)
    {
    case 0:
      pop->this_message_len /= 8;
      break;
    case 1:
      switch (pop->subsequent_message)
        {
        case SSH_X509_POP_SUBSEQ_ENCRYPT_CERT:
        case SSH_X509_POP_SUBSEQ_CHALLENGE_RESP:
          break;
        default:
          return SSH_X509_FAILED_UNKNOWN_VALUE;
          break;
        }
      break;
    case 2:
      pop->mac.value_len /= 8;
      break;
    default:
      return SSH_X509_FAILURE;
      break;
    }

  return SSH_X509_OK;
}

/* This is for the case one needs to decode POP out side this file. */
SshX509Status ssh_x509_pop_decode(SshAsn1Context context,
                                  SshAsn1Node    templatep,
                                  SshAsn1Node    pop_node,
                                  SshX509Pop     pop,
                                  SshX509Config  config)
{
  SshAsn1Status status;
  SshAsn1Node ra_verified, signature, key_encipherment, key_agreement;
  Boolean pop_found;
  unsigned int which_pop;
  SshX509Status rv;

  status =
    ssh_asn1_read_node(context, pop_node,
                       "(optional"
                       "  (choice"
                       "    (any (0))" /* raVerified */
                       "    (any (1))" /* signature */
                       "    (any (e 2))" /* keyEncipherment */
                       "    (any (e 3))))", /* keyAgreement */
                       &pop_found,
                       &which_pop,
                       &ra_verified,
                       &signature,
                       &key_encipherment,
                       &key_agreement);
  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  /* Passthrough value. */
  rv = SSH_X509_OK;

  if (pop_found)
    {
      /* A POP (proof-of-possession) message was found in the
         templatep. */
      switch (which_pop)
        {
        case 0:
          rv = ssh_x509_crmf_decode_null(context, ra_verified, pop);
          break;
        case 1:
          rv = ssh_x509_crmf_decode_pop_signing_key(context, templatep,
                                                    signature, pop,
                                                    config);
          break;
        case 2:
          rv = ssh_x509_crmf_decode_pop_private_key(context, key_encipherment,
                                                    pop);
          break;
        case 3:
          rv = ssh_x509_crmf_decode_pop_private_key(context, key_encipherment,
                                                    pop);
          break;
        default:
          rv = SSH_X509_FAILED_ASN1_DECODE;
          break;
        }
    }

  return rv;
}


SshX509Status
ssh_x509_crmf_decode_publication_info(SshAsn1Context context,
                                      SshAsn1Node node,
                                      SshX509PublicationInfo pinfo,
                                      SshX509Config config)
{
  Boolean pubinfos_found, namenode_found;
  SshAsn1Node pubinfos, pubinfo, namenode;
  SshAsn1Status status;
  SshX509PublicationInfoNode pin;

  status = ssh_asn1_read_node(context, node,
                              "(sequence ()"
                              "  (integer-short ())"
                              "  (optional"
                              "    (any ())))",
                              &pinfo->action,
                              &pubinfos_found, &pubinfos);

  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_ASN1_DECODE;

  if (pubinfos_found)
    {
      pubinfo = ssh_asn1_node_child(pubinfos);
      for (; pubinfo; pubinfo = ssh_asn1_node_next(pubinfo))
        {
          if ((pin = ssh_malloc(sizeof(*pin))) == NULL)
            {
              ssh_x509_publication_info_clear(pinfo);
              return SSH_X509_FAILED_ASN1_DECODE;
            }

          status = ssh_asn1_read_node(context, pubinfo,
                                      "(sequence ()"
                                      "  (integer-short ())"
                                      "  (optional"
                                      "    (any ())))",
                                      &pin->publication_method,
                                      &namenode_found, &namenode);

          if (status != SSH_ASN1_STATUS_OK)
            {
              ssh_free(pin);
              ssh_x509_publication_info_clear(pinfo);
              return SSH_X509_FAILED_ASN1_DECODE;
            }

          if (namenode_found)
            (void)ssh_x509_decode_general_name(context,
                                               namenode, &pin->location,
                                               config);
          else
            pin->location = NULL;

          pin->next = pinfo->nodes;
          pinfo->nodes = pin;
        }
    }
  return SSH_X509_OK;
}


SshX509Status
ssh_x509_crmf_decode_archive_options(SshAsn1Context context,
                                     SshAsn1Node node,
                                     SshX509ArchiveOptions poptions)
{
  size_t which, kgparams_len, len;
  unsigned char *kgparams, *data;
  SshAsn1Node ednode;
  Boolean savekey;

  if (ssh_asn1_read_node(context, node,
                         "(choice"
                         "  (any (e 0))"
                         "  (octet-string (1))"
                         "  (boolean (2)))",
                         &which,
                         &ednode,
                         &kgparams, &kgparams_len,
                         &savekey) == SSH_ASN1_STATUS_OK)
    {
      switch (which)
        {
        case 0:
          ssh_asn1_node_get_data(ednode, &data, &len);
          ssh_crmf_decode_encrypted_value(data, len,
                                          &poptions->encrypted_value);
          ssh_free(data);
          break;
        case 1:
          poptions->keygen_parameters = kgparams;
          poptions->keygen_parameters_len = kgparams_len;
          break;
        case 2:
          poptions->archive_prv_key = savekey;
          break;
        default:
          SSH_NOTREACHED;
          break;
        }
      return SSH_X509_OK;
    }
  return SSH_X509_FAILED_ASN1_DECODE;
}

SshX509Status
ssh_x509_crmf_decode_controls(SshAsn1Context context,
                              SshAsn1Node    node,
                              SshX509Controls controls,
                              SshX509Config config)
{
  SshAsn1Status status;
  SshX509ControlsNode c_node, prev;
  SshAsn1Node   ctrl;
  const SshOidStruct *oids;
  unsigned char *oid;
  unsigned char *tmp;
  size_t         tmp_len;

  for (prev = NULL; node; node = ssh_asn1_node_next(node))
    {
      /* Decode the attribute type. */
      status = ssh_asn1_read_node(context, node,
                                  "(sequence ()"
                                  "  (object-identifier ())"
                                  "  (any ()))",
                                  &oid, &ctrl);
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_DECODE;

      /* Get the oid information. */
      oids = ssh_oid_find_by_oid_of_type(oid, SSH_OID_CONTROLS);
      ssh_free(oid);
      oid = NULL;
      if (oids == NULL)
        {
          controls->unknown++;
          continue;
        }

      if ((c_node = ssh_calloc(1, sizeof(*c_node))) != NULL)
        {
          ssh_x509_controls_node_init(c_node);

          /* Determine the oid of interest. */
          c_node->type = (SshX509ControlsType)oids->extra_int;

          switch (c_node->type)
            {
            case SSH_X509_CTRL_REG_TOKEN:
              status =
                ssh_asn1_read_node(context, ctrl,
                                   "(utf8-string ())", &tmp, &tmp_len);
              if (status != SSH_ASN1_STATUS_OK)
                {
                  goto failure;
                }

              c_node->s.reg_token = ssh_str_make(SSH_CHARSET_UTF8,
                                                 tmp, tmp_len);
              break;
            case SSH_X509_CTRL_AUTHENTICATOR:
              status =
                ssh_asn1_read_node(context, ctrl,
                                   "(utf8-string ())", &tmp, &tmp_len);
              if (status != SSH_ASN1_STATUS_OK)
                {
                  goto failure;
                }

              c_node->s.authenticator = ssh_str_make(SSH_CHARSET_UTF8,
                                                     tmp, tmp_len);
              break;
            case SSH_X509_CTRL_PKI_INFO:
              ssh_x509_publication_info_init(&c_node->s.pki_info);
              if (ssh_x509_crmf_decode_publication_info(context,
                                                        ctrl,
                                                        &c_node->s.pki_info,
                                                        config)
                  != SSH_X509_OK)
                {
                  ssh_x509_publication_info_clear(&c_node->s.pki_info);
                  goto failure;
                }
              break;
            case SSH_X509_CTRL_PKI_OPTIONS:
              ssh_x509_archive_options_init(&c_node->s.pki_options);
              if (ssh_x509_crmf_decode_archive_options
                  (context, ctrl, &c_node->s.pki_options) != SSH_X509_OK)
                {
                  ssh_x509_archive_options_clear(&c_node->s.pki_options);
                  goto failure;
                }
              break;
            case SSH_X509_CTRL_OLD_CERT_ID:
              {
                SshAsn1Node issuer_name;
                ssh_x509_cert_id_init(&c_node->s.old_cert_id);
                status =
                  ssh_asn1_read_node(context, ctrl,
                                     "(sequence ()"
                                     "  (any ())"
                                     "  (integer ()))",
                                     &issuer_name,
                                     &c_node->s.old_cert_id.serial_no);
                if (status != SSH_ASN1_STATUS_OK)
                  {
                    ssh_x509_cert_id_clear(&c_node->s.old_cert_id);
                    goto failure;
                  }

                /* Decode the general names. */
                if (ssh_x509_decode_general_name(context, issuer_name,
                                                 &c_node->s.old_cert_id.issuer,
                                                 config)
                    != SSH_X509_OK)
                  {
                    ssh_x509_cert_id_clear(&c_node->s.old_cert_id);
                    goto failure;
                  }
              }
              break;

            case SSH_X509_CTRL_PUBLIC_KEY:
              /* A public key decoding. */
              ssh_x509_public_key_init(&c_node->s.public_key);

              /* Make the public key. */
              if (ssh_x509_decode_asn1_public_key
                  (context, ctrl, &c_node->s.public_key) != SSH_X509_OK)
                {
                  ssh_x509_public_key_clear(&c_node->s.public_key);
                  goto failure;
                }

              break;
            default:
              controls->unknown++;
              break;
            }

          /* Add to the list. */
          if (prev)
            prev->next = c_node;
          else
            controls->node = c_node;
          prev = c_node;
        }
      else
        {
        failure:
          if (c_node)
            {
              ssh_x509_controls_node_clear(c_node);
              ssh_free(c_node);
            }
          ssh_x509_controls_clear(controls);
          return SSH_X509_FAILED_ASN1_DECODE;
        }
    }
  return SSH_X509_OK;
}

SshX509Status
ssh_x509_decode_optional_validity(SshAsn1Context context,
                                  SshAsn1Node opt_time,
                                  SshBerTime not_before,
                                  SshBerTime not_after)
{
  SshAsn1Status status;
  SshAsn1Node   not_before_node, not_after_node;
  Boolean       not_before_found, not_after_found;
  SshX509Status rv;
  int failcount = 0;

 again:
  status = ssh_asn1_read_node(context, opt_time,
                              "(sequence (4)"
                              "  (optional (any (e 0)))"
                              "  (optional (any (e 1))))",
                              &not_before_found, &not_before_node,
                              &not_after_found, &not_after_node);
  if (status != SSH_ASN1_STATUS_OK)
    {
      SshAsn1Node tmp;
      if (failcount == 0)
        {
          tmp = ssh_asn1_node_child(opt_time);
          (void)ssh_asn1_create_node(context, &opt_time,
                                     "(sequence (4) (any ()))", tmp);
          failcount++;
          goto again;
        }
      return SSH_X509_FAILED_ASN1_DECODE;
    }

  if (not_before_found)
    {
      rv = ssh_x509_decode_time(context,
                                not_before_node,
                                not_before);
      if (rv != SSH_X509_OK)
        return rv;
    }
  if (not_after_found)
    {
      rv = ssh_x509_decode_time(context,
                                not_after_node,
                                not_after);
      if (rv != SSH_X509_OK)
        return rv;
    }
  return SSH_X509_OK;
}

/* Decoding the particular certificate templatep. */
SshX509Status
ssh_x509_crmf_decode_templatep(SshAsn1Context context,
                               SshAsn1Node templatep,
                               SshX509Certificate cert)
{
  SshAsn1Node signing_alg, subject_name, issuer_name,
    optional_time, public_key, extensions;
  SshAsn1Status status;
  SshMPIntegerStruct version;
  unsigned char *issuer_uid, *subject_uid;
  size_t        issuer_uid_len, subject_uid_len;
  Boolean version_found, serial_number_found, signing_found,
    issuer_name_found, optional_time_found, subject_name_found,
    public_key_found, issuer_uid_found, subject_uid_found,
    extensions_found;
  SshX509Status rv = SSH_X509_OK;

  /* Initialize the necessary variables. */
  ssh_mprz_init(&version);
  issuer_uid  = NULL;
  subject_uid = NULL;

  /* Template first. */
  status = ssh_asn1_read_node(context, templatep,
                              "(sequence ()"
                              "  (optional"
                              "    (integer (0)))"   /* version */
                              "  (optional"
                              "    (integer (1)))"   /* serial number */
                              "  (optional"
                              "    (any     (2)))"   /* signing alg. */
                              "  (optional"
                              "    (any     (e 3)))" /* issuer name */
                              "  (optional"
                              "    (any     (4)))"   /* optional validity */
                              "  (optional"
                              "    (any     (e 5)))" /* subject name */
                              "  (optional"
                              "    (any     (6)))"   /* public key */
                              "  (optional"
                              "    (bit-string (e 7)))" /* issuer uid */
                              "  (optional"
                              "    (bit-string (e 8)))" /* subject uid */
                              "  (optional"
                              "    (any     (9))))",  /* extensions */
                              &version_found, &version,
                              &serial_number_found, &cert->serial_number,
                              &signing_found, &signing_alg,
                              &issuer_name_found, &issuer_name,
                              &optional_time_found, &optional_time,
                              &subject_name_found, &subject_name,
                              &public_key_found, &public_key,
                              &issuer_uid_found,
                              &issuer_uid, &issuer_uid_len,
                              &subject_uid_found,
                              &subject_uid, &subject_uid_len,
                              &extensions_found, &extensions);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  /* Check the version number. */
  if (version_found)
    {
      if (ssh_mprz_cmp_ui(&version, 0) < 0 ||
          ssh_mprz_cmp_ui(&version, 2) > 0)
        {
          /* Version number incorrect. */
          rv = SSH_X509_FAILED_VERSION_CHECK;
          goto failed;
        }
      switch (ssh_mprz_get_ui(&version))
        {
        case 0:
          cert->version = SSH_X509_VERSION_1;
          break;
        case 1:
          cert->version = SSH_X509_VERSION_2;
          break;
        case 2:
          cert->version = SSH_X509_VERSION_3;
          break;
        }
    }

  /* Handle the signing algorithm. */
  if (signing_found)
    {
      cert->pop.signature.pk_algorithm =
        ssh_x509_find_algorithm(context, signing_alg,
                                &cert->pop.signature.pk_type);
      if (cert->pop.signature.pk_algorithm == NULL)
        {
          rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_CHECK;
          goto failed;
        }
      /* Rest of the signature information will be found elsewhere. */
    }

  /* Handle the issuer name. */
  if (issuer_name_found)
    {
      if (ssh_x509_decode_dn_name(context,
                                  issuer_name,
                                  SSH_X509_NAME_DISTINGUISHED_NAME,
                                  &cert->issuer_name,
                                  &cert->config) != SSH_X509_OK)
        {
          rv = SSH_X509_FAILED_DN_NAME_CHECK;
          goto failed;
        }
    }

  /* Handle the subject name. */
  if (subject_name_found)
    {
      if (ssh_x509_decode_dn_name(context,
                                  subject_name,
                                  SSH_X509_NAME_DISTINGUISHED_NAME,
                                  &cert->subject_name,
                                  &cert->config) != SSH_X509_OK)
        {
          rv = SSH_X509_FAILED_DN_NAME_CHECK;
          goto failed;
        }
    }

  /* Handle the optional time. */
  if (optional_time_found)
    {
      if (ssh_x509_decode_optional_validity(context,
                                            optional_time,
                                            &cert->not_before,
                                            &cert->not_after) != SSH_X509_OK)
        {
          rv = SSH_X509_FAILED_TIME_DECODE;
          goto failed;
        }
    }

  /* Handle the public key. */
  if (public_key_found)
    {
      SshAsn1Node tmp;

      tmp = ssh_asn1_node_child(public_key);
      status = ssh_asn1_create_node(context, &tmp, "(sequence () (any ()))",
                                    tmp);
      if (status != SSH_ASN1_STATUS_OK)
        {
          rv = SSH_X509_FAILED_ASN1_DECODE;
          goto failed;
        }

      if (ssh_x509_decode_asn1_public_key(context, tmp, &cert->subject_pkey)
          != SSH_X509_OK)
        {
          rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
          goto failed;
        }
    }

  /* Handle the issuer uid. */
  if (issuer_uid_found)
    {
      SshX509Name new_name;

      new_name = ssh_x509_name_alloc(SSH_X509_NAME_UNIQUE_ID,
                                     NULL, NULL,
                                     issuer_uid, issuer_uid_len,
                                     NULL, 0);
      ssh_x509_name_push(&cert->issuer_name, new_name);
      issuer_uid = NULL;
    }

  /* Handle the subject uid. */
  if (subject_uid_found)
    {
      SshX509Name new_name;

      new_name = ssh_x509_name_alloc(SSH_X509_NAME_UNIQUE_ID,
                                     NULL, NULL,
                                     subject_uid, subject_uid_len,
                                     NULL, 0);
      ssh_x509_name_push(&cert->subject_name, new_name);
      subject_uid = NULL;
    }

  /* Handle the extensions. */
  if (extensions_found)
    {
      SshAsn1Node tmp = ssh_asn1_node_child(extensions);
      (void)ssh_asn1_create_node(context, &tmp, "(sequence () (any ()))", tmp);
      rv = ssh_x509_cert_decode_extension(context, tmp, cert);
      if (rv != SSH_X509_OK)
        goto failed;
    }

  /* Done. */

 failed:
  if (rv != SSH_X509_OK)
    cert->version = SSH_X509_VERSION_UNKNOWN;
  ssh_mprz_clear(&version);
  ssh_free(issuer_uid);
  ssh_free(subject_uid);

  return rv;
}

SshX509Status
ssh_x509_crmf_decode_request(SshAsn1Context context,
                             SshAsn1Node request,
                             SshX509Certificate cert)
{
  SshAsn1Node templatep, controls;
  SshAsn1Status status;
  Boolean controls_found;

  /* Decode the main framework of the request. */
  status = ssh_asn1_read_node(context, request,
                              "(sequence (*)"
                              "  (integer ())"   /* certRegId */
                              "  (any ())"       /* templatep */
                              "  (optional "
                              "    (sequence ()" /* controls */
                              "      (any ()))))",
                              &cert->request_id,
                              &templatep,
                              &controls_found, &controls);

  /* In case the one above fails, some applications may still have
     valid template at hand instead of CRMF request. */
  if (status != SSH_ASN1_STATUS_OK)

    {
      if (ssh_x509_crmf_decode_templatep(context, request, cert)
          != SSH_X509_OK)
        return SSH_X509_FAILED_ASN1_DECODE;
      else
        return SSH_X509_OK;
    }
  else
    {
      if (ssh_x509_crmf_decode_templatep(context, templatep, cert)
          == SSH_X509_OK)
        {
          if (!controls_found ||
              (controls_found &&
               ssh_x509_crmf_decode_controls(context, controls,
                                             &cert->controls,
                                             &cert->config)
               == SSH_X509_OK))
            return SSH_X509_OK;
        }
    }

  return SSH_X509_FAILED_ASN1_DECODE;
}

/* The general framework for decoding the request message. */
SshX509Status ssh_x509_crmf_decode_asn1(SshAsn1Context context,
                                        SshAsn1Node crmf_node,
                                        SshX509Certificate cert)
{
  SshAsn1Node request, reg_info, ra_verified, signature,
    key_encipherment, key_agreement;
  SshAsn1Status status;
  Boolean reg_found, pop_found;
  unsigned int which_pop;
  SshX509Status rv = SSH_X509_FAILURE;

  /* Decode the main framework. We may end up here in two ways.. Either
     it is an CRMF, or only the CertTemplate of the CRMF. The following
     will match both of these with sequence of any. Later we check from
     pop if to handle the request node read as template (no pop) */
  status =
    ssh_asn1_read_node(context, crmf_node,
                       "(sequence (*)"
                       "  (any ())"      /* cert request */
                       "  (optional "    /* pop */
                       "    (choice "
                       "      (any (0))" /* raVerified */
                       "      (any (1))" /* signature */
                       "      (any (e 2))" /* keyEncipherment */
                       "      (any (e 3))))" /* keyAgreement */
                       "  (optional "
                       "    (sequence ()" /* regInfo */
                       "      (any ()))))",
                       &request,
                       &pop_found, &which_pop,
                       &ra_verified,
                       &signature,
                       &key_encipherment,
                       &key_agreement,
                       &reg_found, &reg_info);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  if (pop_found)
    {
      /* A POP (proof-of-possession) message was found in the request. */
      switch (which_pop)
        {
        case 0:
          rv = ssh_x509_crmf_decode_null(context, ra_verified, &cert->pop);
          break;
        case 1:
          rv = ssh_x509_crmf_decode_pop_signing_key(context, request,
                                                    signature,
                                                    &cert->pop,
                                                    &cert->config);
          break;
        case 2:
          rv = ssh_x509_crmf_decode_pop_private_key(context, key_encipherment,
                                                    &cert->pop);
          break;
        case 3:
          rv = ssh_x509_crmf_decode_pop_private_key(context, key_encipherment,
                                                    &cert->pop);
          break;
        default:
          rv = SSH_X509_FAILED_ASN1_DECODE;
          break;
        }

      /* Check whether the POP decoding routines ended up with failures.
         If so, assume template. */
      if (rv != SSH_X509_OK)
        {
          if (which_pop > 3)
            goto failed;
          request = crmf_node;
        }
    }

  if (reg_found)
    {
      /* Handle the supplementary information. */
      /* TODO */
    }

  /* Handle the certificate request */
  rv = ssh_x509_crmf_decode_request(context, request, cert);
  if (rv != SSH_X509_OK)
    goto failed;

 failed:
  return rv;
}
#endif /* SSHDIST_CERT */
