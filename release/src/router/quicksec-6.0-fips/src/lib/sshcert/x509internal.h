/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal interface into X.509 certificates. This interface allows
   access to X.509 library internal data structures and functions.
*/

#ifndef X509INTERNAL_H
#define X509INTERNAL_H

/*******************/
/* x509signature.c */
/*******************/

/* Decode signature */
unsigned char *ssh_x509_decode_signature(SshAsn1Context context,
                                         unsigned char *signature,
                                         size_t signature_len,
                                         SshX509PkAlgorithm signature_type,
                                         size_t *out_len);

/* Encode signature */
unsigned char *ssh_x509_encode_signature(SshAsn1Context context,
                                         const unsigned char *signature,
                                         size_t         signature_len,
                                         SshPrivateKey private_key,
                                         size_t *out_len);

/****************/
/* x509public.c */
/****************/

/* Decode public key */
SshX509Status ssh_x509_decode_asn1_public_key(SshAsn1Context context,
                                         SshAsn1Node pk_info,
                                         SshX509PublicKey pkey);
/* Encode public key */
SshAsn1Node ssh_x509_encode_public_key(SshAsn1Context context,
                                       SshX509PublicKey pkey);

/* Encode public key from crypto library key */
SshAsn1Node ssh_x509_encode_public_key_internal(SshAsn1Context context,
                                                SshPublicKey key);

/* Encode public key group */
SshAsn1Node ssh_x509_encode_public_group_internal(SshAsn1Context context,
                                                  SshPkGroup pk_group);








/* Mark that extension of `type' is used and its criticality status */
void ssh_x509_ext_info_set(SshUInt32 *ext_available,
                           SshUInt32 *ext_critical,
                           unsigned int type,
                           Boolean critical);

SshX509Name ssh_x509_name_find_all(SshX509Name list, SshX509NameType type);
SshX509Name ssh_x509_name_alloc(SshX509NameType type,
                                SshDN dn, SshStr name,
                                void  *data, size_t data_len,
                                unsigned char *ber_name, size_t ber_name_len);

void ssh_x509_name_push(SshX509Name *list, SshX509Name name);

/* Find the algorithm defined by the given algorithm identifier. The
   return string is in SSH format. */
const char *ssh_x509_find_algorithm(SshAsn1Context context,
                                    SshAsn1Node algorithm_identifier,
                                    SshX509PkAlgorithm *type);

/* Key identifiers. */
void ssh_x509_key_id_init(SshX509ExtKeyId k);
void ssh_x509_key_id_clear(SshX509ExtKeyId k);
void ssh_x509_key_id_free(SshX509ExtKeyId k);

/* Policy information. */
void ssh_x509_policy_qualifier_info_init(SshX509ExtPolicyQualifierInfo i);
void ssh_x509_policy_qualifier_info_clear(SshX509ExtPolicyQualifierInfo i);
void ssh_x509_policy_qualifier_info_free(SshX509ExtPolicyQualifierInfo i);
void ssh_x509_policy_info_init(SshX509ExtPolicyInfo i);
void ssh_x509_policy_info_clear(SshX509ExtPolicyInfo i);
void ssh_x509_policy_info_free(SshX509ExtPolicyInfo i);

/* Policy mappings. */
void ssh_x509_policy_mappings_init(SshX509ExtPolicyMappings m);
void ssh_x509_policy_mappings_clear(SshX509ExtPolicyMappings m);
void ssh_x509_policy_mappings_free(SshX509ExtPolicyMappings m);

/* Attributes. */
void ssh_x509_directory_attribute_init(SshX509ExtDirAttribute d);
void ssh_x509_directory_attribute_clear(SshX509ExtDirAttribute d);
void ssh_x509_directory_attribute_free(SshX509ExtDirAttribute d);

/* Routines for general subtrees. */
void ssh_x509_general_subtree_init(SshX509GeneralSubtree g);
void ssh_x509_general_subtree_clear(SshX509GeneralSubtree g);
void ssh_x509_general_subtree_free(SshX509GeneralSubtree g);

/* Policy constraints. */
void ssh_x509_policy_const_init(SshX509ExtPolicyConstraints p);
void ssh_x509_policy_const_clear(SshX509ExtPolicyConstraints p);
void ssh_x509_policy_const_free(SshX509ExtPolicyConstraints p);

/* CRL distribution points. */
void ssh_x509_crl_dist_points_init(SshX509ExtCRLDistPoints dp);
void ssh_x509_crl_dist_points_clear(SshX509ExtCRLDistPoints dp);
void ssh_x509_crl_dist_points_free(SshX509ExtCRLDistPoints c);

/* Information access. */
void ssh_x509_info_access_init(SshX509ExtInfoAccess ia);
void ssh_x509_info_access_clear(SshX509ExtInfoAccess ia);
void ssh_x509_info_access_free(SshX509ExtInfoAccess ia);

/* Qualified certificate statements. */
void ssh_x509_qcstatement_init(SshX509ExtQCStatement s);
void ssh_x509_qcstatement_clear(SshX509ExtQCStatement s);
void ssh_x509_qcstatement_free(SshX509ExtQCStatement s);

/* Unknown extensions. */
void ssh_x509_unknown_extension_init(SshX509ExtUnknown unknown);
void ssh_x509_unknown_extension_clear(SshX509ExtUnknown unknown);
void ssh_x509_unknown_extension_free(SshX509ExtUnknown unknown);


/* Handle oid lists. */
void ssh_x509_oid_list_init(SshX509OidList list);
void ssh_x509_oid_list_clear(SshX509OidList list);
void ssh_x509_oid_list_free(SshX509OidList list);

/* Convert between values and bitstrings. */
unsigned int ssh_x509_bs_to_ui(unsigned char *buf, size_t buf_len);
unsigned char *ssh_x509_ui_to_bs(unsigned int value, size_t *buf_len);


/* Reason flags handling */
size_t ssh_x509_convert_rf_to_bits(unsigned char *buf,
                                   SshX509ReasonFlags reason);
SshX509ReasonFlags ssh_x509_convert_rf_from_bits(unsigned char *buf,
                                                 size_t buf_len);
/* Key usage encoding and decoding. */
size_t ssh_x509_convert_uf_to_bits(unsigned char *buf,
                                   SshX509UsageFlags flags);
SshX509UsageFlags ssh_x509_convert_uf_from_bits(unsigned char *buf,
                                                 size_t buf_len);

/* Handle the issuer distribution point. */
void ssh_x509_issuing_dist_point_init(SshX509ExtIssuingDistPoint ip);
void ssh_x509_issuing_dist_point_clear(SshX509ExtIssuingDistPoint ip);
void ssh_x509_issuing_dist_point_free(SshX509ExtIssuingDistPoint ip);

/* Extensions. */
void ssh_x509_cert_extensions_init(SshX509CertExtensions e);
void ssh_x509_cert_extensions_clear(SshX509CertExtensions e);

void ssh_x509_crl_extensions_init(SshX509CrlExtensions e);
void ssh_x509_crl_extensions_clear(SshX509CrlExtensions e);

void ssh_x509_crl_rev_extensions_init(SshX509CrlRevExtensions e);
void ssh_x509_crl_rev_extensions_clear(SshX509CrlRevExtensions e);


void ssh_x509_cert_id_clear(SshX509CertId c);
void ssh_x509_cert_id_init(SshX509CertId c);

void ssh_x509_archive_options_clear(SshX509ArchiveOptions a);
void ssh_x509_archive_options_init(SshX509ArchiveOptions a);

void ssh_x509_encrypted_value_clear(SshX509EncryptedValue e);
void ssh_x509_encrypted_value_init(SshX509EncryptedValue e);

void ssh_x509_controls_init(SshX509Controls c);
void ssh_x509_controls_node_init(SshX509ControlsNode n);
void ssh_x509_controls_node_clear(SshX509ControlsNode n);
void ssh_x509_controls_clear(SshX509Controls c);

void ssh_x509_publication_info_init(SshX509PublicationInfo p);
void ssh_x509_publication_info_node_init(SshX509PublicationInfoNode p);
void ssh_x509_publication_info_node_clear(SshX509PublicationInfoNode p);
void ssh_x509_publication_info_clear(SshX509PublicationInfo p);

void ssh_x509_pop_clear(SshX509Pop p);
void ssh_x509_pop_init(SshX509Pop p);

void ssh_x509_public_key_clear(SshX509PublicKey p);
void ssh_x509_public_key_init(SshX509PublicKey p);

void ssh_x509_mac_value_clear(SshX509MacValue m);
void ssh_x509_mac_value_init(SshX509MacValue m);

void ssh_x509_signature_clear(SshX509Signature s);
void ssh_x509_signature_init(SshX509Signature s);

/*******************************************/
/* x509misc_encode.c and x509misc_decode.c */
/*******************************************/

/* Decode distinguished name from asn1 code to name list */
SshX509Status ssh_x509_decode_dn_name(SshAsn1Context context,
                                      SshAsn1Node data,
                                      SshX509NameType type,
                                      SshX509Name *names,
                                      SshX509Config config);

/* Encode distinguished name from name list to asn1 code */
SshAsn1Node ssh_x509_encode_dn_name(SshAsn1Context context,
                                    SshX509NameType type,
                                    SshX509Name names,
                                    SshX509Config config);

/* Encode signature algorithm to asn1 code */
SshAsn1Node ssh_x509_encode_sigalg(SshAsn1Context context,
                                   SshPrivateKey issuer_key);

/* Decode Validity information. */
SshX509Status ssh_x509_decode_validity(SshAsn1Context context,
                                       SshAsn1Node    data,
                                       SshBerTime     not_before,
                                       SshBerTime     not_after);

/* Encode Validity information. */
SshAsn1Node ssh_x509_encode_validity(SshAsn1Context context,
                                     SshBerTime not_before,
                                     SshBerTime not_after);

/* Decode time structure */
SshX509Status ssh_x509_decode_time(SshAsn1Context context,
                                   SshAsn1Node    data,
                                   SshBerTime     my_time);

/* Encode time structure */
SshAsn1Node ssh_x509_encode_time(SshAsn1Context context,
                                 SshBerTime my_time);

/* Decode basic constraints */
SshX509Status ssh_x509_decode_basic_constraints(SshAsn1Context context,
                                                SshAsn1Node    data,
                                                Boolean       *ca,
                                                size_t        *path_len,
                                                SshX509Config config);

/* Encode basci constraints */
SshAsn1Node ssh_x509_encode_basic_constraints(SshAsn1Context context,
                                              Boolean ca,
                                              size_t path_len,
                                              SshX509Config config);

/* Decode general name */
SshX509Status ssh_x509_decode_general_name(SshAsn1Context context,
                                           SshAsn1Node    name,
                                           SshX509Name   *names,
                                           SshX509Config  config);

/* Encode general name */
SshAsn1Node ssh_x509_encode_general_name(SshAsn1Context context,
                                         SshX509Name names,
                                         SshX509Config config);

/* Decode general name list */
SshX509Status ssh_x509_decode_general_name_list(SshAsn1Context context,
                                                SshAsn1Node    name,
                                                SshX509Name   *names,
                                                SshX509Config  config);

/* Encode general name list */
SshAsn1Node ssh_x509_encode_general_name_list(SshAsn1Context context,
                                              SshX509Name names,
                                              SshX509Config config);


/* Decode general names */
SshX509Status ssh_x509_decode_general_names(SshAsn1Context context,
                                            SshAsn1Node    data,
                                            SshX509Name   *names,
                                            SshX509Config  config);

/* Encode general names */
SshAsn1Node ssh_x509_encode_general_names(SshAsn1Context context,
                                          SshX509Name names,
                                          SshX509Config config);

/* Decode key id */
SshX509Status ssh_x509_decode_key_id(SshAsn1Context   context,
                                     SshAsn1Node      data,
                                     SshX509ExtKeyId *k,
                                     SshX509Config    config);

/* Encode key id */
SshAsn1Node ssh_x509_encode_key_id(SshAsn1Context   context,
                                   SshX509ExtKeyId k,
                                   SshX509Config config);

/* Decode subject key id */
SshX509Status ssh_x509_decode_subject_key_id(SshAsn1Context context,
                                             SshAsn1Node data,
                                             SshX509ExtKeyId *k);

/* Encode subject key id */
SshAsn1Node ssh_x509_encode_subject_key_id(SshAsn1Context context,
                                           SshX509ExtKeyId k);

/* Decode directory attributes */
SshX509Status ssh_x509_decode_directory_attribute(SshAsn1Context context,
                                                  SshAsn1Node data,
                                                  SshX509ExtDirAttribute *d);

/* Encode directory attributes */
SshAsn1Node ssh_x509_encode_directory_attribute(SshAsn1Context context,
                                                SshX509ExtDirAttribute d);

/* Decode general subtree */
SshX509Status ssh_x509_decode_general_subtree(SshAsn1Context context,
                                              SshAsn1Node data,
                                              SshX509GeneralSubtree *g,
                                              SshX509Config config);

/* Encode general subtree */
SshAsn1Node ssh_x509_encode_general_subtree(SshAsn1Context context,
                                            SshX509GeneralSubtree g,
                                            SshX509Config config);

/* Decode name constraints */
SshX509Status ssh_x509_decode_name_const(SshAsn1Context context,
                                         SshAsn1Node data,
                                         SshX509GeneralSubtree *permit,
                                         SshX509GeneralSubtree *exclude,
                                         SshX509Config config);

/* Encode name constraints */
SshAsn1Node ssh_x509_encode_name_const(SshAsn1Context context,
                                       SshX509GeneralSubtree permit,
                                       SshX509GeneralSubtree exclude,
                                       SshX509Config config);

/* Decode CRL distribution points. */
SshX509Status ssh_x509_decode_crl_dist_points(SshAsn1Context context,
                                              SshAsn1Node data,
                                              SshX509Name issuer_names,
                                              SshX509ExtCRLDistPoints *c,
                                              SshX509Config config);

/* Encode CRL distribution points. */
SshAsn1Node ssh_x509_encode_crl_dist_points(SshAsn1Context context,
                                            SshX509ExtCRLDistPoints p,
                                            SshX509Config config);

/* Decode Authority Information Access. */
SshX509Status ssh_x509_decode_auth_info_access(SshAsn1Context context,
                                               SshAsn1Node data,
                                               SshX509ExtInfoAccess *a,
                                               SshX509Config config);

/* Encode Authority Information Access. */
SshAsn1Node ssh_x509_encode_auth_info_access(SshAsn1Context context,
                                             SshX509ExtInfoAccess *a,
                                             SshX509Config config);

/* Decode oid list */
SshX509Status ssh_x509_decode_oid_list(SshAsn1Context context,
                                       SshAsn1Node data,
                                       SshX509OidList *list);
/* Encode oid list */
SshAsn1Node ssh_x509_encode_oid_list(SshAsn1Context context,
                                     SshX509OidList oid_list);

/* Decode key usage */
SshX509Status ssh_x509_decode_key_usage(SshAsn1Context context,
                                        SshAsn1Node data,
                                        SshX509UsageFlags *flags);

/* Encode key usage */
SshAsn1Node ssh_x509_encode_key_usage(SshAsn1Context context,
                                      SshX509UsageFlags flags);

/* Decode Private key usage period. */
SshX509Status
ssh_x509_decode_private_key_usage_period(SshAsn1Context context,
                                         SshAsn1Node    data,
                                         SshBerTime     not_before,
                                         SshBerTime     not_after);

/* Encode Private key usage period. */
SshAsn1Node
ssh_x509_encode_private_key_usage_period(SshAsn1Context context,
                                         SshBerTime not_before,
                                         SshBerTime not_after);

/* Decode the CRL number (trivial). */
SshX509Status ssh_x509_decode_number(SshAsn1Context context,
                                     SshAsn1Node    data,
                                     SshMPInteger        mp_int);

/* Encode the CRL number (trivial). */
SshAsn1Node ssh_x509_encode_number(SshAsn1Context context,
                                   SshMPInteger       mp_int);

/* Decode issuer distribution point */
SshX509Status
ssh_x509_decode_issuing_dist_point(SshAsn1Context context,
                                   SshAsn1Node    data,
                                   SshX509Name    issuer_names,
                                   SshX509ExtIssuingDistPoint *ip,
                                   SshX509Config  config);

/* Encode issuer distribution point */
SshAsn1Node
ssh_x509_encode_issuing_dist_point(SshAsn1Context context,
                                   SshX509ExtIssuingDistPoint ip,
                                   SshX509Config  config);

/* Decode revoked cert extensions. */
SshX509Status ssh_x509_decode_crl_reason_code(SshAsn1Context context,
                                              SshAsn1Node    data,
                                              SshX509CRLReasonCode *flags);

/* Encode revoked cert extensions. */
SshAsn1Node ssh_x509_encode_crl_reason_code(SshAsn1Context context,
                                            SshX509CRLReasonCode flags);

/* Decode hold instruction code. */
SshX509Status ssh_x509_decode_hold_inst_code(SshAsn1Context context,
                                             SshAsn1Node    data,
                                             char **code);

/* Encode hold instruction code. */
SshAsn1Node ssh_x509_encode_hold_inst_code(SshAsn1Context context,
                                           char *code);

/* Decode invalidity dates. */
SshX509Status ssh_x509_decode_invalidity_date(SshAsn1Context context,
                                              SshAsn1Node    data,
                                              SshBerTime     date);

/* Encode invalidity dates. */
SshAsn1Node ssh_x509_encode_invalidity_date(SshAsn1Context context,
                                            SshBerTime date);


/***********************************************/
/* x509policy_encode.c and x509policy_decode.c */
/***********************************************/

/* Decode policy information. */
SshX509Status ssh_x509_decode_policy_info(SshAsn1Context context,
                                          SshAsn1Node data,
                                          SshX509ExtPolicyInfo *i);

/* Encode policy information. */
SshAsn1Node ssh_x509_encode_policy_info(SshAsn1Context context,
                                        SshX509ExtPolicyInfo p);

/* Decode policy mappings. */
SshX509Status ssh_x509_decode_policy_mappings(SshAsn1Context context,
                                              SshAsn1Node data,
                                              SshX509ExtPolicyMappings *m);

/* Encode policy mappings. */
SshAsn1Node ssh_x509_encode_policy_mappings(SshAsn1Context context,
                                            SshX509ExtPolicyMappings m);

/* Decode policy constraints. */
SshX509Status ssh_x509_decode_policy_const(SshAsn1Context context,
                                           SshAsn1Node data,
                                           SshX509ExtPolicyConstraints *p);

/* Encode policy constraints. */
SshAsn1Node ssh_x509_encode_policy_const(SshAsn1Context context,
                                         SshX509ExtPolicyConstraints p);

/*******************************************/
/* x509cert_encode.c and x509cert_decode.c */
/*******************************************/

#define SSH_X509_CERT_ENCODE_IS_ASYNCHRONOUS(c) \
  (c != NULL && c->user_encode_cb != NULL_FNPTR)

/* Structure that is used for both sycnhronous and asynchronous
   encoding of certificates and requests. */
typedef struct SshX509CertEncodeContextRec
{
  SshAsn1Context asn1_context;
  SshX509Status rv;
  SshOperationHandle operation_handle;
  SshOperationHandle crypto_handle;
  SshAsn1Node cert_node;
  SshX509Certificate cert;
  SshX509Crl         crl;
  SshPrivateKey issuer_key;
  unsigned char *buf;
  size_t buf_len;
  SshX509EncodeCB user_encode_cb;
  void *user_context;
} *SshX509CertEncodeContext;

typedef struct SshX509VerifyContextRec
{
  SshOperationHandle op_handle;
  SshOperationHandle crypto_handle;
  SshPublicKey       issuer_key;
  /* Signature algorithm. */
  char              *sign;

  /* Verify callback and context. */
  SshX509VerifyCB    verify_cb;
  void              *verify_ctx;

} *SshX509VerifyContext;

SshX509AsyncCallStatus
ssh_x509_cert_encode_internal(SshX509CertEncodeContext encode_context);
SshX509AsyncCallStatus
ssh_x509_crl_encode_internal(SshX509CertEncodeContext encode_context);

/* The finalizing function for encoding of certificates and
   requests. This functions calls the callback given by user
   in asynchronous case. */
void ssh_x509_cert_finalize_encode(SshX509CertEncodeContext
                                          encode_context);

/* The abort function for encoding operation. */
void ssh_x509_cert_encode_async_abort(void *context);

/* Verification finalization function. Called after the verification
   has succeeded. */
void ssh_x509_verify_async_finish(SshCryptoStatus status, void *context);
/* Verification abort function. This is called after everything is done. */
void ssh_x509_verify_async_abort(void *context);

/* Decode generic X509 extensions. */
SshX509Status ssh_x509_cert_decode_extension(SshAsn1Context context,
                                             SshAsn1Node extension_node,
                                             SshX509Certificate c);
SshX509Status ssh_x509_crl_decode_extension(SshAsn1Context context,
                                            SshAsn1Node extension_node,
                                            SshX509Crl c);
SshX509Status ssh_x509_crl_rev_decode_extension(SshAsn1Context context,
                                                SshAsn1Node extension_node,
                                                SshX509RevokedCerts c,
                                                SshX509Config config);

/* Encode certificate X509 extensions. */
SshX509Status ssh_x509_cert_encode_extension(SshAsn1Context context,
                                             SshX509Certificate c,
                                             SshAsn1Node *ret);
SshX509Status ssh_x509_crl_encode_extension(SshAsn1Context context,
                                            SshX509Crl crl,
                                            SshAsn1Node *ret);
SshX509Status ssh_x509_crl_rev_encode_extension(SshAsn1Context context,
                                                SshX509RevokedCerts c,
                                                SshAsn1Node *ret,
                                                SshX509Config config);

/* Very low level encoding and decoding. */
SshX509AsyncCallStatus
ssh_x509_crl_encode_asn1(SshX509CertEncodeContext encode_context);

SshX509Status ssh_x509_crl_decode_asn1(SshAsn1Context context,
                                       SshAsn1Node    crl_node,
                                       SshX509Crl     crl);

Boolean
ssh_x509_ext_info_available(SshUInt32 ext_available,
                            SshUInt32 ext_critical,
                            unsigned int type,
                            Boolean *critical);

#endif /* X509INTERNAL_H */
