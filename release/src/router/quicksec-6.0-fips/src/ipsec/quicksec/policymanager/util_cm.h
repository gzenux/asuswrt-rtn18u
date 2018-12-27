/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   util_cm.h
*/

#ifndef UTIL_CM_H
#define UTIL_CM_H


#ifdef SSHDIST_IKE_CERT_AUTH
#include "sshincludes.h"
#include "sshasn1.h"
#include "x509.h"
#include "cmi.h"
#include "sshbase64.h"

/** TCP connect timeout in seconds for backend TCP connections (LDAP,
    HTTP, OCSP). */
#define SSH_PM_CM_TCP_CONNECT_TIMEOUT   60

/** Timeout in seconds for CMi lookups. */
#define SSH_PM_CM_QUERY_EXPIRATION      120

/** Result for a certificate request. */
struct SshPmCertReqResultRec
{
  int *number_of_certificates;
  SshIkev2CertEncoding **cert_encodings;
  unsigned char ***certs;
  size_t **cert_lengths;
};

typedef struct SshPmCertReqResultRec *SshPmCertReqResult;
typedef struct SshPmCertReqResultRec SshPmCertReqResultStruct;

/** A CA object. */
struct SshPmCaRec
{
  /** ADT header for store in auth domain. */
  SshADTBagHeaderStruct adt_header;

  /** Certificate manager's certificate handle. */
  SshCMCertificate cert;

  /** CA's unique ID (assigned by PM). */
  SshUInt32 id;

  /** Distinguished subject name of the CA certificate. */
  unsigned char *cert_subject_dn;
  size_t cert_subject_dn_len;

 /** Distinguished issuer name of the CA certificate. */
  unsigned char *cert_issuer_dn;
  size_t cert_issuer_dn_len;

 /** Subject public key identifier of the CA certificate. */
  unsigned char *cert_key_id;
  size_t cert_key_id_len;

  /** Flags like in ssh_pm_add_ca(). */
  SshUInt32 flags;
};

typedef struct SshPmCaRec SshPmCaStruct;
typedef struct SshPmCaRec *SshPmCa;


/* ************************** Certificate manager ****************************/

/** Attach certificate manager resource access. */
Boolean ssh_pm_cm_access_init(SshPm pm);
void ssh_pm_cm_access_uninit(SshPm pm);

Boolean ssh_pm_cm_set_access_callback(SshPm pm, SshCMConfig config);

#if 0
/** This function is intented for systems that may want to flush
   certificate validator content prior to freeing tunnels referencing
   to objects within the validator. It is supposedly called from the
   validator for each new certificate and each deleted certificate,
   and on deletion it will remove the deleted certificate from any
   tunnels it is attached to. */
void
ssh_pm_cm_certificate_notify_callback(void *context,
                                      SshCMNotifyEventType event,
                                      SshCMCertificate object);
#endif /* 0 */

/** Initialize certificate manager for the authentication domain `ad'. */
Boolean ssh_pm_cm_init(SshPm pm, SshPmAuthDomain ad);

/** A callback function of this type is called to notify the completion
   of a certificate manager stop operation. */
typedef void (*SshPmCmStopCB)(void *context);

/** Stop the certificate manager of the policy manager `pm'.  The
   function calls the callback function `callback' when the stop
   operation is complete. */
void ssh_pm_cm_stop(SshPmAuthDomain ad,
                    SshPmCmStopCB callback, void *context);

/** Uninitialize the certificate manager of the auth domain `ad'. */
void ssh_pm_cm_uninit(SshPm pm, SshPmAuthDomain ad);

/** Configure CA certificate `cert', `cert_len' as a point of trust for
   the policy manager `pm'.  The argument `id' specifies the scope of
   the trust of this CA.  The argument `flags' is as for the
   ssh_pm_add_ca() and they are copied to the returned CA
   object. Variable external defines whether the CA came from
   external source or from local configuration.
   The function returns an CA structure or NULL if the
   operation failed. */
SshPmCa ssh_pm_cm_new_ca(SshCMContext cm, const unsigned char *cert,
                         size_t cert_len, SshUInt32 id, SshUInt32 flags,
                         Boolean external);

/** Remove the CA certificate `ca' from the list of trusted CA
   certificates of the policy manager `pm'. */
void ssh_pm_cm_remove_ca(SshPmCa ca);

/** Compare CA certificates. Returns TRUE if certificates match. */
Boolean ssh_pm_compare_ca(SshPm pm, SshPmCa ca1, SshPmCa ca2);

/** Add certificate `cert', `cert_len' into certificate manager.  The
   function returns the CM certificate object if the certificate was
   correctly formatted and it was added to the certificate manager (or
   it was already added) and NULL on error.  The certificate will be
   locked in memory if the certificate is local.  You must call
   ssh_pm_discard_public_key() for the certificate's public key to
   unlock it from the certificate manager. external flag should be
   set if the certificate came from IKE negotiation. */
SshCMCertificate
ssh_pm_cm_new_certificate(SshCMContext cm, const unsigned char *cert,
                          size_t cert_len, Boolean external);


/** Notify certificate manager that the policy manager will not use the
   public key anymore.  The certificate manager will unlock all
   certificates matching the public key from its cache. */
void
ssh_pm_discard_public_key(SshCMContext cm, SshPublicKey public_key);


/** Add CRL `crl', `crl_len' into certificate manager.  The function
   returns TRUE if the CRL was correctly formatted and it was added to
   the certificate manager (or it was already added) and FALSE
   otherwise. The external flag defines whether this CRL is to be
   locked in the Cmi or can it be thrown away if the certificate cache is
   near to its limits. */
Boolean
ssh_pm_cm_new_crl(SshCMContext cm, const unsigned char *crl,
                  size_t crl_len, Boolean external);


typedef void
(*SshPmIkeRequestCertificatesCB)(int *number_of_certificates,
                                 SshIkev2CertEncoding **cert_encodings,
                                 unsigned char ***certs,
                                 size_t **cert_lengths,
                                 void *context);

/** Execute the certificate request operation for the given CAs. The
   sub-thread will eventually call the completion callback `callback'
   to notify the success of the operation.

   Note that the `cmt_cr' sub-structure of `p1' must be initialized
   before this function is called. */
void
ssh_pm_start_certificate_request(
                                 SshPm pm, SshPmP1 p1, SshUInt32 number_of_cas,
                                 SshIkev2CertEncoding *ca_encodings,
                                 unsigned char **certificate_authorities,
                                 size_t *certificate_authority_lens,
                                 SshPmIkeRequestCertificatesCB callback,
                                 void *context);

/** Free certificate request result `r' that was done for `num_cas'
   CAs. */
void ssh_pm_cert_request_result_free(SshPmCertReqResult r, SshUInt32 num_cas);

/** Try to decode PEM data `data', `data_len'.  The argument
   `not_pem_return' is set to FALSE if the input data was not PEM
   encoded.  If the decode operation is successful, the function
   returns ssh_malloc()ated binary blob and its length in
   `len_return'.  The function returns NULL if the input was not PEM
   encoded or the system run out of memory.  You can tell the
   difference between these return values by investigating the value
   of `not_pem_return' in the error case. */
unsigned char *ssh_pm_pem_to_binary(const unsigned char *data, size_t data_len,
                                    size_t *len_return,
                                    Boolean *not_pem_return);

/** Returns the subject name encoded as IKE payload ID from the given
   certificate (or opened certificate).  Additionally the function
   fills in the Alternative Subject Names into `altnames' array (which
   it allocates to hold `naltnames' pointers to ike payloads it
   allocates).  If the argument `public_key_return' is not NULL, it is
   set to contain the public key of the certificate.  It is up to the
   caller to deallocate the results.  The function returns NULL if it
   can not extract the names from the certificates or if it runs out
   of memory. */
SshIkev2PayloadID
ssh_pm_cert_names(const unsigned char *cert, size_t cert_len,
                  SshIkev2PayloadID **altnames, size_t *naltnames,
                  SshPublicKey *public_key_return);

SshIkev2PayloadID
ssh_pm_cert_x509_names(SshX509Certificate x509cert,
                       SshIkev2PayloadID **altnames, size_t *naltnames,
                       SshPublicKey *public_key_return);


/** Render function for `Subject Name' of the SshCMCertificate
   `datum'. */
int ssh_pm_cert_subject_render(unsigned char *buf, int buf_size,
                               int precision, void *datum);


typedef enum
{
  SSH_PM_CM_PUBLIC_KEY,
  SSH_PM_CM_PRIVATE_KEY,
} SshPmCmObjectType;

/** For ECDSA certificates, this function retrieves the applicable signature
    scheme consistent with RFC 4754. Scheme may be located from any of the
    enumerated SshPmCmObjectType value */
Boolean ssh_pm_get_key_scheme(void * key,
                              SshPmCmObjectType type,
                              const char ** scheme);
/* ****************** IKEv2 policy calls ***********************************/


SshOperationHandle
ssh_pm_ike_get_cas(SshSADHandle sad_handle,
                   SshIkev2ExchangeData ed,
                   SshIkev2PadGetCAsCB reply_callback,
                   void *reply_callback_context);

SshOperationHandle
ssh_pm_ike_get_certificates(SshSADHandle sad_handle,
                            SshIkev2ExchangeData ed,
                            SshIkev2PadGetCertificatesCB reply_callback,
                            void *reply_callback_context);

SshOperationHandle
ssh_pm_ike_public_key(SshSADHandle sad_handle,
                      SshIkev2ExchangeData ed,
                      SshIkev2PadPublicKeyCB reply_callback,
                      void *reply_callback_context);

void
ssh_pm_ike_new_certificate_request(SshSADHandle sad_handle,
                                   SshIkev2ExchangeData ed,
                                   SshIkev2CertEncoding ca_encoding,
                                   const unsigned char *certificate_authority,
                                   size_t certificate_authority_len);

void
ssh_pm_ike_new_certificate(SshSADHandle sad_handle,
                           SshIkev2ExchangeData ed,
                           SshIkev2CertEncoding cert_encoding,
                           const unsigned char *cert_data,
                           size_t cert_data_len);

SshCMCertificate
ssh_pm_get_certificate_by_kid(SshPm pm, unsigned char *kid, size_t kid_len);

Boolean
ssh_pm_get_certificate_kid(SshPm pm, const unsigned char *cert,
                           size_t cert_len, unsigned char **kid_ret,
                           size_t *kid_ret_len);
#endif /* SSHDIST_IKE_CERT_AUTH */
#endif /* UTIL_CM_H */

/** eof */
