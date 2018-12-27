/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   util_mscapi.h
*/

#ifndef UTIL_MSCAPI_H
#define UTIL_MSCAPI_H

#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI

#include <wincrypt.h>

typedef PCCERT_CONTEXT SshCertificate;
typedef PCCERT_CHAIN_CONTEXT SshCertificateChain;

/** Initialize the module. Return TRUE on success. */
Boolean
ssh_pm_mscapi_init(void);

/** Uninitialize the module. */
void
ssh_pm_mscapi_uninit(void);

/** Get handle to a cerfificate in a certificate chain. If `prev' is
    NULL, get the first certificate in the chain. If `prev' if
    non-NULL, get the certificate following `prev'. Return NULL if
    there are no more certificates in the chain. The returned handle
    does not need to be freed; all certificate handles in the chain
    are freed when the chain itself is freed. */
SshCertificate
ssh_pm_mscapi_cert_chain_next(SshCertificateChain chain,
                              SshCertificate prev);

/** Check if the certificate is a CA certificate and return TRUE if it
    is, FALSE otherwise. */
Boolean
ssh_pm_mscapi_is_ca_cert(SshCertificate cert);

/** Store the DER encoding of the given certificate into a buffer that
    is allocated using ssh_malloc(). Store pointer to the buffer into
    the location pointed to by `buf' and the length of the encoding
    into the location pointed to by `len'. Return TRUE if succesful,
    FALSE otherwise (in which case nothing remains allocated). */
Boolean
ssh_pm_mscapi_export_local_cert(SshCertificate cert,
                                unsigned char **buf, size_t *len);

/** Decode a DER-encoded certificate, store it into the certificate
    store and put handle to it into the location pointed to by
    `cert'. After use, the handle must be freed using
    ssh_pm_mscapi_free_cert(). Return TRUE if succesful, FALSE
    otherwise. */
Boolean
ssh_pm_mscapi_import_remote_cert(const unsigned char *buf, size_t len,
                                 SshCertificate *cert);

/** Store the DER-encoded subject name of the given certificate into a
    buffer that is allocated using ssh_malloc(). Store pointer to the
    buffer containing the encoding into the location pointed to by
    `buf' and the length of the encoding into the location pointed to
    by `len'. Return TRUE if succesful, FALSE otherwise (in which case
    nothing remains allocated). */
Boolean
ssh_pm_mscapi_cert_subject(SshCertificate cert,
                           unsigned char **buf, size_t *len);

/** Store the DER-encoded issuer name of the given certificate into a
    buffer that is allocated using ssh_malloc(). Store pointer to the
    buffer containing the encoding into the location pointed to by
    `buf' and the length of the encoding into the location pointed to
    by `len'. Return TRUE if succesful, FALSE otherwise (in which case
    nothing remains allocated). */
Boolean
ssh_pm_mscapi_cert_issuer(SshCertificate cert,
                          unsigned char **buf, size_t *len);

/** Store the SHA-1 hash of the public key (aka key identifier) of the
    given certificate into a buffer that is allocated using
    ssh_malloc(). Store pointer to the buffer containing the hash into
    the location pointed to by `buf' and the length of the hash into
    the location pointed to by `len'. Return TRUE if succesful, FALSE
    otherwise (in which case nothing remains allocated). */
Boolean
ssh_pm_mscapi_cert_key_id(SshCertificate cert,
                          unsigned char **buf, size_t *len);

/** Store the subject alternative name of type 'type' of the given
    certificate into a buffer that is allocated using ssh_malloc().
    Store pointer to the buffer containing the encoding into the location
    pointed to by `buf' and the length of the encoding into the location
    pointed to by `len'. Return TRUE if succesful, FALSE otherwise (in which
    case nothing remains allocated).
 */
Boolean
ssh_pm_mscapi_get_altname(SshCertificate cert, SshPmIdentityType type,
                          unsigned char **buf, size_t *len);

/** Convert a null-terminated string into a SshIkev2PayloadID the type
    of which is DN (distinguished name). The returned
    SshIkev2PayloadID as well as its data buffer are allocated using
    ssh_malloc(). */
SshIkev2PayloadID
ssh_pm_mscapi_str_to_dn(const unsigned char *str);

/** Convert a SshIkev2PayloadID the type of which is DN (distinguished
    name) into a null-terminated string. The returned string is
    allocated using ssh_malloc(). */
char *
ssh_pm_mscapi_dn_to_str(SshIkev2PayloadID id);

/** Find a trusted certificate and return handle it. The handle must
    be freed using ssh_pm_mscapi_free_cert(). Return NULL is the
    certificate was not found. The certificate is searched by matching
    `name' with certificate subject name. */
SshCertificate
ssh_pm_mscapi_get_trusted_cert(SshIkev2PayloadID id);

/** Find an user certificate and return handle it. The handle must be
    freed after use using ssh_pm_mscapi_free_cert(). Return NULL is a
    certificate was not found. The certificate is searched by matching
    `id' with certificate subject name and subject alternative
    names. If `prev' is NULL, find the first matching certificate. If
    `prev' is non-null, find the next matching certificate after
    `prev' and free `prev' regardless of whether a new certificate is
    found or not. */
SshCertificate
ssh_pm_mscapi_get_local_cert(SshIkev2PayloadID id, SshCertificate prev);
SshCertificate
ssh_pm_mscapi_get_remote_cert(SshIkev2PayloadID id, SshCertificate prev);

/** Return the certificate chain from a given certitificate to a
    trusted root certificate. The chain must be freed after use using
    ssh_pm_mscapi_free_cert_chain(). Return NULL is the chain can not
    be constructed. */
SshCertificateChain
ssh_pm_mscapi_get_cert_chain(SshCertificate cert, SshUInt32 *ret_error);

/** Return a proxy public key created from the public key of the given
    certificate. The key must be freed using
    ssh_public_key_free(). Return NULL if failed. */
SshPublicKey
ssh_pm_mscapi_get_public_key(SshCertificate cert);

/** Return a proxy private key created from the public key of the
    given certificate. The key must be freed using
    ssh_private_key_free(). Return NULL if failed. */
SshPrivateKey
ssh_pm_mscapi_get_private_key(SshCertificate cert);

/** Release reference to a certificate. */
void
ssh_pm_mscapi_free_cert(SshCertificate cert);

/** Release reference to a certificate chain. */
void
ssh_pm_mscapi_free_cert_chain(SshCertificateChain cert_chain);

/** Compare CA certificates. Returns TRUE if certificates match. */
Boolean
ssh_pm_mscapi_compare_ca(SshPm pm, SshPmCa ca1, SshPmCa ca2);

#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */

#endif /* UTIL_MSCAPI_H */
