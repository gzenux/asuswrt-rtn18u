/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   pad_auth_domain.h
*/

#include "sshincludes.h"

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
#include "cmi.h"
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Return the authorization domain based on the domain name. */
SshPmAuthDomain
ssh_pm_auth_domain_get_by_name(SshPm pm,
                               char *name);

/** Return the default authorization domain. */
SshPmAuthDomain
ssh_pm_auth_domain_get_default(SshPm pm);


/** Check that our negotiation is currently using the
    correct authorization domain. Update it to the negotiation
    context, if necessary. */
Boolean
ssh_pm_auth_domain_check_by_ed(SshPm pm,
                               SshIkev2ExchangeData ed);

/** Initialize authentication domains for Policy Manager. */
Boolean
ssh_pm_auth_domains_init(SshPm pm);

/** Un-initiatialize authentication domains. */
void
ssh_pm_auth_domains_uninit(SshPm pm);


/** Create a new authorization domain and set
    reference count to one. */
SshPmAuthDomain
ssh_pm_auth_domain_create(SshPm pm,
                          char *name);


/** Increase the authentication domain reference count by one. */
void
ssh_pm_auth_domain_take_ref(SshPmAuthDomain ad);

/** Decrease the authentication domain reference count by one and
    destroy it if the reference count decreases to zero. */
void
ssh_pm_auth_domain_destroy(SshPm pm, SshPmAuthDomain ad);

/** Remove all authentication domains and re-create the
    default one. */
Boolean
ssh_pm_reset_auth_domains(SshPm pm);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
/* Iterate through the authentication domains and shut down
   certificate validators. */
void
ssh_pm_cert_validators_stop(SshPm pm,
                            void *final_cb,
                            void *final_cb_context);

/** Add an end user certificate to an authentication domain.

    The certificate can be any certificate.  Typically it would be
    either an intermediate certificate between our own trusted CA and
    our own certificate, or an intermediate CA certificate used by a
    peer that does not send its certificates in a certificate payload.
    The certificate can be in either PEM-encoded ASCII format or in
    raw binary format (this function will try to parse both formats).
    Multiple certificates can be added to the system in this way.
    Certificates added using this function are kept permanently in the
    cache.

    @return
    This function returns TRUE if the certificate was successfully
    added, and FALSE if an error occurred (for example if the
    certificate could not be parsed or memory allocation failed). */

SshCMCertificate
ssh_pm_auth_domain_add_cert(SshPm pm, SshPmAuthDomain ad,
                            const unsigned char *cert,
                            size_t cert_len);

Boolean
ssh_pm_auth_domain_add_cert_to_all(SshPm pm,
                                   const unsigned char *cert,
                                   size_t cert_len);


void
ssh_pm_auth_domain_discard_public_key(SshPm pm, SshPmAuthDomain ad,
                                      SshPublicKey public_key);

void
ssh_pm_auth_domain_discard_public_key_from_all(SshPm pm,
                                               SshPublicKey public_key);

#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_RADIUS
Boolean
ssh_pm_auth_domain_radius_is_configured(SshPmAuthDomain ad);

Boolean
ssh_pm_auth_domain_set_radius_server(SshPmAuthDomain ad,
                                     const char *server,
                                     const char *port,
                                     const char *acct_port,
                                     const unsigned char *secret,
                                     size_t secret_len);
#endif /* SSHDIST_RADIUS */
