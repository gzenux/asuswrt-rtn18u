/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager authentication domains.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmPADAuthDomain"


/** Returns authorization domain based on domain name */
SshPmAuthDomain
ssh_pm_auth_domain_get_by_name(SshPm pm,
                               char *name)
{
  SshPmAuthDomainStruct ad_probe;
  SshPmAuthDomain ad;
  SshADTHandle h;

  ad_probe.auth_domain_name = name;
  h = ssh_adt_get_handle_to_equal(pm->auth_domains, &ad_probe);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Could not locate authentication domain %s", name));
      return NULL;
    }

  ad = ssh_adt_get(pm->auth_domains, h);

  return ad;
}

SshPmAuthDomain
ssh_pm_auth_domain_get_default(SshPm pm)
{
  SSH_ASSERT(pm->default_auth_domain != NULL);

  return pm->default_auth_domain;
}

static int
ad_name_compare(char *ad1_name, char *ad2_name)
{
  if (!ad1_name && ad2_name)
    return 1;
  else if (ad1_name && !ad2_name)
    return -1;
  else if (!ad1_name && !ad2_name)
    return 0;
  else
    return strcmp(ad1_name, ad2_name);
}

/** Check that our negotiation is currently using the
    correct authorization domain. Update it to negotiation
    context if necessary. */
Boolean
ssh_pm_auth_domain_check_by_ed(SshPm pm,
                               SshIkev2ExchangeData ed)
{
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;

  SSH_PM_ASSERT_P1(p1);
  SSH_PM_ASSERT_P1N(p1);

  if (p1->n->tunnel == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Negotiation tunnel not set, unable to get "
                              "authentication domain"));
      return FALSE;
    }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  else if (p1->auth_domain &&
           p1->n->tunnel->second_auth_domain_name &&
           ed->ike_ed->first_auth_done)
    {
      if (ad_name_compare(p1->auth_domain->auth_domain_name,
                          p1->n->tunnel->second_auth_domain_name))
        {
          SshPmAuthDomain first_round_auth_domain = NULL;

          char *second_auth_domain_name =
            p1->n->tunnel->second_auth_domain_name;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Negotiation moving to second authentication, switching "
                     "to authentication domain %s.",
                     second_auth_domain_name));

          first_round_auth_domain = p1->auth_domain;
          p1->auth_domain = NULL;

          p1->auth_domain
            = ssh_pm_auth_domain_get_by_name(pm,
                                             second_auth_domain_name);

          if (!p1->auth_domain)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Invalid configuration in tunnel %s, second "
                         "authentication domain %s does not exist.",
                         p1->n->tunnel->tunnel_name,
                         second_auth_domain_name));

              /* On error-case we do not store reference to the first auth
                 domain */
              ssh_pm_auth_domain_destroy(pm, first_round_auth_domain);
              return FALSE;
            }

          /* Store the old domain to prevent it from being removed during
             p1 lifetime. */
          p1->first_round_auth_domain = first_round_auth_domain;
        }
      else
        return TRUE;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
  else if (p1->auth_domain &&
           ad_name_compare(p1->auth_domain->auth_domain_name,
                           p1->n->tunnel->auth_domain_name))
    {
      /* If the tunnel has changed during first authentication */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Tunnel change changed authentication domain during "
                 "negotiation."));

      ssh_pm_auth_domain_destroy(pm, p1->auth_domain);
      p1->auth_domain = NULL;

      p1->auth_domain
        = ssh_pm_auth_domain_get_by_name(pm,
                                         p1->n->tunnel->auth_domain_name);

      if (!p1->auth_domain)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Invalid configuration in tunnel %s, authentication "
                     "domain %s does not exist.",
                     p1->n->tunnel->tunnel_name,
                     p1->n->tunnel->auth_domain_name));
          return FALSE;
        }

    }
  else if (p1->auth_domain)
    {
      /* Everything is ok, continue */
      return TRUE;
    }
  else if (p1->n->tunnel->auth_domain_name)
    {
      /* If the tunnel has authentication domain set */
      p1->auth_domain
        = ssh_pm_auth_domain_get_by_name(pm,
                                         p1->n->tunnel->auth_domain_name);

      if (!p1->auth_domain)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Invalid configuration in tunnel %s, authentication "
                     "domain %s does not exist.",
                     p1->n->tunnel->tunnel_name,
                     p1->n->tunnel->auth_domain_name));
          return FALSE;
        }
    }
  else
    {
      /* Use default domain for this negotiation, as it is not set
         for the tunnel. */
      p1->auth_domain = pm->default_auth_domain;
    }

  if (p1->auth_domain)
    {
      ssh_pm_auth_domain_take_ref(p1->auth_domain);
      return TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get a suitable authentication "
                             "domain for the negotiation."));
      return FALSE;
    }
}



/*************** Functions to handle authentication domains  *************** */

static SshUInt32
ssh_pm_auth_domain_hash_adt(void *ptr, void *ctx)
{
  SshPmAuthDomain ad = (SshPmAuthDomain) ptr;
  SshUInt32 hash = 0;
  int i;

  if (ad->auth_domain_name == NULL)
    return hash;

  for (i = 0; ad->auth_domain_name[i]; i++)
    hash = ((hash << 5) ^ (unsigned char) ad->auth_domain_name[i]
            ^ (hash >> 16) ^ (hash >> 7));

  return hash;
}

static int
ssh_pm_auth_domain_compare_adt(void *ptr1, void *ptr2, void *ctx)
{
  SshPmAuthDomain ad1 = (SshPmAuthDomain) ptr1;
  SshPmAuthDomain ad2 = (SshPmAuthDomain) ptr2;

  if (!ad1->auth_domain_name && !ad2->auth_domain_name)
    return 0;
  else if (!ad1->auth_domain_name)
    return -1;
  else if (!ad2->auth_domain_name)
    return 1;
  else
    return strcmp(ad1->auth_domain_name, ad2->auth_domain_name);
}

static void
ssh_pm_auth_domain_destroy_adt(void *ptr, void *ctx)
{
  SshPmAuthDomain ad = (SshPmAuthDomain) ptr;
  SshPm pm = (SshPm) ctx;

  ssh_pm_auth_domain_destroy(pm, ad);
}


/** Initializes authentication domains for PM  */
Boolean
ssh_pm_auth_domains_init(SshPm pm)
{
  SshPmAuthDomain default_ad;

  SSH_ASSERT(pm->auth_domains == NULL);

  pm->auth_domains
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshPmAuthDomainStruct,
                                               adt_header),
                             SSH_ADT_HASH,     ssh_pm_auth_domain_hash_adt,
                             SSH_ADT_COMPARE,  ssh_pm_auth_domain_compare_adt,
                             SSH_ADT_DESTROY,  ssh_pm_auth_domain_destroy_adt,
                             SSH_ADT_CONTEXT,  pm,

                             SSH_ADT_ARGS_END);

  if (pm->auth_domains == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Out of memory while creating authentication "
                              "domain store."));
      return FALSE;
    }

  /* Creation of the auth domain successful, add the default domain
     to the structure. */
  default_ad = ssh_pm_auth_domain_create(pm, NULL);

  if (!default_ad)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Out of memory while creating default "
                              "authentication domain"));
      ssh_pm_auth_domains_uninit(pm);
      return FALSE;
    }

  pm->default_auth_domain = default_ad;
  ssh_pm_auth_domain_take_ref(default_ad);

  return TRUE;
}

/** Un-initiatialize the authentication domains */
void
ssh_pm_auth_domains_uninit(SshPm pm)
{
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Uninitializing all authentication domains"));

  if (pm->auth_domains != NULL)
    {
      ssh_adt_destroy(pm->auth_domains);
      pm->auth_domains = NULL;
    }

  if (pm->default_auth_domain != NULL)
    {
      ssh_pm_auth_domain_destroy(pm, pm->default_auth_domain);
      pm->default_auth_domain = NULL;
    }

  return;
}

#ifdef SSHDIST_IKE_CERT_AUTH
static int
ssh_pm_ca_compare_adt(void *ptr1, void *ptr2, void *ctx)
{
  SshPmCa ca1 = (SshPmCa) ptr1;
  SshPmCa ca2 = (SshPmCa) ptr2;

  return ca1->id - ca2->id;
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Creates new authorization domain and sets
    reference count to one */
SshPmAuthDomain
ssh_pm_auth_domain_create(SshPm pm,
                          char *name)
{
  SshPmAuthDomain ad = NULL;
  char *auth_domain_name = NULL;

  if (!name && pm->default_auth_domain)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Default authentication domain already exists"));
      return NULL;
    }

  if (name && ssh_pm_auth_domain_get_by_name(pm, name))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Authentication domain %s already exists", name));
      return NULL;
    }


  ad = ssh_malloc(sizeof(*ad));

  if (!ad)
    return NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocated %s authentication domain %s",
                               name ? "new" : "default",
                               name ? name : ""));

  ad->auth_domain_name = NULL;
  ad->ike_preshared_keys = NULL;

#ifdef SSHDIST_IKE_CERT_AUTH
  ad->ca_container = NULL;
#ifdef SSHDIST_CERT
  ad->cm = NULL;
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (name)
    {
      auth_domain_name = ssh_strdup(name);

      if (!auth_domain_name)
        goto error;
    }

  ad->pm = pm;
  ad->auth_domain_name = auth_domain_name;

  /* This is increased if default authentication domain is reset.
     For regular auth domains this is always 0. */
  ad->generation = 0;

#ifdef SSHDIST_IKE_CERT_AUTH

  /* Initialize the CA store */
  ad->num_cas = 0;
  ad->cas = NULL;

  ad->ca_container =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmCaStruct,
                                             adt_header),
                           SSH_ADT_COMPARE, ssh_pm_ca_compare_adt,
                           SSH_ADT_CONTEXT, pm,
                           SSH_ADT_ARGS_END);
  if (!ad->ca_container)
    goto error;

#ifdef SSHDIST_CERT
  ad->cm_stop_callback = NULL;
  ad->cm_stop_callback_context = NULL;
  ad->cm_stopped = FALSE;

  /* Initialize the certificate validator */
  if (!ssh_pm_cm_init(pm, ad))
    goto error;
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_EXTERNALKEY
  /* Install certificates from externalkey providers to this auth domain. */
  if (!ssh_pm_ek_refresh_certificates(pm, ad))
    goto error;
#endif /* SSHDIST_EXTERNALKEY */

  /* Initialize the preshared key cache. */
  if (!ssh_pm_ike_preshared_keys_create(pm, ad))
    goto error;

#ifdef SSHDIST_IKE_EAP_AUTH
  /* Initialize EAP. */
  if (!ssh_pm_eap_init(ad))
    goto error;

  ad->eap_protocols = NULL;
  ad->num_eap_protocols = 0;
#endif /* SSHDIST_IKE_EAP_AUTH */


#ifdef SSHDIST_RADIUS
  ad->radius_client = NULL;
  ad->radius_server_info = NULL;
  ad->radius_auth = NULL;
#endif /* SSHDIST_RADIUS */

  ad->private_key = NULL;
  ad->public_key = NULL;

  ad->passwd_auth = NULL;

  /* Success */
  ad->reference_count = 1;

  ssh_adt_insert(pm->auth_domains, ad);

  return ad;

 error:
  SSH_DEBUG(SSH_D_ERROR, ("Failed to create authentication domain"));

  if (ad->auth_domain_name)
    ssh_free(ad->auth_domain_name);

  if (ad->ike_preshared_keys)
    ssh_pm_ike_preshared_keys_destroy(ad);

#ifdef SSHDIST_IKE_CERT_AUTH
  if (ad->ca_container)
    ssh_adt_destroy(ad->ca_container);
#ifdef SSHDIST_CERT
  if (ad->cm)
    ssh_pm_cm_uninit(pm, ad);
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_free(ad);

  return NULL;
}


/** Increases auth domain reference cound by one */
void
ssh_pm_auth_domain_take_ref(SshPmAuthDomain ad)
{
  ad->reference_count++;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Reference count for %s authentication domain %s is %d",
             ad->auth_domain_name ? "regular" : "default",
             ad->auth_domain_name ? ad->auth_domain_name : "",
             ad->reference_count));

  return;
}

/** Decreases auth domain reference count by one and
    destroys it if reference count decreases to zero. */
void
ssh_pm_auth_domain_destroy(SshPm pm, SshPmAuthDomain ad)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  SshUInt32 i;
#endif /* SSHDIST_IKE_CERT_AUTH */

  ad->reference_count--;

  if (ad->reference_count)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Reference count for %s authentication domain %s is %d",
                 ad->auth_domain_name ? "regular" : "default",
                 ad->auth_domain_name ? ad->auth_domain_name : "",
                 ad->reference_count));

      /* Still references left */
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Destroying %s authentication domain %s",
             ad->auth_domain_name ? "regular" : "default",
             ad->auth_domain_name ? ad->auth_domain_name : ""));

  ssh_pm_ike_preshared_keys_destroy(ad);

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  ssh_pm_cm_uninit(pm, ad);
#endif /* SSHDIST_CERT */
  ssh_adt_destroy(ad->ca_container);

  for (i = 0; i < ad->num_cas; i++)
    {
      ssh_free(ad->cas[i]->cert_key_id);
      ssh_free(ad->cas[i]->cert_subject_dn);
      ssh_free(ad->cas[i]->cert_issuer_dn);
      ssh_free(ad->cas[i]);
    }

  if (ad->cas)
    ssh_free(ad->cas);
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (ad->private_key)
    ssh_private_key_free(ad->private_key);
  if (ad->public_key)
    ssh_public_key_free(ad->public_key);

#ifdef SSHDIST_IKE_EAP_AUTH
  ssh_pm_eap_uninit(ad);

  ssh_free(ad->eap_protocols);
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_RADIUS
  if (ad->radius_client)
    ssh_radius_client_destroy(ad->radius_client);

  if (ad->radius_server_info)
    ssh_radius_client_server_info_destroy(ad->radius_server_info);

  if (ad->radius_auth)
    ssh_pm_auth_radius_destroy(ad->radius_auth);
#endif /* SSHDIST_RADIUS */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_IKE_XAUTH
   if (ad->passwd_auth)
     ssh_pm_auth_passwd_destroy(ad->passwd_auth);
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  ssh_free(ad->auth_domain_name);
  ssh_free(ad);

  return;
}

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
/*********** Functions to stop certificate validators  ********************* */

static void
ssh_pm_cert_validators_stop_cb(void *context)
{
  SshADTHandle h;
  SshPmAuthDomain ad = (SshPmAuthDomain) context;
  SshPm pm = ad->pm;

  /* Validator in this domain has stopped */
  ad->cm_stopped = TRUE;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Certificate validator in %s auth domain %s has been stopped",
             ad->auth_domain_name ? "regular" : "default",
             ad->auth_domain_name ? ad->auth_domain_name : ""));

  /* Enumerate through validators and check if all have stopped. */
  for (h = ssh_adt_enumerate_start(pm->auth_domains);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->auth_domains, h))
    {
      ad = ssh_adt_get(pm->auth_domains, h);

      if (!ad->cm_stopped)
        {
          /* Some validators are still running */
          return;
        }
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("All certificate validators have stopped"));

  /* Inform the shutdown process that we are done */
  ((SshPmCmStopCB) ad->cm_stop_callback)(ad->cm_stop_callback_context);
}


/* Iterate through authentication domains and shutdown
   certificate validators */
void
ssh_pm_cert_validators_stop(SshPm pm,
                            void *final_callback,
                            void *final_cb_context)
{
  SshADTHandle h;
  SshPmAuthDomain ad = NULL;

  if (!pm->auth_domains)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Authentication domains already destroyed or "
                             "never created!"));
      return;
    }

  /* Enumerate through validators and order them to stop. */
  for (h = ssh_adt_enumerate_start(pm->auth_domains);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->auth_domains, h))
    {
      ad = ssh_adt_get(pm->auth_domains, h);

      ad->cm_stop_callback = final_callback;
      ad->cm_stop_callback_context = final_cb_context;
      ad->cm_stopped = FALSE;

      ssh_pm_cm_stop(ad, ssh_pm_cert_validators_stop_cb, ad);
    }
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */



/*********** Functions to handle authentication domain objects  ************ */

#ifdef SSHDIST_IKE_CERT_AUTH
static void
clear_certificates_from_p1(SshPmP1 p1)
{
  if (p1->auth_cert)
    {
#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
      ssh_pm_mscapi_free_cert(p1->auth_cert);
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
      p1->auth_cert = NULL;
    }
  if (p1->auth_ca_cert)
    {
#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
      ssh_pm_mscapi_free_cert(p1->auth_ca_cert);
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
      p1->auth_ca_cert = NULL;
    }
}
#endif /* SSHDIST_IKE_CERT_AUTH */

Boolean
ssh_pm_reset_auth_domains(SshPm pm)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  SshPmP1 p1;
  int i;
#endif /* SSHDIST_IKE_CERT_AUTH */
  SshUInt32 generation;
  SshPmAuthDomain backup_default_ad;
  SshADTContainer backup_ads;

  SSH_ASSERT(pm->default_auth_domain != NULL);

  generation = pm->default_auth_domain->generation;

  /* Store backup in case of failure */
  backup_default_ad = pm->default_auth_domain;
  backup_ads = pm->auth_domains;

  pm->default_auth_domain = NULL;
  pm->auth_domains = NULL;

  generation++;

  if (!ssh_pm_auth_domains_init(pm))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to initialize authentication domains "
                              "during reset!"));

      /* We were not succesfull, restore earlier configuration */
      SSH_ASSERT(pm->default_auth_domain == NULL);
      SSH_ASSERT(pm->auth_domains == NULL);

      pm->default_auth_domain = backup_default_ad;
      pm->auth_domains = backup_ads;

      return FALSE;
    }
  else
    {
      pm->default_auth_domain->generation = generation;

      /* We were succesfull, destroy old configuration */
      ssh_adt_destroy(backup_ads);
      ssh_pm_auth_domain_destroy(pm, backup_default_ad);

#ifdef SSHDIST_IKE_CERT_AUTH
      /* Destroy all the references to stored certificates from
         policymanager-side */
      for (p1 = pm->active_p1_negotiations; p1; p1 = p1->n->next)
        {
          clear_certificates_from_p1(p1);
        }

      for (i = 0; i < SSH_PM_IKE_SA_HASH_TABLE_SIZE; i++)
        {
          for (p1 = pm->ike_sa_hash[i]; p1; p1 = p1->hash_next)
            {
              clear_certificates_from_p1(p1);
            }
        }
#endif /* SSHDIST_IKE_CERT_AUTH */

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Reset all authentication domains to their initial state, "
                 "current generation %d", generation));

      return TRUE;
    }
}



















































































































/*************** Functions to set certificate authentication ************** */

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
Boolean
ssh_pm_auth_domain_add_ca(SshPm pm, SshPmAuthDomain ad,
                          const unsigned char *cert,
                          size_t cert_len,
                          SshUInt32 flags)
{
  SshPmCa ca, *new_cas;
  SshUInt32 ca_id = pm->next_ca_id++;
  SshUInt32 i;

  if (!ad)
    ad = pm->default_auth_domain;

  SSH_ASSERT(ad != NULL);

  /* Configure the certificate into the system. */
  ca = ssh_pm_cm_new_ca(ad->cm, cert, cert_len, ca_id, flags, FALSE);

  if (ca == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to configure new CA"));
      return FALSE;
    }

  for (i = 0; i < ad->num_cas; i++)
    {
      if (ssh_pm_compare_ca(pm, ca, ad->cas[i]))
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("CA is already configured to authentication domain"));
          ca->cert = NULL;
          ssh_pm_cm_remove_ca(ca);
          return TRUE;
        }
    }

  /* Add it to the policy manager's list of CA's. */
  if (ad->num_cas)
    new_cas = ssh_realloc(ad->cas,
                          ad->num_cas * sizeof(*ad->cas),
                          ((ad->num_cas + 1) * sizeof(*ad->cas)));
  else
    new_cas = ssh_malloc(sizeof(*ad->cas));

  if (new_cas == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate memory for new CA certificate"));
      ssh_pm_cm_remove_ca(ca);
      return FALSE;
    }

  ad->cas = new_cas;
  ad->cas[ad->num_cas++] = ca;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Added CA to %s authentication domain %s",
             ad->auth_domain_name ? "regular" : "default",
             ad->auth_domain_name ? ad->auth_domain_name : ""));
  return TRUE;
}
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
Boolean
ssh_pm_auth_domain_add_ca(SshPm pm, SshPmAuthDomain ad,
                          const unsigned char *id_encoding,
                          size_t id_encoding_len, SshUInt32 flags)
{
  SshIkev2PayloadID id = NULL;
  SshCertificate cert = NULL;
  SshPmCa ca = NULL, *new_cas = NULL;
  Boolean malformed;
  SshUInt32 i;

  if (!ad)
    ad = pm->default_auth_domain;

  SSH_ASSERT(ad != NULL);

  ca = ssh_calloc(1, sizeof *ca);
  if (ca == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot allocate CA entry"));
      goto fail;
    }

  id = ssh_pm_decode_identity(((flags & 0x000f0000) >> 16), id_encoding,
                              id_encoding_len, &malformed);
  /* Get IKE id type stored in the upper 16 bits of flags. */
  if (id == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot decode CA identity"));
      goto fail;
    }

  cert = ssh_pm_mscapi_get_trusted_cert(id);
  if (cert == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get certificate for CA %@",
                             ssh_pm_ike_id_render, id));
      goto fail;
    }

  if (!ssh_pm_mscapi_cert_key_id(cert, &ca->cert_key_id,
                                  &ca->cert_key_id_len) ||
      !ssh_pm_mscapi_cert_subject(cert, &ca->cert_subject_dn,
                                  &ca->cert_subject_dn_len) ||
      !ssh_pm_mscapi_cert_issuer(cert, &ca->cert_issuer_dn,
                                 &ca->cert_issuer_dn_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get names and key id for CA %@",
                             ssh_pm_ike_id_render, id));
      goto fail;
    }

  for (i = 0; i < ad->num_cas; i++)
    {
      if (ssh_pm_mscapi_compare_ca(pm , ca, ad->cas[i]))
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("CA is already configured to policy manager"));
          if (ca)
            {
              if (ca->cert_key_id)
                ssh_free(ca->cert_key_id);
              if (ca->cert_subject_dn)
                ssh_free(ca->cert_subject_dn);
              if (ca->cert_issuer_dn)
                ssh_free(ca->cert_issuer_dn);
              ssh_free(ca);
            }
          goto out;
        }
    }

  if (ad->num_cas)
    new_cas = ssh_realloc(ad->cas,
                          ad->num_cas * sizeof(*ad->cas),
                          ((ad->num_cas + 1) * sizeof(*ad->cas)));
  else
    new_cas = ssh_malloc(sizeof(*ad->cas));

  if (new_cas == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate memory for new CA entry"));
      goto fail;
    }

  ad->cas = new_cas;
  ad->cas[ad->num_cas++] = ca;

 out:
  ssh_pm_mscapi_free_cert(cert);
  ssh_pm_ikev2_payload_id_free(id);
  return TRUE;

 fail:
  if (ca)
    {
      if (ca->cert_key_id)
        ssh_free(ca->cert_key_id);
      if (ca->cert_subject_dn)
        ssh_free(ca->cert_subject_dn);
      if (ca->cert_issuer_dn)
        ssh_free(ca->cert_issuer_dn);
      ssh_free(ca);
    }
  if (cert)
    ssh_pm_mscapi_free_cert(cert);
  if (id)
    ssh_pm_ikev2_payload_id_free(id);
  return FALSE;
}
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */

#ifdef SSHDIST_CERT













SshCMCertificate
ssh_pm_auth_domain_add_cert_internal(SshPm pm, SshPmAuthDomain ad,
                                     const unsigned char *cert,
                                     size_t cert_len,
                                     Boolean external)
{
  SSH_ASSERT(ad != NULL);

  return ssh_pm_cm_new_certificate(ad->cm, cert, cert_len, external);
}

SshCMCertificate
ssh_pm_auth_domain_add_cert(SshPm pm, SshPmAuthDomain ad,
                            const unsigned char *cert,
                            size_t cert_len)
{
  if (!ad)
    ad = pm->default_auth_domain;

  SSH_ASSERT(ad != NULL);

  return ssh_pm_auth_domain_add_cert_internal(pm, ad, cert, cert_len, FALSE);
}

Boolean
ssh_pm_auth_domain_add_cert_to_all(SshPm pm,
                                   const unsigned char *cert,
                                   size_t cert_len)
{
  SshADTHandle h;
  SshPmAuthDomain ad;
  Boolean success = TRUE;

  /* Enumerate through auth domains and add cert to all */
  for (h = ssh_adt_enumerate_start(pm->auth_domains);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->auth_domains, h))
    {
      ad = ssh_adt_get(pm->auth_domains, h);

      if (!ssh_pm_cm_new_certificate(ad->cm, cert, cert_len, FALSE))
        {
          success = FALSE;
          SSH_DEBUG(SSH_D_ERROR,
                    ("Adding certificate to %s authentication domain %s "
                     "failed.",
                     ad->auth_domain_name ? "regular" : "default",
                     ad->auth_domain_name ? ad->auth_domain_name : ""));
        }

      if (!success)
        break;
    }

  return success;
}

Boolean
ssh_pm_auth_domain_add_crl(SshPm pm, SshPmAuthDomain ad,
                           const unsigned char *crl, size_t crl_len)
{
  if (!ad)
    ad = pm->default_auth_domain;

  SSH_ASSERT(ad != NULL);

  return ssh_pm_cm_new_crl(ad->cm, crl, crl_len, FALSE);
}

void
ssh_pm_auth_domain_discard_public_key(SshPm pm, SshPmAuthDomain ad,
                                      SshPublicKey public_key)
{
  if (!ad)
    ad = pm->default_auth_domain;

  if (ad)
    {
      ssh_pm_discard_public_key(ad->cm, public_key);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Cannot discard public key, default authentication "
                 "domain has already been removed."));
    }
}

void
ssh_pm_auth_domain_discard_public_key_from_all(SshPm pm,
                                               SshPublicKey public_key)
{
  SshADTHandle h;
  SshPmAuthDomain ad;

  /* Enumerate through auth domains and add cert to all */
  for (h = ssh_adt_enumerate_start(pm->auth_domains);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->auth_domains, h))
    {
      ad = ssh_adt_get(pm->auth_domains, h);

      ssh_pm_discard_public_key(ad->cm, public_key);
    }

  return;
}

#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */


#ifdef SSHDIST_RADIUS
Boolean
ssh_pm_auth_domain_radius_is_configured(SshPmAuthDomain ad)
{
  if (ad->radius_server_info)
    return TRUE;
  else
    return FALSE;
}

Boolean
ssh_pm_auth_domain_set_radius_server(SshPmAuthDomain ad,
                                     const char *server,
                                     const char *port,
                                     const char *acct_port,
                                     const unsigned char *secret,
                                     size_t secret_len)
{
  return ssh_radius_client_server_info_add_server(ad->radius_server_info,
                                                  server, port, acct_port,
                                                  secret, secret_len);

}
#endif /* SSHDIST_RADIUS */

/* RAW RSA keys authentication */
Boolean
ssh_pm_auth_domain_set_private_key(SshPmAuthDomain ad,
                                   SshPrivateKey private_key)
{
  if (ssh_private_key_select_scheme(private_key,
                                    SSH_PKF_SIGN,
                                    "rsa-pkcs1-sha1",
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to set private key scheme"));
      return FALSE;
    }

  if (ad->private_key)
    ssh_private_key_free(ad->private_key);

  ad->private_key = private_key;
  return TRUE;
}

/* RAW RSA keys authentication */
Boolean
ssh_pm_auth_domain_set_public_key(SshPmAuthDomain ad,
                                  SshPublicKey public_key)
{
  /* Set the proper scheme for RSA. */
  if (ssh_public_key_select_scheme(public_key,
                                   SSH_PKF_SIGN,
                                   "rsa-pkcs1-implicit",
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to set public key scheme"));
      return FALSE;
    }

  if (ad->public_key)
    ssh_public_key_free(ad->public_key);

  ad->public_key = public_key;
  return TRUE;
}

#ifdef SSHDIST_IKE_EAP_AUTH
Boolean
ssh_pm_auth_domain_accept_eap_auth(SshPmAuthDomain ad,
                                   SshUInt8 eap_type, SshUInt8 preference,
                                   SshUInt32 transform)
{
  SshPmEapProtocol new_eap_protocols;
  SshUInt32 index;

  SSH_DEBUG(SSH_D_LOWSTART, ("Accept EAP authentication protocol %d with "
                             "preference %d", eap_type, preference));

  if (eap_type == SSH_EAP_TYPE_NONE)
    return TRUE;

  /* Ok, check that do we have this EAP type already. */
  for (index = 0; index < ad->num_eap_protocols; index++)
    {
      if (ad->eap_protocols[index].eap_type == eap_type)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Duplicate EAP protocol type %d",
                                  eap_type));
          return FALSE;
        }
    }

  /* Add it to the tunnel's list of EAP protocols. */
  new_eap_protocols = ssh_realloc(ad->eap_protocols,
                                  ad->num_eap_protocols *
                                  sizeof(SshPmEapProtocolStruct),
                                  (ad->num_eap_protocols + 1)
                                  * sizeof(SshPmEapProtocolStruct));

  if (new_eap_protocols == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate memory for new EAP protocol"));
      return FALSE;
    }

  index = ad->num_eap_protocols++;

  ad->eap_protocols = new_eap_protocols;
  ad->eap_protocols[index].eap_type = eap_type;
  ad->eap_protocols[index].preference = preference;
  ad->eap_protocols[index].transform = transform;

  return TRUE;
}
#endif /* SSHDIST_IKE_EAP_AUTH */
