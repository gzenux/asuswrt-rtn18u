/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager rendering and logging functions
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmUtilRender"

/*--------------------------------------------------------------------*/
/* Rendering functions                                                */
/*--------------------------------------------------------------------*/

int ssh_pm_render_ike_spi(unsigned char *buf, int buf_size,
                          int precision, void *datum)
{
  int i, len, total_len;
  unsigned char *ptr = (unsigned char *)datum;
  const unsigned char *delim;

  total_len = 0;

  for (i = 0; i < 8; i++)
    {
      delim = ((i % 4) == 0 && i != 0) ? ssh_custr(" ") : ssh_custr("");
      len = ssh_snprintf(buf, buf_size, "%s%02x", delim, *ptr);
      if (len < 0)
        return 0;
      ptr++;

      total_len += len;
      buf += len;
      buf_size -= len;
    }
  return total_len;
}

/* Alternative (prettier) version of ssh_ikev2_payload_id_render, used
   for displaying log event for a completed IKE negotiation. */
int ssh_pm_ike_id_render(unsigned char *buf, int buf_size,
                         int precision, void *datum)
{
  SshIkev2PayloadID id = datum;
  int len;

  if (id == NULL || id->id_data == NULL)
    {
      len = ssh_snprintf(buf, buf_size + 1, "(null)");
      if (len >= buf_size)
        return buf_size + 1;
      return len;
    }

#ifdef SSHDIST_IKE_ID_LIST
  if (id->id_type == (int) IPSEC_ID_LIST)
    len = ssh_snprintf(buf, buf_size + 1, "%.*@",
                       id->id_data_size,
                       ssh_safe_text_render,
                       id->id_data);
  else
#endif /* SSHDIST_IKE_ID_LIST */
    /* Print data. */
    if (id->id_type == SSH_IKEV2_ID_TYPE_IPV4_ADDR)
      {
        len = ssh_snprintf(buf, buf_size + 1, "%@",
                           ssh_ipaddr4_uint32_render,
                           (void *) (size_t) SSH_GET_32BIT(id->id_data));
      }
    else if (id->id_type == SSH_IKEV2_ID_TYPE_IPV6_ADDR)
      {
        len = ssh_snprintf(buf, buf_size + 1, "%@",
                           ssh_ipaddr6_byte16_render,
                           id->id_data);
      }
#ifdef SSHDIST_CERT
    else if (id->id_type == SSH_IKEV2_ID_TYPE_ASN1_DN ||
             id->id_type == SSH_IKEV2_ID_TYPE_ASN1_GN)
      {
        SshDNStruct dn[1];
        char *name;

        len = 0;
        ssh_dn_init(dn);
        if (ssh_dn_decode_der(id->id_data, id->id_data_size, dn, NULL))
          {
            if (ssh_dn_encode_ldap(dn, &name))
              {
                len = ssh_snprintf(buf, buf_size + 1, "%s", name);
                ssh_free(name);
              }
          }
        ssh_dn_clear(dn);
      }
#endif /* SSHDIST_CERT */
#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI
    else if (id->id_type == SSH_IKEV2_ID_TYPE_ASN1_DN)
      {
        char *name;

        len = 0;
        name = ssh_pm_mscapi_dn_to_str(id);
        if (name)
          {
            len = ssh_snprintf(buf, buf_size + 1, "%s", name);
            ssh_free(name);
          }
      }
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
    else if (id->id_type == SSH_IKEV2_ID_TYPE_KEY_ID)
      len = ssh_snprintf(buf, buf_size + 1, "%.*@",
                         id->id_data_size,
                         ssh_hex_render,
                         id->id_data);
    else
      len = ssh_snprintf(buf, buf_size + 1, "%.*@",
                         id->id_data_size,
                         ssh_safe_text_render,
                         id->id_data);


#ifdef SSHDIST_IKE_ID_LIST
  if (id->id_type == (int) IPSEC_ID_LIST)
    len += ssh_snprintf(buf + len, buf_size - len + 1, " (id list %s)",
                        ssh_ikev2_id_to_string(id->id_type));
  else
#endif /* SSHDIST_IKE_ID_LIST */
    len += ssh_snprintf(buf + len, buf_size - len + 1, " (%s)",
                        ssh_ikev2_id_to_string(id->id_type));

  if (len >= buf_size)
    return buf_size + 1;
  return len;
}


/*--------------------------------------------------------------------*/
/* Logging functions                                                  */
/*--------------------------------------------------------------------*/

void
ssh_pm_log_p1_event(SshLogFacility facility, SshLogSeverity severity,
                    SshPmP1 p1, const char *event, Boolean rekey)
{
  ssh_log_event(facility, severity, "");
  ssh_log_event(facility, severity, "IKE%s SA [%s%s] negotiation %s:",
#ifdef SSHDIST_IKEV1
                (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
                ? "v1":
#endif /* SSHDIST_IKEV1 */
                "v2",
                (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
                ? "Initiator" : "Responder",
                rekey ? " rekey" : "",
                event);
  ssh_pm_log_p1(facility, severity, p1, FALSE);
  ssh_log_event(facility, severity, "");
}

void ssh_pm_log_p1_success(SshPm pm,SshPmP1 p1, Boolean rekey)
{
  char options[64];

  /* Log the event */
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "");

  /* Format options. */
  ssh_snprintf(options, sizeof(options), "%s%s",
               (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
               ? "Initiator" : "Responder",
               rekey ? " rekey" : "");

#ifdef SSHDIST_IKE_MOBIKE
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
    strcat(options, ", MOBIKE");
#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT ||
      p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
    strcat(options, ", NAT-T");
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSHDIST_IKEV1
  if (p1->n && p1->n->ed && p1->n->ed->ike_ed
      && p1->n->ed->ike_ed->exchange_type == SSH_IKE_XCHG_TYPE_AGGR
      && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
    strcat(options, ", Aggressive");
#endif /* SSHDIST_IKEV1 */

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "IKE%s SA [%s] negotiation completed:",
#ifdef SSHDIST_IKEV1
                (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
                ? "v1" :
#endif /* SSHDIST_IKEV1 */
                "v2",
                options);
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "");

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Local Authentication Method  : %s",
                ssh_find_keyword_name(ssh_pm_ike_authentication_methods,
                                      p1->local_auth_method));
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Remote Authentication Method : %s",
                ssh_find_keyword_name(ssh_pm_ike_authentication_methods,
                                      p1->remote_auth_method));

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (p1->second_local_auth_method)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Second Local Authentication Method  : %s",
                    ssh_find_keyword_name(ssh_pm_ike_authentication_methods,
                                          p1->second_local_auth_method));
    }
  if (p1->second_remote_auth_method)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Second Remote Authentication Method : %s",
                    ssh_find_keyword_name(ssh_pm_ike_authentication_methods,
                                          p1->second_remote_auth_method));
     }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  if (p1->ike_sa->mac_algorithm != NULL)
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  IKE algorithms : %s, %s, %s",
                  p1->ike_sa->encrypt_algorithm,
                  p1->ike_sa->prf_algorithm,
                  p1->ike_sa->mac_algorithm);
  else
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  IKE algorithms : %s, %s",
                  p1->ike_sa->encrypt_algorithm,
                  p1->ike_sa->prf_algorithm);

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Diffie-Hellman : group %u (%u bits)",
                p1->dh_group,
                ssh_pm_dh_group_size(pm, p1->dh_group));

  ssh_pm_log_p1(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL, p1, TRUE);

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Local Lifetime: %u seconds",
                (unsigned int) p1->lifetime);
}



void
ssh_pm_log_p1(SshLogFacility facility, SshLogSeverity severity,
              SshPmP1 p1, Boolean verbose)
{
  SshPmTunnel tunnel;
  tunnel = ssh_pm_p1_get_tunnel(p1->pm, p1);

  ssh_log_event(facility, severity, "");

  if (tunnel != NULL)
    {
      ssh_log_event(facility, severity,
                    "  Local IKE peer  %@:%d routing instance %d ID %@",
                    ssh_ipaddr_render,  p1->ike_sa->server->ip_address,
                    SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
                    tunnel->routing_instance_id,
                    ssh_pm_ike_id_render, p1->local_id);

      ssh_log_event(facility, severity,
                    "  Remote IKE peer %@:%d routing instance %d ID %@",
                    ssh_ipaddr_render, p1->ike_sa->remote_ip,
                    p1->ike_sa->remote_port,
                    tunnel->routing_instance_id,
                    ssh_pm_ike_id_render, p1->remote_id);
    }
  else
    {
      ssh_log_event(facility, severity,
                    "  Local IKE peer  %@:%d ID %@",
                    ssh_ipaddr_render,  p1->ike_sa->server->ip_address,
                    SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
                    ssh_pm_ike_id_render, p1->local_id);

      ssh_log_event(facility, severity,
                    "  Remote IKE peer %@:%d ID %@",
                    ssh_ipaddr_render, p1->ike_sa->remote_ip,
                    p1->ike_sa->remote_port,
                    ssh_pm_ike_id_render, p1->remote_id);
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (p1->second_remote_id)
    {
      ssh_log_event(facility, severity,
                    "  Second Remote IKE ID %@",
                    ssh_pm_ike_id_render, p1->second_remote_id);
    }

  if (p1->second_local_id)
    {
      ssh_log_event(facility, severity,
                    "  Second Local IKE ID %@",
                    ssh_pm_ike_id_render, p1->second_local_id);
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

#ifdef SSHDIST_IKE_EAP_AUTH
  if (p1->eap_remote_id)
    ssh_log_event(facility, severity,
                  "  Authenticated EAP identity %@",
                  ssh_pm_ike_id_render, p1->eap_remote_id);
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (p1->second_eap_remote_id)
    ssh_log_event(facility, severity,
                  "  Authenticated second EAP identity %@",
                  ssh_pm_ike_id_render, p1->second_eap_remote_id);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

  if (verbose)
    ssh_log_event(facility, severity, "  Initiator SPI %@ Responder SPI %@",
                  ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_i,
                  ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_r);
}


void
ssh_pm_log_xauth_event(SshLogFacility facility,
                       SshLogSeverity severity,
                       SshPmP1 p1,
                       Boolean success)
{
  ssh_log_event(facility, severity, "");

  ssh_log_event(facility, severity, "XAuth/CFGMODE [%s] exchange %s",
                (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
                ? "Initiator" : "Responder",
                success ? "successful" : "failed");
  ssh_log_event(facility, severity, "  Remote IKE peer %@:%d ID %@",
                ssh_ipaddr_render, p1->ike_sa->remote_ip,
                p1->ike_sa->remote_port,
                ssh_pm_ike_id_render, p1->remote_id);

  ssh_log_event(facility, severity, "");
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
void
ssh_pm_log_cfgmode_event(SshLogFacility facility, SshLogSeverity severity,
                         SshPmP1 p1,  SshIkev2ConfType type,
                         const char *event)
{
  char *name = "UNKNOWN";

  switch (type)
    {
    case SSH_IKEV2_CFG_REQUEST:
      name = "REQUEST";
      break;

    case SSH_IKEV2_CFG_REPLY:
      name = "REPLY";
      break;

    case SSH_IKEV2_CFG_SET:
      name = "SET";
      break;

    case  SSH_IKEV2_CFG_ACK:
      name = "ACK";
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  ssh_log_event(facility, severity, "");
  ssh_log_event(facility, severity, "CFGMODE [%s] exchange %s:",
                name, event);
  ssh_pm_log_p1(facility, severity, p1, FALSE);
  ssh_log_event(facility, severity, "");
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */


void
ssh_pm_log_remote_access_attributes(SshLogFacility facility,
                                    SshLogSeverity severity,
                                    SshPmRemoteAccessAttrs attrs)
{
  SshUInt32 i;

  for (i = 0; i < attrs->num_addresses; i++)
    ssh_log_event(facility, severity, "    Address %@",
                  ssh_ipaddr_render, &attrs->addresses[i]);

  if (attrs->address_expiry_set)
    ssh_log_event(facility, severity, "    Valid   %u seconds",
                  (unsigned int) attrs->address_expiry);

  for (i = 0; i < attrs->num_dns; i++)
    ssh_log_event(facility, severity, "    DNS     %@",
                  ssh_ipaddr_render, &attrs->dns[i]);

  for (i = 0; i < attrs->num_wins; i++)
    ssh_log_event(facility, severity, "    WINS    %@",
                  ssh_ipaddr_render, &attrs->wins[i]);

  for (i = 0; i < attrs->num_dhcp; i++)
    ssh_log_event(facility, severity, "    DHCP    %@",
                  ssh_ipaddr_render, &attrs->dhcp[i]);

  for (i = 0; i < attrs->num_subnets; i++)
    ssh_log_event(facility, severity, "    Subnet  %@",
                  ssh_ipaddr_render, &attrs->subnets[i]);
}

static void
pm_log_failure(SshLogFacility facility,
               SshLogSeverity severity,
               SshPmP1 p1,
               const char *event)
{
  ssh_ikev2_debug_error_local(p1->ike_sa, event);
  ssh_log_event(facility, severity, "    %s", event);
}

void
ssh_pm_log_ike_sa_selection_failure(SshLogFacility facility,
                                    SshLogSeverity severity,
                                    SshPmP1 p1,
                                    SshIkev2SaSelectionError failure_mask)
{
  if (failure_mask & SSH_IKEV2_SA_SELECTION_ERROR_ENCR_MISMATCH)
    pm_log_failure(facility, severity, p1, "Encryption algorithm mismatch");
  if (failure_mask & SSH_IKEV2_SA_SELECTION_ERROR_PRF_MISMATCH)
    pm_log_failure(facility, severity, p1, "PRF algorithm mismatch");
  if (failure_mask & SSH_IKEV2_SA_SELECTION_ERROR_INTEG_MISMATCH)
    pm_log_failure(facility, severity, p1, "Integrity algorithm mismatch");
  if (failure_mask & SSH_IKEV2_SA_SELECTION_ERROR_D_H_MISMATCH)
    pm_log_failure(facility, severity, p1, "DH group mismatch");
  if (failure_mask & SSH_IKEV2_SA_SELECTION_ERROR_ESN_MISMATCH)
    pm_log_failure(facility, severity, p1,
                   "Extended Sequence Number mismatch");
  if (failure_mask & SSH_IKEV2_SA_SELECTION_ERROR_ATTR_MISMATCH)
    pm_log_failure(facility, severity, p1, "IKE transform attribute mismatch "
                  "(possible key size mismatch).");
  if (failure_mask & SSH_IKEV2_SA_SELECTION_ERROR_ESP_NULL_NULL)
    pm_log_failure(facility, severity, p1, "ESP NULL-NULL proposed");
}

#ifdef SSHDIST_IKE_MOBIKE
void
ssh_pm_log_p1_additional_addresses(SshLogFacility facility,
                                   SshLogSeverity severity,
                                   SshPmP1 p1, Boolean verbose)
{
   if (p1->ike_sa->num_additional_ip_addresses)
    {
      SshUInt32 i;

      for (i = 0; i < p1->ike_sa->num_additional_ip_addresses; i++)
        ssh_log_event(facility, severity, "  MOBIKE additional address %@",
                      ssh_ipaddr_render,
                      &p1->ike_sa->additional_ip_addresses[i]);
    }
}
#endif /* SSHDIST_IKE_MOBIKE */

int
ssh_pm_spis_render(unsigned char *buf, int buf_size,
                   int precision, void *datum)
{
  SshUInt32 *spis = (SshUInt32 *) datum;
  int wrote;
  int result = 0;
  int too_small_buffer = buf_size + 1;
  Boolean first = TRUE;

  if (spis[SSH_PME_SPI_ESP_IN])
    {
      wrote = ssh_snprintf(buf, buf_size, "ESP=0x%08lx",
                           (unsigned long) spis[SSH_PME_SPI_ESP_IN]);
      if (wrote >= buf_size - 1)
        return too_small_buffer;

      result += wrote;
      buf += wrote;
      buf_size -= wrote;
      first = FALSE;
    }
  if (spis[SSH_PME_SPI_AH_IN])
    {
      wrote = ssh_snprintf(buf, buf_size, "%sAH=0x%08lx",
                           first ? "" : ", ",
                           (unsigned long)
                           spis[SSH_PME_SPI_AH_IN]);
      if (wrote >= buf_size - 1)
        return too_small_buffer;

      result += wrote;
      buf += wrote;
      buf_size -= wrote;
      first = FALSE;
    }
  if (spis[SSH_PME_SPI_IPCOMP_IN])
    {
      wrote = ssh_snprintf(buf, buf_size, "%sIPComp=0x%04lx",
                           first ? "" : ", ",
                           (unsigned long)
                           spis[SSH_PME_SPI_IPCOMP_IN]);
      if (wrote >= buf_size - 1)
        return too_small_buffer;

      result += wrote;
    }

  if (precision >= 0)
    if (result > precision)
      result = precision;

  return result;
}

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
int
ssh_pm_cert_subject_render(unsigned char *buf, int buf_size,
                           int precision, void *datum)
{
  SshCMCertificate cmcert = (SshCMCertificate) datum;
  SshX509Certificate x509_cert;
  char *ldap;
  size_t len;

  if (ssh_cm_cert_get_x509(cmcert, &x509_cert) != SSH_CM_STATUS_OK)
    goto error;

  if (!ssh_x509_cert_get_subject_name(x509_cert, &ldap))
    goto error;

  ssh_x509_cert_free(x509_cert);

  len = strlen(ldap);
  if (len > buf_size)
    {
      ssh_free(ldap);
      return buf_size + 1;
    }

  memcpy(buf, ldap, len);
  ssh_free(ldap);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  return len;

  /* Error handling. */

 error:

  ssh_x509_cert_free(x509_cert);
  if (buf_size < 3)
    return buf_size + 1;

  memcpy(buf, "???", 3);

  return 3;
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */


/*--------------------------------------------------------------------*/
/* Stringifying functions                                             */
/*--------------------------------------------------------------------*/

/* SshPmQm errors. */

const SshKeywordStruct ssh_pm_qm_error_to_string_table[] = {
  { "Phase-1 failed", SSH_PM_QM_ERROR_P1_FAILED },
  { "No IKE peers", SSH_PM_QM_ERROR_NO_IKE_PEERS },
  { "Internal error", SSH_PM_QM_ERROR_INTERNAL_PM },
  { "Network unavailable", SSH_PM_QM_ERROR_NETWORK_UNAVAILABLE },
  { NULL, 0 }
};

const char *ssh_pm_qm_error_to_string(int error)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_pm_qm_error_to_string_table, error);
  if (name)
    return name;

  return ssh_ikev2_error_to_string(error);
}

/*--------------------------------------------------------------------*/
/* Logging functions                                                  */
/*--------------------------------------------------------------------*/

void
ssh_pm_log_qm_event(SshLogFacility facility, SshLogSeverity severity,
                    SshPmQm qm, const char *event)
{
  ssh_log_event(facility, severity, "");
  ssh_log_event(facility, severity, "IPsec SA [%s] negotiation %s:",
                qm->initiator ? "Initiator" : "Responder",
                event);
  if (qm->p1)
    ssh_pm_log_p1(facility, severity, qm->p1, FALSE);
  else
    ssh_log_event(facility, severity, "");

  if (qm->error == 0)
    {
      if (qm->local_ts)
        ssh_log_event(facility, severity,
                      "  Local Traffic Selector  %@",
                      ssh_ikev2_ts_render, qm->local_ts);
      if (qm->remote_ts)
        ssh_log_event(facility, severity,
                      "  Remote Traffic Selector %@",
                      ssh_ikev2_ts_render, qm->remote_ts);
    }
  ssh_log_event(facility, severity, "");
}

void
ssh_pm_log_manual_sa_event(SshPm pm, SshPmQm qm, Boolean sa_installation,
                           const char *event)
{
  SshEngineTransformData trd = &qm->sa_handler_data.trd.data;
  SshPmCipher cipher = NULL;
  SshPmMac mac = NULL;
  SshPmCompression compression = NULL;

  /* Log event success / failure. */
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "IPsec SA [Manual%s, %s] installation %s:",
                (sa_installation ? "" : " SA Rule"),
                (trd->transform & SSH_PM_IPSEC_TUNNEL) ?
                "tunnel" : "transport", event);
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "");

  /* Log SA peers, if transform was installed. */
  if (sa_installation)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Local peer  %@",
                    ssh_ipaddr_render, &trd->own_addr);
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Remote peer %@",
                    ssh_ipaddr_render, &trd->gw_addr);
    }

  /* Log rule selectors. */
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Local Traffic Selector  %@",
                ssh_ikev2_ts_render, qm->local_ts);
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Remote Traffic Selector %@",
                ssh_ikev2_ts_render, qm->remote_ts);
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "");

  /* Log SPIs and algorithms, if transform was installed. */
  if (sa_installation)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Inbound SPI:      | Outbound SPI: | Algorithm:");
      /*               ESP    [xxxxxxxx] | [xxxxxxxx]    | encr - hmac */
      /*               IPComp [xxxx]     | [xxxx]        | compr */

      cipher = ssh_pm_ipsec_cipher(pm, 0, trd->transform);
      mac = ssh_pm_ipsec_mac(pm, 0, trd->transform);

      if (trd->transform & SSH_PM_IPSEC_ESP)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  ESP    [%08lx] | [%08lx]    | %s - %s",
                        (unsigned long) trd->spis[SSH_PME_SPI_ESP_IN],
                        (unsigned long) trd->spis[SSH_PME_SPI_ESP_OUT],
                        (cipher ? cipher->name : "null"),
                        (mac ? mac->name : "none"));
        }

      if (trd->transform & SSH_PM_IPSEC_AH)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  AH     [%08lx] | [%08lx]    | %s",
                        (unsigned long) trd->spis[SSH_PME_SPI_AH_IN],
                        (unsigned long) trd->spis[SSH_PME_SPI_AH_OUT],
                        (mac ? mac->name : "none"));
        }

      if (trd->transform & SSH_PM_IPSEC_IPCOMP)
        {
          compression = ssh_pm_compression(pm, 0, trd->transform);
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  IPComp [%04lx]     | [%04lx]        | %s",
                        (unsigned long) trd->spis[SSH_PME_SPI_IPCOMP_IN],
                        (unsigned long) trd->spis[SSH_PME_SPI_IPCOMP_OUT],
                        (compression ? compression->name : "none"));
        }
    }

  /* Log SPIs. */
  else
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Inbound SPI:      | Outbound SPI:");
      if (qm->tunnel->transform & SSH_PM_IPSEC_ESP)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  ESP    [%08lx] | [%08lx]",
                        (unsigned long) qm->tunnel->u.manual.esp_spi_in,
                        (unsigned long) qm->tunnel->u.manual.esp_spi_out);
        }

      if (qm->tunnel->transform & SSH_PM_IPSEC_AH)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  AH     [%08lx] | [%08lx]",
                        (unsigned long) qm->tunnel->u.manual.ah_spi_in,
                        (unsigned long) qm->tunnel->u.manual.ah_spi_out);
        }

      if (qm->tunnel->transform & SSH_PM_IPSEC_IPCOMP)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  IPComp [%04lx]     | [%04lx]",
                        (unsigned long) qm->tunnel->u.manual.ipcomp_cpi_in,
                        (unsigned long) qm->tunnel->u.manual.ipcomp_cpi_out);
        }
    }
}

void
ssh_pm_log_trd_event(SshLogFacility facility, SshPmeFlowEvent event,
                     SshEngineTransformData trd)
{
  SshLogSeverity severity;

  severity = SSH_LOG_INFORMATIONAL;

  switch (event)
    {
    case SSH_ENGINE_EVENT_EXPIRED:
      /* Do not log these, causes too much flood. */
      break;
    case SSH_ENGINE_EVENT_DESTROYED:
      if (trd != NULL)
        {
          ssh_log_event(facility, severity, "");
          ssh_log_event(facility, severity,
                        "IPsec SA destroyed: "
                        "Inbound SPI:      | Outbound SPI: ");

          if (trd->transform & SSH_PM_IPSEC_AH)
            ssh_log_event(facility, severity,
                          "                    AH     [%08lx] | [%08lx]",
                          (unsigned long)
                          trd->spis[SSH_PME_SPI_AH_IN],
                          (unsigned long)
                          trd->spis[SSH_PME_SPI_AH_OUT]);

          if (trd->transform & SSH_PM_IPSEC_ESP)
            ssh_log_event(facility, severity,
                          "                    ESP    [%08lx] | [%08lx]",
                          (unsigned long)
                          trd->spis[SSH_PME_SPI_ESP_IN],
                          (unsigned long)
                          trd->spis[SSH_PME_SPI_ESP_OUT]);

          if (trd->transform & SSH_PM_IPSEC_IPCOMP)
            ssh_log_event(facility, severity,
                          "                    IPComp [%04lx]     | [%04lx]",
                          (unsigned long)
                          trd->spis[SSH_PME_SPI_IPCOMP_IN],
                          (unsigned long)
                          trd->spis[SSH_PME_SPI_IPCOMP_OUT]);
        }
      break;
    default:
      /* Do nothing */
      break;
    }
}



void
ssh_pm_log_rule_selection_failure(SshLogFacility facility,
                                  SshLogSeverity severity,
                                  SshPmP1 p1,
                                  SshUInt32 failure_mask)
{
  if (failure_mask & SSH_PM_E_NO_RULES)
    pm_log_failure(facility, severity, p1, "No IPsec rules configured");
  if (failure_mask & SSH_PM_E_PEER_IP_MISMATCH)
    pm_log_failure(facility, severity, p1, "Peer IP address mismatch");
  if (failure_mask & SSH_PM_E_LOCAL_IP_MISMATCH)
    pm_log_failure(facility, severity, p1, "Local IP address mismatch");
  if (failure_mask & SSH_PM_E_CA_NOT_TRUSTED)
    pm_log_failure(facility, severity, p1, "CA not trusted");
  if (failure_mask & SSH_PM_E_ACCESS_GROUP_MISMATCH)
    pm_log_failure(facility, severity, p1, "Access group mismatch");
  if (failure_mask & SSH_PM_E_LOCAL_TS_MISMATCH)
    pm_log_failure(facility, severity, p1, "Local Traffic Selector mismatch");
  if (failure_mask & SSH_PM_E_REMOTE_TS_MISMATCH)
    pm_log_failure(facility, severity, p1, "Remote Traffic Selector mismatch");
  if (failure_mask & SSH_PM_E_LOCAL_ID_MISMATCH)
    pm_log_failure(facility, severity, p1, "Local ID mismatch");
  if (failure_mask & SSH_PM_E_REMOTE_ID_MISMATCH)
    pm_log_failure(facility, severity, p1, "Remote ID mismatch");
  if (failure_mask & SSH_PM_E_SIMULTANEUS_LOSER)
    pm_log_failure(facility, severity, p1, "Lost on simultaneous SA rekey "
                  "arbitration");
  if (failure_mask & SSH_PM_E_IKE_VERSION_MISMATCH)
    pm_log_failure(facility, severity, p1, "IKE version mismatch");
  if (failure_mask & SSH_PM_E_PROTOCOL_MISMATCH_NATT)
    pm_log_failure(facility, severity, p1, "Protocol mismatch with NAT-T");
  if (failure_mask & SSH_PM_E_ALGORITHM_MISMATCH)
    pm_log_failure(facility, severity, p1, "Algorithm did not match policy");
  if (failure_mask & SSH_PM_E_ALGORITHM_UNSUPPORTED)
    pm_log_failure(facility, severity, p1, "Unsupported algorithm");
  if (failure_mask & SSH_PM_E_AUTH_METHOD_MISMATCH)
    pm_log_failure(facility, severity, p1, "Authentication method mismatch");
  if (failure_mask & SSH_PM_E_AUTH_METHOD_UNSUPPORTED)
    pm_log_failure(facility, severity, p1,
                   "Unsupported authentication method");
  if (failure_mask & SSH_PM_E_ENCAPSULATION_MISMATCH)
    pm_log_failure(facility, severity, p1, "Encapsulation mode mismatch");
  if (failure_mask & SSH_PM_E_ERROR_MEMORY)
    pm_log_failure(facility, severity, p1, "Out of memory");
}


#ifdef SSHDIST_IKE_CERT_AUTH
void
ssh_pm_log_cmi_failure(SshLogFacility facility, SshLogSeverity severity,
                       SshPmP1 p1, SshUInt32 failure_mask)
{

  if (failure_mask & SSH_CM_SSTATE_CERT_ALG_MISMATCH)
    pm_log_failure(facility, severity, p1,
                  "Algorithm mismatch between the certificate and "
                  "the search constraints");

  if (failure_mask & SSH_CM_SSTATE_CERT_KEY_USAGE_MISMATCH)
    pm_log_failure(facility, severity, p1,
                  "Key usage mismatch between the certificate and "
                  "the search constraints");

  if (failure_mask & SSH_CM_SSTATE_CERT_NOT_IN_INTERVAL)
    pm_log_failure(facility, severity, p1,
                  "Certificate was not valid in the time interval");

  if (failure_mask & SSH_CM_SSTATE_CERT_INVALID)
    pm_log_failure(facility, severity, p1,
                  "Certificate is not valid");

  if (failure_mask & SSH_CM_SSTATE_CERT_INVALID_SIGNATURE)
    pm_log_failure(facility, severity, p1,
                  "Certificate signature was not verified correctly");

  if (failure_mask & SSH_CM_SSTATE_CERT_REVOKED)
    pm_log_failure(facility, severity, p1,
                  "Certificate was revoked by a CRL");

  if (failure_mask & SSH_CM_SSTATE_CERT_NOT_ADDED)
    pm_log_failure(facility, severity, p1,
                  "Certificate was not added to the cache");

  if (failure_mask & SSH_CM_SSTATE_CERT_DECODE_FAILED)
    pm_log_failure(facility, severity, p1,
                  "Certificate decoding failed");

  if (failure_mask & SSH_CM_SSTATE_CERT_NOT_FOUND)
    pm_log_failure(facility, severity, p1,
                  "Certificate was not found (anywhere)");

  if (failure_mask & SSH_CM_SSTATE_CERT_CHAIN_LOOP)
    pm_log_failure(facility, severity, p1,
                  "Certificate chain looped (did not find trusted root)");

  if (failure_mask & SSH_CM_SSTATE_CERT_CRITICAL_EXT)
    pm_log_failure(facility, severity, p1,
                  "Certificate contains critical extension that "
                  "was not handled");

  if (failure_mask & SSH_CM_SSTATE_CERT_CA_INVALID)
    pm_log_failure(facility, severity, p1,
                  "Certificate issuer was not valid "
                  "(CA specific information missing)");

  if (failure_mask & SSH_CM_SSTATE_CRL_OLD)
    pm_log_failure(facility, severity, p1,
                  "CRL is too old");

  if (failure_mask & SSH_CM_SSTATE_CRL_INVALID)
    pm_log_failure(facility, severity, p1,
                  "CRL is not valid");

  if (failure_mask & SSH_CM_SSTATE_CRL_INVALID_SIGNATURE)
    pm_log_failure(facility, severity, p1,
                  "CRL signature was not verified correctly");

  if (failure_mask & SSH_CM_SSTATE_CRL_NOT_FOUND)
    pm_log_failure(facility, severity, p1,
                  "CRL was not found (anywhere)");

  if (failure_mask & SSH_CM_SSTATE_CRL_NOT_ADDED)
    pm_log_failure(facility, severity, p1,
                  "CRL was not added to the cache");

  if (failure_mask & SSH_CM_SSTATE_CRL_DECODE_FAILED)
    pm_log_failure(facility, severity, p1,
                  "CRL decoding failed");

  if (failure_mask & SSH_CM_SSTATE_CRL_IN_FUTURE)
    pm_log_failure(facility, severity, p1,
                  "CRL is not currently valid, but in the future");

  if (failure_mask & SSH_CM_SSTATE_CRL_DUPLICATE_SERIAL_NO)
    pm_log_failure(facility, severity, p1,
                  "CRL contains duplicate serial numbers");

  if (failure_mask & SSH_CM_SSTATE_INTERVAL_NOT_VALID)
    pm_log_failure(facility, severity, p1,
                  "Time interval is not continuous");

  if (failure_mask & SSH_CM_SSTATE_TIMES_UNAVAILABLE)
    pm_log_failure(facility, severity, p1,
                  "Time information not available");

  if (failure_mask & SSH_CM_SSTATE_DB_METHOD_TIMEOUT)
    pm_log_failure(facility, severity, p1,
                  "Database method failed due to timeout");

  if (failure_mask & SSH_CM_SSTATE_DB_METHOD_FAILED)
    pm_log_failure(facility, severity, p1,
                  "Database method failed");

  if (failure_mask & SSH_CM_SSTATE_PATH_NOT_VERIFIED)
    pm_log_failure(facility, severity, p1,
                  "Path was not verified");

  if (failure_mask & SSH_CM_SSTATE_PATH_LENGTH_REACHED)
    pm_log_failure(facility, severity, p1,
                  "Maximum path length reached");

  if (failure_mask & SSH_CM_SSTATE_ALGORITHM_NOT_ALLOWED)
    pm_log_failure(facility, severity, p1,
                  "Algorithm or key not allowed (not strong enough)");
}
#endif /* SSHDIST_IKE_CERT_AUTH */



#ifdef SSHDIST_L2TP
void
ssh_pm_log_l2tp_event(SshLogFacility facility, SshLogSeverity severity,
                      SshL2tpTunnelInfo tunnel, SshL2tpSessionInfo session,
                      const char *event)
{
  Boolean initiator = TRUE;

  if (session)
    {
      if (!session->initiator)
        initiator = FALSE;
    }
  else if (tunnel)
    {
      if (!tunnel->initiator)
        initiator = FALSE;
    }

  ssh_log_event(facility, severity, "");
  ssh_log_event(facility, severity, "L2TP [%s, incoming-call] negotiation %s:",
                initiator ? "Initiator" : "Responder",
                event);
  ssh_log_event(facility, severity, "");

  if (tunnel)
    {
      ssh_log_event(facility, severity, "  Local L2TP peer  %s:%s",
                    tunnel->local_addr, tunnel->local_port);
      ssh_log_event(facility, severity, "  Remote L2TP peer %s:%s",
                    tunnel->remote_addr, tunnel->remote_port);

      if (session)
        {
          ssh_log_event(facility, severity,
                        "  Local tunnel ID  %5u session ID %5u",
                        (unsigned int) tunnel->local_id,
                        (unsigned int) session->local_id);
          ssh_log_event(facility, severity,
                        "  Remote tunnel ID %5u session ID %5u",
                        (unsigned int) tunnel->remote_id,
                        (unsigned int) session->remote_id);
        }
    }

  ssh_log_event(facility, severity, "");
}
#endif /* SSHDIST_L2TP */

void ssh_pm_log_interceptor_interface(SshInterceptorInterface *ifp)
{
  int j;

  static const SshKeywordStruct medianames[] =
    {
      {"nonexistent",   SSH_INTERCEPTOR_MEDIA_NONEXISTENT},
      {"plain",         SSH_INTERCEPTOR_MEDIA_PLAIN},
      {"ethernet",      SSH_INTERCEPTOR_MEDIA_ETHERNET},
      {"fddi",          SSH_INTERCEPTOR_MEDIA_FDDI},
      {"tokenring",     SSH_INTERCEPTOR_MEDIA_TOKENRING},
      {NULL, 0},
    };

  if (ifp->to_protocol.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT
      || ifp->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    return;

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
#ifdef WITH_IPV6
                "%2d: `%s' [media=%s, Routing instance=%d:%s MTU_IPv4=%d "
                "MTU_IPv6=%d]",
#else /* WITH_IPV6 */
                "%2d: `%s' [media=%s, Routing instance=%d:%s MTU_IPv4=%d]",
#endif /* WITH_IPV6 */
                (int) ifp->ifnum, ifp->name,
                ssh_find_keyword_name(medianames, ifp->to_adapter.media),
                ifp->routing_instance_id, ifp->routing_instance_name,
                ifp->to_adapter.mtu_ipv4
#ifdef WITH_IPV6
                , ifp->to_adapter.mtu_ipv6
#endif /* WITH_IPV6 */
                );

  for (j = 0; j < ifp->num_addrs; j++)
    {
      switch (ifp->addrs[j].protocol)
        {
        case SSH_PROTOCOL_IP4:
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "    %@/%@ [%@]",
                        ssh_ipaddr_render, &ifp->addrs[j].addr.ip.ip,
                        ssh_ipmask_render, &ifp->addrs[j].addr.ip.mask,
                        ssh_ipaddr_render,
                        &ifp->addrs[j].addr.ip.broadcast);
          break;

        case SSH_PROTOCOL_IP6:
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "    %@/%@",
                        ssh_ipaddr_render, &ifp->addrs[j].addr.ip.ip,
                        ssh_ipmask_render, &ifp->addrs[j].addr.ip.mask);
          break;

        default:
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "    protocol %d", ifp->addrs[j].protocol);
          break;
        }
    }
}
