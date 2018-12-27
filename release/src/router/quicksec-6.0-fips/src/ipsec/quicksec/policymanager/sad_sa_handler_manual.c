/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPSec SA handler for manually keyed tunnels.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmSaHandler"

Boolean
ssh_pm_manual_sa_handler(SshPm pm, SshPmQm qm)
{
  SshPmTunnel tunnel;
  SshUInt32 num_ciphers;
  SshUInt32 num_macs;
  SshUInt32 num_compressions;
  SshPmCipher cipher = NULL;
  SshPmMac mac = NULL;
  SshPmCompression compression = NULL;
  Boolean esp_has_mac = FALSE;
  size_t encr_key_len = 0;
  size_t auth_key_len = 0;
  const unsigned char *encr_key_in = NULL;
  const unsigned char *encr_key_out = NULL;
  const unsigned char *auth_key_in = NULL;
  const unsigned char *auth_key_out = NULL;
  SshUInt32 key_size;
  char keysizebuf[8] = {0};

  tunnel = qm->tunnel;
  SSH_ASSERT(tunnel != NULL);

  /* Initialize transform data. */

  /* First, general initialization. */
  SSH_ASSERT(tunnel->num_peers > 0);
  qm->sa_handler_data.trd.data.gw_addr = tunnel->peers[0];
  ssh_pm_tunnel_select_local_ip(tunnel,
                                &qm->sa_handler_data.trd.data.gw_addr,
                                &qm->sa_handler_data.trd.data.own_addr);
  qm->sa_handler_data.trd.data.own_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  /* Clear trigger packet selectors. */
  SSH_IP_UNDEFINE(&qm->sel_dst);
  SSH_IP_UNDEFINE(&qm->sel_src);
  qm->sel_src_port = 0;
  qm->sel_dst_port = 0;
  qm->sel_ipproto = SSH_IPPROTO_ANY;

  /* From which rule-set do the inbound packets arrive? */
  qm->sa_handler_data.trd.data.inbound_tunnel_id = tunnel->tunnel_id;

  if (qm->tunnel->outer_tunnel)
    {
      qm->sa_handler_data.trd.control.outer_tunnel_id =
        qm->tunnel->outer_tunnel->tunnel_id;
      qm->sa_handler_data.trd.data.restart_after_tre = 1;
    }

  /* Check if we require transport mode. */
  if (!(tunnel->flags & SSH_PM_T_TRANSPORT_MODE))
    qm->sa_handler_data.trd.data.transform |= SSH_PM_IPSEC_TUNNEL;

  /* Set df-bit policy. */
  if (qm->rule->flags & SSH_PM_RULE_DF_SET)
    qm->sa_handler_data.trd.data.df_bit_processing = SSH_ENGINE_DF_SET;
  else if (qm->rule->flags & SSH_PM_RULE_DF_CLEAR)
    qm->sa_handler_data.trd.data.df_bit_processing = SSH_ENGINE_DF_CLEAR;
  else
    qm->sa_handler_data.trd.data.df_bit_processing = SSH_ENGINE_DF_KEEP;

  /* Get algorithms. */

  (void) ssh_pm_ipsec_num_algorithms(pm, tunnel->transform,
                                     0,
                                     &num_ciphers, &num_macs,
                                     &num_compressions, NULL);

  if (num_ciphers
      && (tunnel->transform & SSH_PM_IPSEC_ESP))
    {
      cipher = ssh_pm_ipsec_cipher(pm, 0, tunnel->transform);
      SSH_ASSERT(cipher != NULL);
      ssh_pm_cipher_key_sizes(tunnel, cipher, SSH_PM_ALG_IPSEC_SA,
                              NULL, NULL, NULL, &key_size);
      encr_key_len = key_size / 8;
      ssh_snprintf(keysizebuf, sizeof(keysizebuf), "/%u",
                   (unsigned int) key_size);
    }
  else
    {
      /* Configuration specifies a cipher but no esp,
         which does not make much sense. */
      num_ciphers = 0;
    }

  if (num_macs
      && (tunnel->transform & (SSH_PM_IPSEC_ESP | SSH_PM_IPSEC_AH)))
    {
      mac = ssh_pm_ipsec_mac(pm, 0, tunnel->transform);
      SSH_ASSERT(mac != NULL);
      ssh_pm_mac_key_sizes(tunnel, mac, SSH_PM_ALG_IPSEC_SA,
                           NULL, NULL, NULL, &key_size);
      auth_key_len = key_size / 8;
    }
  else
    {
      /* Configuration specifies a mac but no esp or ah,
         which does not make much sense. */
      num_macs = 0;
    }

  if (num_compressions
      && (tunnel->transform & SSH_PM_IPSEC_IPCOMP))
    {
      compression = ssh_pm_compression(pm, 0, tunnel->transform);
      SSH_ASSERT(compression != NULL);
    }
  else
    {
      /* Configuration specifies a compression alg but no ipcomp,
         which does not make much sense. */
      num_compressions = 0;
    }

  /* Store key lengths into the transform data structure. */
  qm->sa_handler_data.trd.data.cipher_key_size = encr_key_len;
  qm->sa_handler_data.trd.data.cipher_iv_size = num_ciphers ?
    cipher->iv_size / 8 : 0;
  qm->sa_handler_data.trd.data.cipher_nonce_size = 0;
  qm->sa_handler_data.trd.data.mac_key_size = auth_key_len;

  /* Split key material into sub-keys. */

  SSH_ASSERT(tunnel->u.manual.key_len == (encr_key_len + auth_key_len) * 2);

  encr_key_in = tunnel->u.manual.key;
  auth_key_in = encr_key_in + encr_key_len;
  encr_key_out = auth_key_in + auth_key_len;
  auth_key_out = encr_key_out + encr_key_len;

  if (tunnel->transform & SSH_PM_IPSEC_AH)
    {
      qm->sa_handler_data.trd.data.transform |= SSH_PM_IPSEC_AH;

      qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_AH_IN]
        = tunnel->u.manual.ah_spi_in;
      qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_AH_OUT]
        = tunnel->u.manual.ah_spi_out;

      /* Set the algorithm. */
      SSH_ASSERT(mac != NULL);
      qm->sa_handler_data.trd.data.transform |= mac->mask_bits[1];

      /* Get inbound key. */
      memcpy(qm->sa_handler_data.trd.data.keymat
             + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
             auth_key_in, auth_key_len);

      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                        ("Inbound AH MAC key:"),
                        (qm->sa_handler_data.trd.data.keymat
                         + SSH_IPSEC_MAX_ESP_KEY_BITS / 8),
                        auth_key_len);

      /* Get outbound key. */
      memcpy(qm->sa_handler_data.trd.data.keymat
             + SSH_IPSEC_MAX_KEYMAT_LEN / 2
             + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
             auth_key_out, auth_key_len);

      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                        ("Outbound AH MAC key:"),
                        (qm->sa_handler_data.trd.data.keymat
                         + SSH_IPSEC_MAX_KEYMAT_LEN / 2
                         + SSH_IPSEC_MAX_ESP_KEY_BITS / 8),
                        auth_key_len);
    }

  if (tunnel->transform & SSH_PM_IPSEC_ESP)
    {
      qm->sa_handler_data.trd.data.transform |= SSH_PM_IPSEC_ESP;

      qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_ESP_IN]
        = tunnel->u.manual.esp_spi_in;
      qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_ESP_OUT]
        = tunnel->u.manual.esp_spi_out;

      /* Set the algorithms. */
      if (num_ciphers)
        {
          SSH_ASSERT(cipher != NULL);
          qm->sa_handler_data.trd.data.transform |= cipher->mask_bits;
        }
      if (num_macs && (tunnel->transform & SSH_PM_IPSEC_AH) == 0)
        {
          SSH_ASSERT(mac != NULL);
          qm->sa_handler_data.trd.data.transform |= mac->mask_bits[0];
          esp_has_mac = TRUE;
        }

      /* Get inbound keys. */
      if (num_ciphers)
        {
          memcpy(qm->sa_handler_data.trd.data.keymat,
                 encr_key_in, encr_key_len);
          SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Inbound ESP cipher key:"),
                            qm->sa_handler_data.trd.data.keymat,
                            encr_key_len);
        }
      if (esp_has_mac)
        {
          memcpy(qm->sa_handler_data.trd.data.keymat
                 + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
                 auth_key_in, auth_key_len);
          SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                            ("Inbound ESP MAC key:"),
                            (qm->sa_handler_data.trd.data.keymat
                             + SSH_IPSEC_MAX_ESP_KEY_BITS / 8),
                            auth_key_len);
        }

      /* Get outbound keys. */
      if (num_ciphers)
        {
          memcpy(qm->sa_handler_data.trd.data.keymat
                 + SSH_IPSEC_MAX_KEYMAT_LEN / 2,
                 encr_key_out, encr_key_len);
          SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                            ("Outbound ESP cipher key:"),
                            (qm->sa_handler_data.trd.data.keymat
                             + SSH_IPSEC_MAX_KEYMAT_LEN / 2),
                            encr_key_len);
        }
      if (esp_has_mac)
        {
          memcpy(qm->sa_handler_data.trd.data.keymat
                 + SSH_IPSEC_MAX_KEYMAT_LEN / 2
                 + SSH_IPSEC_MAX_ESP_KEY_BITS / 8,
                 auth_key_out, auth_key_len);
          SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                            ("Outbound ESP MAC key:"),
                            (qm->sa_handler_data.trd.data.keymat
                             + SSH_IPSEC_MAX_KEYMAT_LEN / 2
                             + SSH_IPSEC_MAX_ESP_KEY_BITS / 8),
                            auth_key_len);
        }

    }

  if (tunnel->transform & SSH_PM_IPSEC_IPCOMP)
    {
      qm->sa_handler_data.trd.data.transform |= SSH_PM_IPSEC_IPCOMP;
      qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_IPCOMP_IN]
        = tunnel->u.manual.ipcomp_cpi_in;
      qm->sa_handler_data.trd.data.spis[SSH_PME_SPI_IPCOMP_OUT]
        = tunnel->u.manual.ipcomp_cpi_out;

      /* Set algorithm. */
      SSH_ASSERT(compression != NULL);
      qm->sa_handler_data.trd.data.transform |= compression->mask_bits;
    }

  /* Final initialization. */
  qm->sa_handler_data.trd.data.transform |= SSH_PM_IPSEC_MANUAL;

  /* Set peer handle to invalid value. */
  qm->sa_handler_data.trd.control.peer_handle = SSH_IPSEC_INVALID_INDEX;

  qm->sa_handler_data.trd.data.packet_enlargement =
    ssh_pm_compute_trd_packet_enlargement(pm,
                             qm->sa_handler_data.trd.data.transform,
                             SSH_IP_IS6(&qm->sa_handler_data.trd.data.gw_addr),
                             cipher, mac);












  if (mac && mac->digest_size == 0)
    {
      qm->sa_handler_data.trd.data.packet_enlargement += 32;
    }

  /* Start an SA handler thread that takes care of installing the
     transform and outbound rule. */
  ssh_fsm_thread_init(&pm->fsm, &qm->sub_thread,
                      ssh_pm_st_sa_handler_start, NULL_FNPTR, NULL_FNPTR, qm);
  ssh_fsm_set_thread_name(&qm->sub_thread, "SA handler");

  /* All done. */
  return TRUE;
}
