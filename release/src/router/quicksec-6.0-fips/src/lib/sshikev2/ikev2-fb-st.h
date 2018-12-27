/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef IKEV2_FB_ST_H
#define IKEV2_FB_ST_H

#include "sshincludes.h"

/* Main thread states for Phase-I initiator negotiations */
SSH_FSM_STEP(ikev2_fb_i_p1_negotiation_start);
SSH_FSM_STEP(ikev2_fb_i_p1_negotiation_negotiate);
SSH_FSM_STEP(ikev2_fb_i_p1_negotiation_result);
SSH_FSM_STEP(ikev2_fb_i_p1_finish);
#ifdef SSHDIST_ISAKMP_CFG_MODE
SSH_FSM_STEP(ikev2_fb_i_p1_check_cfg);
SSH_FSM_STEP(ikev2_fb_i_p1_wait_cfg);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Sub-thread states for Phase-I initiator negotiations */
SSH_FSM_STEP(ikev2_fb_st_i_ike_id_request);
SSH_FSM_STEP(ikev2_fb_st_i_ike_notify_request);
SSH_FSM_STEP(ikev2_fb_st_i_ike_psk_request);
SSH_FSM_STEP(ikev2_fb_st_i_ike_psk_result);
#ifdef SSHDIST_IKE_CERT_AUTH
SSH_FSM_STEP(ikev2_fb_st_i_ike_private_key_request);
#endif /* SSHDIST_IKE_CERT_AUTH */
SSH_FSM_STEP(ikev2_fb_st_i_ike_sa_request);
#ifdef SSHDIST_ISAKMP_CFG_MODE
SSH_FSM_STEP(ikev2_fb_st_i_conf_request);
#endif /* SSHDIST_ISAKMP_CFG_MODE */
SSH_FSM_STEP(ikev2_fb_st_i_ike_sa_result);

/* Main thread states for Phase-I responder negotiations */
SSH_FSM_STEP(ikev2_fb_p1_negotiation_allocate_sa);
SSH_FSM_STEP(ikev2_fb_p1_negotiation_wait_sa_done);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Cfgmode initiator states */
SSH_FSM_STEP(ikev2_fb_i_cfg_negotiation_start);
SSH_FSM_STEP(ikev2_fb_i_cfg_negotiation_connect);
SSH_FSM_STEP(ikev2_fb_i_cfg_negotiation_result);
SSH_FSM_STEP(ikev2_fb_i_cfg_negotiation_final);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Informational exchange initiator states */
SSH_FSM_STEP(ikev2_fb_i_info_negotiation_start);
SSH_FSM_STEP(ikev2_fb_i_info_negotiation_result);

/* Main thread states for Quick Mode negotiations */
SSH_FSM_STEP(ikev2_fb_i_qm_negotiation_start);
SSH_FSM_STEP(ikev2_fb_i_qm_negotiation_negotiate);
SSH_FSM_STEP(ikev2_fb_i_qm_negotiation_result);
SSH_FSM_STEP(ikev2_fb_qm_negotiation_wait_sa_installation);

/* Sub-thread states for Quick Mode negotiations */
SSH_FSM_STEP(ikev2_fb_st_i_qm_sa_alloc_spi);
SSH_FSM_STEP(ikev2_fb_st_i_qm_sa_notify_request);
SSH_FSM_STEP(ikev2_fb_st_i_qm_sa_request);
SSH_FSM_STEP(ikev2_fb_st_i_qm_result);

/* Phase-I new connections */
SSH_FSM_STEP(ikev2_fb_st_new_p1_connection_start);
SSH_FSM_STEP(ikev2_fb_st_new_p1_connection_result);

/* IKE identity states */
SSH_FSM_STEP(ikev2_fb_st_id_request);
SSH_FSM_STEP(ikev2_fb_st_id_request_result);

/* IKE find preshared key states */
SSH_FSM_STEP(ikev2_fb_st_find_pre_shared_key);
SSH_FSM_STEP(ikev2_fb_st_find_pre_shared_key_result);

#ifdef SSHDIST_IKE_CERT_AUTH
/* Find public key operation states */
SSH_FSM_STEP(ikev2_fb_st_find_public_key);
SSH_FSM_STEP(ikev2_fb_st_find_public_key_result);

/* Request certificates and find private key operation states */
SSH_FSM_STEP(ikev2_fb_st_request_certs);
SSH_FSM_STEP(ikev2_fb_st_request_certs_result);
#endif /* SSHDIST_IKE_CERT_AUTH */

/* IKE SA selection */
SSH_FSM_STEP(ikev2_fb_st_select_ike_sa);
SSH_FSM_STEP(ikev2_fb_st_select_ike_sa_finish);

/* IPSec SA selection */
SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_start);
SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_build_notify);
SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_alloc_spi);
SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_notify_request);
SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_check_notifies);
SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_select);
SSH_FSM_STEP(ikev2_fb_st_select_qm_sa_finish);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Cfgmode policy call states */
SSH_FSM_STEP(ikev2_fb_st_cfg_fill_attrs_conf_request);
SSH_FSM_STEP(ikev2_fb_st_cfg_fill_attrs_conf_received);
SSH_FSM_STEP(ikev2_fb_st_cfg_fill_attrs_result);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_IKE_XAUTH
/* Xauth states */
SSH_FSM_STEP(ikev2_fb_st_i_xauth_start);
SSH_FSM_STEP(ikev2_fb_st_i_xauth_negotiate);
SSH_FSM_STEP(ikev2_fb_st_i_xauth_negotiation_result);
SSH_FSM_STEP(ikev2_fb_st_i_xauth_result);
SSH_FSM_STEP(ikev2_fb_st_i_xauth_failed);
SSH_FSM_STEP(ikev2_fb_st_r_xauth_start);
#endif /* SSHDIST_IKE_XAUTH */
#endif /* IKEV2_FB_H */
