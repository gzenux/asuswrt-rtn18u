/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp state machine function prototypes.
*/

#ifndef ISAKMP_STATE_H
#define ISAKMP_STATE_H

/* Isakmp state machine states */
typedef enum {
  SSH_IKE_ST_ANY,               /* Any state (0) */
  SSH_IKE_ST_START_SA_NEGOTIATION_I, /* Start SA negotiation, initiator (1) */
  SSH_IKE_ST_START_SA_NEGOTIATION_R, /* Start SA negotiation, responder (2) */

  /* Oakley Main Mode states */
  SSH_IKE_ST_MM_SA_I,           /* Sent SA, initiator (3) */
  SSH_IKE_ST_MM_SA_R,           /* Sent SA, responder (4) */

  SSH_IKE_ST_MM_KE_I,           /* Sent KE, initiator (5) */
  SSH_IKE_ST_MM_KE_R,           /* Sent KE, responder (6) */

  SSH_IKE_ST_MM_FINAL_I,        /* Sent final packet, initiator (7) */
  SSH_IKE_ST_MM_FINAL_R,        /* Sent final packet, responder (8) */
  SSH_IKE_ST_MM_DONE_I,         /* Waiting for done, initiator (9) */

  /* Oakley Aggressive Mode states */
  SSH_IKE_ST_AM_SA_I,           /* Sent SA, KE etc, initiator (10) */
  SSH_IKE_ST_AM_SA_R,           /* Sent SA, KE etc, responder (11) */
  SSH_IKE_ST_AM_FINAL_I,        /* Sent final packet, initiator (12) */
  SSH_IKE_ST_AM_DONE_R,         /* Waiting for done, initiator (13) */

  /* Oakley Quick Mode */
  SSH_IKE_ST_START_QM_I,        /* Start qm negotiation, initiator (14) */
  SSH_IKE_ST_START_QM_R,        /* Start qm negotiation, responder (15) */

  SSH_IKE_ST_QM_HASH_SA_I,      /* -.-, Sent HASH(1), SA, Ni, [KE, IDui,
                                   IDur], initiator (16) */
  SSH_IKE_ST_QM_HASH_SA_R,      /* -.-, Sent HASH(2), SA, Nr, [KE, IDui,
                                   IDur], responder (17) */
  SSH_IKE_ST_QM_HASH_I,         /* -.-, Sent HASH(3) (18) */
  SSH_IKE_ST_QM_DONE_R,         /* -.-, Waiting for done (19) */

  /* Oakley New Group Mode */
  SSH_IKE_ST_START_NGM_I,       /* Start ngm negotiation, initiator (20) */
  SSH_IKE_ST_START_NGM_R,       /* Start ngm negotiation, responder (21) */

  SSH_IKE_ST_NGM_HASH_SA_I,     /* -.-, Sent HASH(1), SA, initiator (22) */
  SSH_IKE_ST_NGM_HASH_SA_R,     /* -.-, Sent HASH(2), SA, responder (23) */
  SSH_IKE_ST_NGM_DONE_I,        /* -.-, Waiting for done, SA, initiator (24) */

#ifdef SSHDIST_ISAKMP_CFG_MODE
  /* Configuration Mode */
  SSH_IKE_ST_START_CFG_I,       /* Start cfg negotiation, initiator (25) */
  SSH_IKE_ST_START_CFG_R,       /* Start cfg negotiation, responder (26) */

  SSH_IKE_ST_CFG_HASH_ATTR_I,   /* -.-, Sent [HASH,] ATTR initiator (27) */
  SSH_IKE_ST_CFG_HASH_ATTR_R,   /* -.-, Sent [HASH,] ATTR responder (28) */
  SSH_IKE_ST_CFG_DONE_I,        /* -.-, Waiting for done, responder (29) */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

  SSH_IKE_ST_DONE,              /* All done (25/30) */
  SSH_IKE_ST_DELETED            /* Isakmp negotiation is already deleted
                                   (26/31) */
} SshIkeProtocolState;

/* Isakmp state machine input check function, returns 0 if ok.
   modifies isakmp_sa. */
typedef SshIkeNotifyMessageType
        (*SshIkeInputStateFunction)(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_input_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkeStateMachine state);

/* Isakmp state machine output function, returns 0 if ok.
   Appends data to isakmp_output_packet. */
typedef SshIkeNotifyMessageType
        (*SshIkeOutputStateFunction)(SshIkeContext isakmp_context,
                                     SshIkePacket isakmp_input_packet,
                                     SshIkePacket isakmp_output_packet,
                                     SshIkeSA isakmp_sa,
                                     SshIkeNegotiation negotiation,
                                     SshIkeStateMachine state);

typedef enum {
  SSH_IKE_FIELDS_NONE                   = 0x0000,
  SSH_IKE_FIELDS_SA                     = 0x0001,
  SSH_IKE_FIELDS_KE                     = 0x0002,
  SSH_IKE_FIELDS_KE_SA                  = 0x0003,
  SSH_IKE_FIELDS_ID                     = 0x0004,
  SSH_IKE_FIELDS_ID_SA                  = 0x0005,
  SSH_IKE_FIELDS_ID_KE                  = 0x0006,
  SSH_IKE_FIELDS_ID_KE_SA               = 0x0007,
  SSH_IKE_FIELDS_SIG                    = 0x0008,
  SSH_IKE_FIELDS_SIG_SA                 = 0x0009,
  SSH_IKE_FIELDS_SIG_KE                 = 0x000a,
  SSH_IKE_FIELDS_SIG_KE_SA              = 0x000b,
  SSH_IKE_FIELDS_SIG_ID                 = 0x000c,
  SSH_IKE_FIELDS_SIG_ID_SA              = 0x000d,
  SSH_IKE_FIELDS_SIG_ID_KE              = 0x000e,
  SSH_IKE_FIELDS_SIG_ID_KE_SA           = 0x000f,
  SSH_IKE_FIELDS_NONCE                  = 0x0010,
  SSH_IKE_FIELDS_NONCE_SA               = 0x0011,
  SSH_IKE_FIELDS_NONCE_KE               = 0x0012,
  SSH_IKE_FIELDS_NONCE_KE_SA            = 0x0013,
  SSH_IKE_FIELDS_NONCE_ID               = 0x0014,
  SSH_IKE_FIELDS_NONCE_ID_SA            = 0x0015,
  SSH_IKE_FIELDS_NONCE_ID_KE            = 0x0016,
  SSH_IKE_FIELDS_NONCE_ID_KE_SA         = 0x0017,
  SSH_IKE_FIELDS_NONCE_SIG              = 0x0018,
  SSH_IKE_FIELDS_NONCE_SIG_SA           = 0x0019,
  SSH_IKE_FIELDS_NONCE_SIG_KE           = 0x001a,
  SSH_IKE_FIELDS_NONCE_SIG_KE_SA        = 0x001b,
  SSH_IKE_FIELDS_NONCE_SIG_ID           = 0x001c,
  SSH_IKE_FIELDS_NONCE_SIG_ID_SA        = 0x001d,
  SSH_IKE_FIELDS_NONCE_SIG_ID_KE        = 0x001e,
  SSH_IKE_FIELDS_NONCE_SIG_ID_KE_SA     = 0x001f,
  SSH_IKE_FIELDS_HASH                   = 0x0020,
  SSH_IKE_FIELDS_HASH_SA                = 0x0021,
  SSH_IKE_FIELDS_HASH_KE                = 0x0022,
  SSH_IKE_FIELDS_HASH_KE_SA             = 0x0023,
  SSH_IKE_FIELDS_HASH_ID                = 0x0024,
  SSH_IKE_FIELDS_HASH_ID_SA             = 0x0025,
  SSH_IKE_FIELDS_HASH_ID_KE             = 0x0026,
  SSH_IKE_FIELDS_HASH_ID_KE_SA          = 0x0027,
  SSH_IKE_FIELDS_HASH_SIG               = 0x0028,
  SSH_IKE_FIELDS_HASH_SIG_SA            = 0x0029,
  SSH_IKE_FIELDS_HASH_SIG_KE            = 0x002a,
  SSH_IKE_FIELDS_HASH_SIG_KE_SA         = 0x002b,
  SSH_IKE_FIELDS_HASH_SIG_ID            = 0x002c,
  SSH_IKE_FIELDS_HASH_SIG_ID_SA         = 0x002d,
  SSH_IKE_FIELDS_HASH_SIG_ID_KE         = 0x002e,
  SSH_IKE_FIELDS_HASH_SIG_ID_KE_SA      = 0x002f,
  SSH_IKE_FIELDS_HASH_NONCE             = 0x0030,
  SSH_IKE_FIELDS_HASH_NONCE_SA          = 0x0031,
  SSH_IKE_FIELDS_HASH_NONCE_KE          = 0x0032,
  SSH_IKE_FIELDS_HASH_NONCE_KE_SA       = 0x0033,
  SSH_IKE_FIELDS_HASH_NONCE_ID          = 0x0034,
  SSH_IKE_FIELDS_HASH_NONCE_ID_SA       = 0x0035,
  SSH_IKE_FIELDS_HASH_NONCE_ID_KE       = 0x0036,
  SSH_IKE_FIELDS_HASH_NONCE_ID_KE_SA    = 0x0037,
  SSH_IKE_FIELDS_HASH_NONCE_SIG         = 0x0038,
  SSH_IKE_FIELDS_HASH_NONCE_SIG_SA      = 0x0039,
  SSH_IKE_FIELDS_HASH_NONCE_SIG_KE      = 0x003a,
  SSH_IKE_FIELDS_HASH_NONCE_SIG_KE_SA   = 0x003b,
  SSH_IKE_FIELDS_HASH_NONCE_SIG_ID      = 0x003c,
  SSH_IKE_FIELDS_HASH_NONCE_SIG_ID_SA   = 0x003d,
  SSH_IKE_FIELDS_HASH_NONCE_SIG_ID_KE   = 0x003e,
  SSH_IKE_FIELDS_HASH_NONCE_SIG_ID_KE_SA= 0x003f,
  SSH_IKE_FIELDS_CR                     = 0x0040,
  SSH_IKE_FIELDS_CR_HASH                = 0x0060,
  SSH_IKE_FIELDS_CERT                   = 0x0080,
  SSH_IKE_FIELDS_CERT_HASH              = 0x00a0,
  SSH_IKE_FIELDS_CERT_CR                = 0x00c0,
  SSH_IKE_FIELDS_CERT_CR_HASH           = 0x00e0,
  SSH_IKE_FIELDS_D                      = 0x0100,
  SSH_IKE_FIELDS_D_HASH                 = 0x0120,
  SSH_IKE_FIELDS_N                      = 0x0200,
  SSH_IKE_FIELDS_N_ID_KE                = 0x0206,
  SSH_IKE_FIELDS_N_HASH                 = 0x0220,
  SSH_IKE_FIELDS_N_CR                   = 0x0240,
  SSH_IKE_FIELDS_N_CR_HASH              = 0x0260,
  SSH_IKE_FIELDS_N_CERT                 = 0x0280,
  SSH_IKE_FIELDS_N_CERT_HASH            = 0x02a0,
  SSH_IKE_FIELDS_N_CERT_CR              = 0x02c0,
  SSH_IKE_FIELDS_N_CERT_CR_HASH         = 0x02e0,
  SSH_IKE_FIELDS_VID                    = 0x0400,
  SSH_IKE_FIELDS_VID_CR                 = 0x0440,
  SSH_IKE_FIELDS_VID_CR_HASH            = 0x0460,
  SSH_IKE_FIELDS_VID_CERT               = 0x0480,
  SSH_IKE_FIELDS_VID_CERT_HASH          = 0x04a0,
  SSH_IKE_FIELDS_VID_CERT_CR            = 0x04c0,
  SSH_IKE_FIELDS_VID_CERT_CR_HASH       = 0x04e0,
  SSH_IKE_FIELDS_VID_D                  = 0x0500,
  SSH_IKE_FIELDS_VID_D_HASH             = 0x0520,
  SSH_IKE_FIELDS_VID_N                  = 0x0600,
  SSH_IKE_FIELDS_VID_N_HASH             = 0x0620,
  SSH_IKE_FIELDS_VID_N_CR               = 0x0640,
  SSH_IKE_FIELDS_VID_N_CR_HASH          = 0x0660,
  SSH_IKE_FIELDS_VID_N_CERT             = 0x0680,
  SSH_IKE_FIELDS_VID_N_CERT_HASH        = 0x06a0,
  SSH_IKE_FIELDS_VID_N_CERT_CR          = 0x06c0,
  SSH_IKE_FIELDS_VID_N_CERT_CR_HASH     = 0x06e0,
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SSH_IKE_FIELDS_ATTR                   = 0x0800,
  SSH_IKE_FIELDS_ATTR_HASH              = 0x0820,
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  SSH_IKE_FIELDS_ANY                    = 0xffff
} SshIkeFields;

/* Max number of operations in input and output lists. */
#define SSH_IKE_OPERATIONS_MAX 20

/* Isakmp state machine description structure */
struct SshIkeStateMachineRec {
  SshIkeProtocolState state;    /* Current state */
  SshIkeProtocolState next_state; /* Next state */
  SshIkeAuthMeth auth_method; /* Authentication method */
  SshIkeExchangeType xchg_type; /* Exchange type */
  SshIkeFields mandatory_input_fields; /* Fields that must be given */
  SshIkeFields optional_input_fields; /* Fields that may be given */
  SshIkeInputStateFunction in_funcs[SSH_IKE_OPERATIONS_MAX]; /* Null terminated
                                                               list of
                                                               functions */
  SshIkeOutputStateFunction out_funcs[SSH_IKE_OPERATIONS_MAX]; /* Null
                                                                 terminated
                                                                 list of
                                                                 functions */
};

/*                                                              shade{0.9}
 * Isakmp state machine input function prototypes               shade{1.0}
 */

#define I_F(x)                                                  \
SshIkeNotifyMessageType (x)(SshIkeContext isakmp_context,       \
                            SshIkePacket isakmp_input_packet,   \
                            SshIkeSA isakmp_sa,                 \
                            SshIkeNegotiation negotiation,      \
                            SshIkeStateMachine state)

I_F(ike_st_i_sa_proposal);
I_F(ike_st_i_sa_value);
I_F(ike_st_i_ke);
I_F(ike_st_i_id);
I_F(ike_st_i_cert);
I_F(ike_st_i_cr);
I_F(ike_st_i_hash);
#ifdef SSHDIST_IKE_CERT_AUTH
I_F(ike_st_i_hash_key);
I_F(ike_st_i_sig);
#endif /* SSHDIST_IKE_CERT_AUTH */
I_F(ike_st_i_nonce);
I_F(ike_st_i_qm_hash_1);
I_F(ike_st_i_qm_hash_2);
I_F(ike_st_i_qm_hash_3);
I_F(ike_st_i_qm_sa_proposals);
I_F(ike_st_i_qm_sa_values);
I_F(ike_st_i_qm_ids);
I_F(ike_st_i_qm_ke);
I_F(ike_st_i_qm_nonce);
I_F(ike_st_i_gen_hash);
I_F(ike_st_i_ngm_sa_proposal);
I_F(ike_st_i_ngm_sa_values);
I_F(ike_st_i_status_n);
I_F(ike_st_i_n);
I_F(ike_st_i_d);
I_F(ike_st_i_vid);
I_F(ike_st_i_encrypt);
I_F(ike_st_i_retry_now);
#ifdef SSHDIST_ISAKMP_CFG_MODE
I_F(ike_st_i_cfg_restart);
I_F(ike_st_i_cfg_attr);
#endif /* SSHDIST_ISAKMP_CFG_MODE */
I_F(ike_st_i_private);
#undef I_F

/*                                                              shade{0.9}
 * Isakmp state machine output function prototypes              shade{1.0}
 */

#define O_F(x)                                                  \
SshIkeNotifyMessageType (x)(SshIkeContext isakmp_context,       \
                            SshIkePacket isakmp_input_packet,   \
                            SshIkePacket isakmp_output_packet,  \
                            SshIkeSA isakmp_sa,                 \
                            SshIkeNegotiation negotiation,      \
                            SshIkeStateMachine state)

O_F(ike_st_o_sa_proposal);
O_F(ike_st_o_sa_values);
O_F(ike_st_o_ke);
O_F(ike_st_o_nonce);
O_F(ike_st_o_id);
#ifdef SSHDIST_IKE_CERT_AUTH
O_F(ike_st_o_sig);
#endif /* SSHDIST_IKE_CERT_AUTH */
O_F(ike_st_o_sig_or_hash);
O_F(ike_st_o_hash);
#ifdef SSHDIST_IKE_CERT_AUTH
O_F(ike_st_o_cr);
#endif /* SSHDIST_IKE_CERT_AUTH */
O_F(ike_st_o_vids);
#ifdef SSHDIST_IKE_CERT_AUTH
O_F(ike_st_o_certs);
O_F(ike_st_o_optional_certs);
#endif /* SSHDIST_IKE_CERT_AUTH */
O_F(ike_st_o_get_pre_shared_key);
O_F(ike_st_o_encrypt);
O_F(ike_st_o_calc_skeyid);
O_F(ike_st_o_optional_encrypt);
#ifdef SSHDIST_IKE_CERT_AUTH
O_F(ike_st_o_hash_key);
#endif /* SSHDIST_IKE_CERT_AUTH */
O_F(ike_st_o_status_n);
O_F(ike_st_o_qm_hash_1);
O_F(ike_st_o_qm_hash_2);
O_F(ike_st_o_qm_hash_3);
O_F(ike_st_o_qm_sa_proposals);
O_F(ike_st_o_qm_sa_values);
O_F(ike_st_o_qm_nonce);
O_F(ike_st_o_qm_optional_ke);
O_F(ike_st_o_qm_optional_ids);
O_F(ike_st_o_qm_optional_responder_lifetime_n);
O_F(ike_st_o_gen_hash);
O_F(ike_st_o_ngm_sa_proposal);
O_F(ike_st_o_ngm_sa_values);
O_F(ike_st_o_rerun);
O_F(ike_st_o_wait_done);
O_F(ike_st_o_copy_iv);
O_F(ike_st_o_done);
O_F(ike_st_o_qm_done);
O_F(ike_st_o_qm_wait_done);
O_F(ike_st_o_ngm_done);
O_F(ike_st_o_ngm_wait_done);
O_F(ike_st_o_n_done);
O_F(ike_st_o_d_done);
#ifdef SSHDIST_ISAKMP_CFG_MODE
O_F(ike_st_o_cfg_attr);
O_F(ike_st_o_cfg_done);
O_F(ike_st_o_cfg_wait_done);
#endif /* SSHDIST_ISAKMP_CFG_MODE */
O_F(ike_st_o_private);
#undef O_F

#endif /* ISAKMP_STATE_H */
