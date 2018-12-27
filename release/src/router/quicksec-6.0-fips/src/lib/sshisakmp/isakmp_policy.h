/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp policy manager function calls.
*/

#ifndef ISAKMP_POLICY_H
#define ISAKMP_POLICY_H

#ifndef ISAKMP_H
#error "Do not include this file, include the isakmp.h instead"
#endif /* ISAKMP_H */

/*
 * All policy manager functions get policy manager info as a first argument and
 * that struct contains also the policy manager context given to start server
 * function. All items returned by policy manager to isakmp library should be
 * mallocated copy if the item and isakmp library will free it using ssh_free
 * when it doesn't need it any more.
 */

#ifdef SSHDIST_IKE_CERT_AUTH
/* Type of key to search */
typedef enum {
  SSH_IKE_POLICY_KEY_TYPE_RSA_SIG,
  SSH_IKE_POLICY_KEY_TYPE_RSA_ENC,
  SSH_IKE_POLICY_KEY_TYPE_DSS_SIG
#ifdef SSHDIST_CRYPT_ECP
  , SSH_IKE_POLICY_KEY_TYPE_ECP_DSA_SIG
#endif /* SSHDIST_CRYPT_ECP */
} SshPolicyKeyType;
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Generic isakmp authentication methods */
typedef enum {
  SSH_IKE_AUTH_METHOD_ANY,
  SSH_IKE_AUTH_METHOD_PHASE_1,
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_IKE_AUTH_METHOD_SIGNATURES,
  SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION,
#endif /* SSHDIST_IKE_CERT_AUTH */
  SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY
} SshIkeAuthMeth;

/* Policy manager context. */
struct SshIkePMContextRec {
  void *upper_context;          /* Isakmpd context. This context is used by
                                   the upper level library using the isakmp
                                   library to store policy information. */
#ifdef SSHDIST_IKE_CERT_AUTH
  void *certificate_cache;      /* Certificate cache context. This context is
                                   used by the isakmp_policy.c to make simple
                                   certificate processing operations. */
  void *private_key_cache;      /* Private key cache context. This context is
                                   used by the policy manager to implement
                                   find_private_key operation. */
#endif /* SSHDIST_IKE_CERT_AUTH */
  void *pre_shared_key_cache;   /* Pre shared key cache context. This context
                                   is used by the policy manager to implement
                                   find_pre_shared_key operation. */
};

#ifdef SSHDIST_IKEV2
/* Flag values for the unified server context */
#define SSH_IKE_SERVER_FLAG_NAT_T_LOCAL_PORT    0x1
#endif /* SSHDIST_IKEV2 */

/* Phase I policy info structure. This structure is given to all phase I policy
   functions, and pointer to it is also included in phase II policy info
   structure. */
struct SshIkePMPhaseIRec {
  SshIkePMContext pm;

  /* Filled by isakmp library */
  SshIkeCookies cookies;        /* Pointer to cookies (SshIkeSA structure).
                                   This is always valid. */
  SshIkeNegotiation negotiation; /* ISAKMP SA negotiation pointer. */
  SshIkePayloadID local_id;     /* Local end identity in phase I (malloc). This
                                   may be NULL if no id received yet. */
  char *local_id_txt;           /* Text version of local end id (malloc). This
                                   value is always valid, and contains "No Id"
                                   if identity has not yet been received. This
                                   is for debugging printf purposes. */
  SshIkePayloadID remote_id;    /* Remote end identity in phase I (malloc).
                                   This may be NULL if no id received yet. */
  char *remote_id_txt;          /* Text version of remote end id (malloc). This
                                   value is always valid, and contains "No Id"
                                   if identity has not yet been received. This
                                   is for debugging printf purposes. */

  /* These are always valid: */
  unsigned char *local_ip;      /* Local ip number (malloc). */
  unsigned char *local_port;    /* Local port number (malloc) */
  unsigned char *remote_ip;     /* Remote ip number (malloc) */
  unsigned char *remote_port;   /* Remote port number (malloc) */
  int major_version;            /* Major version from the packet */
  int minor_version;            /* Minor version from the packet */
  SshIkeExchangeType exchange_type; /* Exchange type */
  Boolean this_end_is_initiator; /* This end is initiator. */

  /* These are filled after we have processed the responders SA. */
  SshIkeAuthMeth auth_method_type; /* Copy of current generic authentication
                                      method type */
  SshIkeAttributeAuthMethValues auth_method; /* Explisit authentication method
                                                used in this negotiation. */
#ifdef SSHDIST_IKE_XAUTH
  Boolean hybrid_edge;           /* We are the edge device in hybrid auth. */
  Boolean hybrid_client;         /* We are the client in hybrid auth. */
#endif /* SSHDIST_IKE_XAUTH */

  /* Filled by policy manager sa selection module */
  SshTime sa_start_time;         /* SA creation time, select_sa function
                                   will set this. */
  SshTime sa_expire_time;        /* SA expiration time, select_sa or
                                   ike_st_i_sa_values function
                                   will calculate and set this. */

  /* Filled by policy manager authentication module, freed by isakmp
     library. */
  void *auth_data;              /* Policy manager data pointer for
                                   authentication data. The isakmp library
                                   doesn't do anything with this. The policy
                                   manager can allocate some data here, and it
                                   will be passed to next call to policy
                                   manager. The policy manager is also allowed
                                   to modify / free this data at will. The
                                   isakmp library will automatically call
                                   ssh_free for this object when negotiation
                                   is deleted. This can be used to store
                                   certificate or pre shared key data used to
                                   authenticate this negotiation. This is
                                   usually filled in
                                   find_public_key/find_pre_shared_key etc
                                   functions. */
  size_t auth_data_len;         /* Length of authentication data (internal to
                                   policy manager). This is here so the
                                   auth_data can be just a string (certificate
                                   or pre shared key) and this can be used to
                                   specify the length of the string. */
  void *own_auth_data;          /* Policy manager data pointer for
                                   authentication data. The isakmp library
                                   doesn't do anything with this. The policy
                                   manager can allocate some data here, and it
                                   will be passed to next call to policy
                                   manager. The policy manager is also allowed
                                   to modify / free this data at will. The
                                   isakmp library will automatically call
                                   ssh_free for this object when negotiation
                                   is deleted. This can be used to store the
                                   local certificate or pre shared key data
                                   used to authenticate this negotiation. This
                                   should be filled in find_private_key
                                   function, and used in request_certificates
                                   function. */
  size_t own_auth_data_len;     /* Length of authentication data (internal to
                                   policy manager). This is here so the
                                   auth_data can be just a string (certificate
                                   or pre shared key) and this can be used to
                                   specify the length of the string. */

#ifdef SSHDIST_IKE_CERT_AUTH
  SshPublicKey public_key;      /* Public key of the local end. Filled in
                                   in find_private_key function. Freed by the
                                   ISAKMP library. */
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
  /* Filled by policy manager certificate processing module, freed by isakmp
     library. */
  int number_of_certificates;   /* Number of certificates given by the other
                                   end. */
  int number_of_allocated_certificates; /* Size of certificates and
                                           certificate_lens tables. This is the
                                           allocated size and the
                                           number_of_certificates is the used
                                           size. If 0 then certificates and
                                           certificate_lens are not
                                           allocated. */
  char **certificates;          /* Array of certificates given by the other
                                   end. Note, this is all certificates given by
                                   the other end, all of them might not be
                                   used. The new_certificates function fills
                                   this and isakmp library will free each
                                   certificate with ssh_free and the array
                                   itself. */
  size_t *certificate_lens;     /* Array of certificate lengths. Filled by
                                   new_certificates function and freed by
                                   isakmp library. */
  SshIkeCertificateEncodingType *certificate_encodings;
                                /* Array of certificate encodings. Filled by
                                   new_certificates function and freed by
                                   isakmp library. */
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Internal policy manager structure pointer */
  void *policy_manager_data;    /* Policy manager data pointer. The isakmp
                                   library doesn't do anything with that. The
                                   policy manager can allocate some data here,
                                   and it will be passed to next call to policy
                                   manager. The policy manager is also allowed
                                   to modify / free this data at will. The
                                   isakmp library will automatically call
                                   ssh_free for this object when negotiation
                                   is deleted. */

  /* Doi of the Phase 1 negotiation. Filled in after the SA payload has been
     processed. */
  SshIkeDOI doi;
#ifdef SSHDIST_IKEV2
  /* Flags used for selecting the listener in the unified server context */
  SshUInt32 server_flags;
#endif /* SSHDIST_IKEV2 */
};

/* Phase II Qm policy info structure. This structure is given to all quick mode
   policy functions. */
struct SshIkePMPhaseQmRec {
  SshIkePMContext pm;

  /* Filled by isakmp library */
  SshIkePMPhaseI phase_i;       /* Pointer to phase I negotiation info. This is
                                   always valid. */

  SshIkeNegotiation negotiation; /* QM negotiation pointer. */

  SshIkePayloadID local_i_id;   /* Local end identity set by initiator
                                   (malloc). This may be NULL. */
  char *local_i_id_txt;         /* Text version of local end id (malloc). This
                                   value is always valid, and contains "No Id"
                                   if identity has not yet been received. This
                                   is for debugging printf purposes. */
  SshIkePayloadID local_r_id;   /* Local end identity set by responder
                                   (malloc). This may be NULL. */
  char *local_r_id_txt;         /* Text version of local end id (malloc). This
                                   value is always valid, and contains "No Id"
                                   if identity has not yet been received. This
                                   is for debugging printf purposes. */
  SshIkePayloadID remote_i_id;  /* Remote end identity set by initiator
                                   (malloc). This may be NULL. */
  char *remote_i_id_txt;        /* Text version of remote end id (malloc). This
                                   value is always valid, and contains "No Id"
                                   if identity has not yet been received. This
                                   is for debugging printf purposes. */
  SshIkePayloadID remote_r_id;  /* Remote end identity set by responder
                                   (malloc). This may be NULL. */
  char *remote_r_id_txt;        /* Text version of remote end id (malloc). This
                                   value is always valid, and contains "No Id"
                                   if identity has not yet been received. This
                                   is for debugging printf purposes. */

  /* These are always valid: */
  unsigned char *local_ip;      /* Local ip number (malloc) */
  unsigned char *local_port;    /* Local port number (malloc) */
  unsigned char *remote_ip;     /* Remote ip number (malloc) */
  unsigned char *remote_port;   /* Remote port number (malloc) */
  SshIkeExchangeType exchange_type; /* Exchange type */
  Boolean this_end_is_initiator; /* This end is initiator. */
  SshUInt32 message_id;         /* Copy message id of this exchange */

  /* Filled by policy manager sa selection module, note that these might be
     changed by the policy manager because of responder lifetime or certificate
     validity checks from the values the initiator selected. */
  unsigned long sa_expire_timer_sec;/* SA expire timer value. */
  unsigned long sa_expire_timer_kb;/* SA expire kilobyte value. */

  /* Internal policy manager structure pointer */
  void *policy_manager_data;    /* Policy manager data pointer. The isakmp
                                   library doesn't do anything with that. The
                                   policy manager can allocate some data here,
                                   and it will be passed to next call to policy
                                   manager. The policy manager is also allowed
                                   to modify / free this data at will. The
                                   isakmp library will automatically call
                                   ssh_free for this object when negotiation
                                   is deleted. */
#ifdef SSHDIST_IKEV2
  /* Flags used for selecting the listener in the unified server context */
  SshUInt32 server_flags;
#endif /* SSHDIST_IKEV2 */
};

/* Generic phase II policy info structure. This structure is given to all other
   phase II functions (ngm, info, and delete). */
struct SshIkePMPhaseIIRec {
  SshIkePMContext pm;

  /* Filled by isakmp library */
  SshIkePMPhaseI phase_i;       /* Pointer to phase I negotiation info */

  SshIkeNegotiation negotiation; /* Phase II negotiation pointer. */

  unsigned char *local_ip;      /* Local ip number (malloc) */
  unsigned char *local_port;    /* Local port number (malloc) */
  unsigned char *remote_ip;     /* Remote ip number (malloc) */
  unsigned char *remote_port;   /* Remote port number (malloc) */
  SshIkeExchangeType exchange_type; /* Exchange type */
  Boolean this_end_is_initiator; /* This end is initiator. */
  SshUInt32 message_id;         /* Copy message id of this exchange */

  /* Internal policy manager structure pointer */
  void *policy_manager_data;    /* Policy manager data pointer. The isakmp
                                   library doesn't do anything with that. The
                                   policy manager can allocate some data here,
                                   and it will be passed to next call to policy
                                   manager. The policy manager is also allowed
                                   to modify / free this data at will. The
                                   isakmp library will automatically call
                                   ssh_free for this object when negotiation
                                   is deleted. */
#ifdef SSHDIST_IKEV2
  /* Flags used for selecting the listener in the unified server context */
  SshUInt32 server_flags;
#endif /* SSHDIST_IKEV2 */
};


/* Callback function to call when policy manager has the initial config data
   for isakmp sa negotiation. If allow_connection is false the whole connection
   is immediately dropped without any notification. If the integer parameters
   are < 0, and if compat_flags is SSH_IKE_FLAGS_USE_DEFAULTS, then the
   defaults from the server is taken. */

/* See ISAKMP_FLAGS_* for compat_flags. */
typedef void (*SshPolicyNewConnectionCB)(Boolean allow_connection,
                                         SshUInt32 compat_flags,
                                         SshInt32 retry_limit,
                                         SshInt32 retry_timer,
                                         SshInt32 retry_timer_usec,
                                         SshInt32 retry_timer_max,
                                         SshInt32 retry_timer_max_usec,
                                         SshInt32 expire_timer,
                                         SshInt32 expire_timer_usec,
                                         void *context);

/* Get initial config data for the new isakmp connection. This will be called
   immediately when a new phase I negotiation is received before any processing
   is done for the payload itself. The compatibility flags can only be set at
   this point. The pm_info only have following fields: cookies, local_ip,
   local_port, remote_ip, remote_port, major_version, minor_version, and
   exchange_type.

   Call callback_in when the data is available (it can also be called
   immediately). */

void ssh_policy_new_connection(SshIkePMPhaseI pm_info,
                               SshPolicyNewConnectionCB callback_in,
                               void *callback_context_in);

/* Get initial config data for the new phase II negotiation. This will be
   called immediately when a new phase II negotiation packet is received before
   any processing is done for the payload itself. The compatibility flags can
   only be set at this point. The pm_info only have following fields: phase_i,
   local_ip, local_port, remote_ip, remote_port, exchange_type, and message_id.

   Call callback_in when the data is available (it can also be called
   immediately). */

void ssh_policy_new_connection_phase_ii(SshIkePMPhaseII pm_info,
                                        SshPolicyNewConnectionCB callback_in,
                                        void *callback_context_in);


/* Get initial config data for the new quick mode negotiation. This will be
   called immediately when a new quick mode negotiation packet is received
   before any processing is done for the payload itself. The compatibility
   flags can only be set at this point. The pm_info only have following fields:
   phase_i, local_ip, local_port, remote_ip, remote_port, exchange_type, and
   message_id.

   Call callback_in when the data is available (it can also be called
   immediately). */

void ssh_policy_new_connection_phase_qm(SshIkePMPhaseQm pm_info,
                                        SshPolicyNewConnectionCB callback_in,
                                        void *callback_context_in);

#ifdef SSHDIST_IKE_CERT_AUTH
/* Callback function to call from find_public_key when the public key data is
   ready. If no key is found the public_key_out is NULL. The public_key is copy
   of the public key and the isakmp library will free it after the negotiation
   ends. The hash_out is freed by the isakmp library after isakmp library
   doesn't need it any more. */
typedef void (*SshPolicyFindPublicKeyCB)(SshPublicKey public_key_out,
                                         unsigned char *hash_out,
                                         size_t hash_len_out,
                                         void *context);

/* Find public key for remote host. The primary selector is the id fields if
   they are given, and if they are NULL then the ip address is used as
   selector.

   If hash_alg_in is not NULL and there is multiple keys for the host, then
   return hash of the selected key in the hash_out buffer. The length of hash
   is hash_len_out. The isakmp library will free the buffer, after it is no
   longer needed. If the isakmp/oakley should't send hash of key to remote end
   then, then hash_len_out is set to zero, and hash_out to NULL.

   Call callback_in when the data is available (it can also be called
   immediately). */

void ssh_policy_find_public_key(SshIkePMPhaseI pm_info,
                                SshPolicyKeyType key_type_in,
                                const unsigned char *hash_alg_in,
                                SshPolicyFindPublicKeyCB callback_in,
                                void *callback_context_in);


/* Callback function to call from find_private_key when the private key data is
   ready. If no key is found the private_key_out is NULL. The private_key is
   copy of the private key and the ISAKMP library will free it after the
   negotiation ends. */
typedef void (*SshPolicyFindPrivateKeyCB)(SshPrivateKey private_key_out,
                                          void *context);

/* Find private key for local host. The primary selector is the hash of the
   certificate of the key if it is given. The secondary selector is the id
   fields if they are given, and if they are NULL then the ip address is used
   as selector. Call callback_in when the data is available (it can also be
   called immediately). */

void ssh_policy_find_private_key(SshIkePMPhaseI pm_info,
                                 SshPolicyKeyType key_type,
                                 const unsigned char *hash_alg_in,
                                 const unsigned char *hash_in,
                                 size_t hash_len_in,
                                 SshPolicyFindPrivateKeyCB callback_in,
                                 void *callback_context_in);
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Callback function to call from find_pre_shared_key when the preshared key
   data is ready. If no data is found the key_out is NULL. The key_out is a
   copy of pre shared key, and ISAKMP library will free it when it doesn't need
   it anymore. */
typedef void (*SshPolicyFindPreSharedKeyCB)(unsigned char *key_out,
                                            size_t key_out_len,
                                            void *context);


/* Find pre shared secret for host. The primary selector is the id fields if
   they are given and if they are NULL then ip address is used instead. Call
   callback_in when the data is available (it can also be called immediately).
   */

void ssh_policy_find_pre_shared_key(SshIkePMPhaseI pm_info,
                                    SshPolicyFindPreSharedKeyCB callback_in,
                                    void *callback_context_in);

#ifdef SSHDIST_IKE_CERT_AUTH
/* The ISAKMP library calls this function to process certificate data. The
   function should add the certificate to certificate tables and if it can
   trust the new keys add them to the public key database.

   If the function does not trust the keys, it just ignores the certificate.
   The certificate encoding can be any of the supported certificate types found
   in <tt/isakmp.h/. The certificate_data is freed after this call. */

void ssh_policy_new_certificate(SshIkePMPhaseI pm_info,
                                SshIkeCertificateEncodingType cert_encoding,
                                unsigned char *certificate_data,
                                size_t certificate_data_len);

/* Callback function to call from request_certificates when the
   certificate chain is ready. All the tables are arrays that have
   number_of_cas entries, and each entry in the tables correspons to
   reply to one CA request. If no data is found for that CA the
   number_of_certificates is 0. If non zero number of certificates is
   returned then certs and cert_lengths tables are allocated and the
   certs table contains mallocated pointers to certificates and
   cert_lengths table contains their size respectively. The isakmp
   library is responsible of freeing all tables and certificate data
   in them after it doesn't need them anymore. The certificate chains
   for each CA must be returned ordered so that the trust anchor (or
   topmost CA is first, and subject certificate is the last. */

typedef void (*SshPolicyRequestCertificatesCB)(int *number_of_certificates,
                                               SshIkeCertificateEncodingType
                                               **cert_encodings,
                                               unsigned char ***certs,
                                               size_t **cert_lengths,
                                               void *context);

/* Get chain of certificates with given encoding and to given certificate
   authority. Call callback_in when the data is available (it can also be
   called immediately). */
void ssh_policy_request_certificates(SshIkePMPhaseI pm_info,
                                     int number_of_cas,
                                     SshIkeCertificateEncodingType
                                     *ca_encodings,
                                     unsigned char **certificate_authorities,
                                     size_t *certificate_authority_lens,
                                     SshPolicyRequestCertificatesCB
                                     callback_in,
                                     void *callback_context_in);

/* Callback function to call from get_certificate_authorities, when the list of
   certificate authorities is ready. If no certificate authorities is to be
   send to other end then set the number_of_cas to zero. If non zero number of
   ca's is returned then ca_encodings, ca_names, and ca_name_lens tables are
   allocated and contain the encoding type, CA distinguished name and CA
   distinguished name lengths. The ISAKMP library is responsible of freeing all
   tables, and the ca_name data after it doesn't need it anymore. */

typedef void (*SshPolicyGetCAsCB)(int number_of_cas,
                                  SshIkeCertificateEncodingType *ca_encodings,
                                  unsigned char **ca_names,
                                  size_t *ca_name_lens,
                                  void *context);

/* Get certificate authority list to be sent to other end. Call callback_in
   when the data is available (it can also be called immediately). This list is
   used in two places, first it is used to request certificates from CA to our
   own key from our certificate cache so those certificates can be sent to
   other end. Secondly it is used to send certificate requests to other end. */
void ssh_policy_get_certificate_authorities(SshIkePMPhaseI pm_info,
                                            SshPolicyGetCAsCB callback_in,
                                            void *callback_context_in);
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Callback function to call from the nonce_data_len when the data is
   available. */
typedef void (*SshPolicyNonceDataLenCB)(size_t nonce_data_len,
                                        void *context);

/* Ask how many bytes of nonce data should we create for this connection. Call
   callback_in when the data is available (it can also be called immediately).
   */
void ssh_policy_isakmp_nonce_data_len(SshIkePMPhaseI pm_info,
                                      SshPolicyNonceDataLenCB callback_in,
                                      void *callback_context_in);

/* Callback function to call from the isakmp_id when the identity data is
   ready. The payload will be freed by the ISAKMP code when it is not needed
   anymore. If id_payload is NULL then no identity payload is used (only
   possible in the quick mode, in main mode it means that system is out of
   memory, thus the negotiation is aborted with out of memory error). */
typedef void (*SshPolicyIsakmpIDCB)(SshIkePayloadID id_payload,
                                    void *context);

/* Ask our own local id for ISAKMP SA negotiation. Call callback_in when the
   data is available (it can also be called immediately). */
void ssh_policy_isakmp_id(SshIkePMPhaseI pm_info,
                          SshPolicyIsakmpIDCB callback_in,
                          void *callback_context_in);

/* Request policy manager to process vendor id information. */
void ssh_policy_isakmp_vendor_id(SshIkePMPhaseI pm_info,
                                 unsigned char *vendor_id,
                                 size_t vendor_id_len);

/* Callback to call when policy manager have the vendor id payloads ready. If
   number_of_vids is zero then no vendor id payloads is added. If non zero
   number of vendor id payload is returned then vendor_ids and vendor_id_lens
   tables are allocated and the vendor_ids table contains mallocated pointers
   to vendor_ids and vendor_id_lens table contains their size respectively. The
   ISAKMP library is responsible of freeing both vendor_ids data, vendor_id
   contents and vendor_id_lens tables after they doesn't need them anymore. */
typedef void (*SshPolicyRequestVendorIDsCB)(int number_of_vids,
                                            unsigned char **vendor_ids,
                                            size_t *vendor_id_lens,
                                            void *context);

/* Get vendor id payloads. Call callback_in when the data is available (it can
   also be called immediately). */
void ssh_policy_isakmp_request_vendor_ids(SshIkePMPhaseI pm_info,
                                          SshPolicyRequestVendorIDsCB
                                          callback_in,
                                          void *callback_context_in);

/* Function call when ssh_policy_{isakmp,ngm}_select_sa wants to return data.
   When it is finished it will call this function and provide selected proposal
   and table of all transforms selected in proposal. If selected_proposal is -1
   then no proposal was chosen. The ISAKMP library will free transforms_indexes
   when it doesn't need it anymore. */
typedef void (*SshPolicySACB)(int proposal_index, int number_of_protocols,
                              int *transforms_indexes, void *context);

/* Send query to policy manager that will select one proposal isakmp sa, and
   select one transform from each protocol in proposal. When it is ready it
   will call callback_in and give information of selected sa to it. This can
   also call callback immediate if the answer can be given immediately. */

void ssh_policy_isakmp_select_sa(SshIkePMPhaseI pm_info,
                                 SshIkeNegotiation negotiation,
                                 SshIkePayload sa_in,
                                 SshPolicySACB callback_in,
                                 void *callback_context_in);

/* Send query to policy manager that will select one proposal ngm sa, and
   select one transform from each protocol in proposal. When it is ready it
   will call callback_in and give information of selected sa to it. This can
   also call callback immediate if the answer can be given immediately. */

void ssh_policy_ngm_select_sa(SshIkePMPhaseII pm_info,
                              SshIkeNegotiation negotiation,
                              SshIkePayload sa_in,
                              SshPolicySACB callback_in,
                              void *callback_context_in);


/* Selected proposal and transforms returned by policy manager, all tables are
   malloceted by policy manager and freed by isakmp module. */
struct SshIkeIpsecSelectedSAIndexesRec {
  int proposal_index;           /* Index to selected proposal table in
                                   SshIkePayloadSA. If -1 then no proposal
                                   selected  */
  int number_of_protocols;      /* Number of protocols in this SA */
  int *transform_indexes;       /* Mallocated table of indexes of selected
                                   transform in table in SshIkePayloadT of all
                                   protocols */
  size_t *spi_sizes;            /* Mallocated table of spi_sizes for each
                                   transform selected. Policy manager fills
                                   this. */
  unsigned char **spis;         /* Mallocated table of mallocated spi values
                                   for each transform. Policy manager allocates
                                   and fills this. */
  unsigned long expire_secs;    /* If set to non zero then send RESPONDER
                                   LIFETIME notification to other end giving
                                   this value as lifetime of the IPsec SA in
                                   seconds. If the value is zero then assume
                                   that the value offered by the other end is
                                   acceptable by the policy, and there is no
                                   need to send RESPONDER LIFETIME
                                   notifications. */
  unsigned long expire_kb;      /* See documentation above, except this gives
                                   the kilobyte limit. */
};

/* Function call when ssh_policy_qm_select_sa wants to return data. When it is
   finished it will call this function and provide mallocate structure
   containing reply to all sa queries. If return_values is NULL then any of the
   sas didn't have any suitable proposals. The ISAKMP library will free
   return_values data after it is no longer needed. */
typedef void (*SshPolicyQmSACB)(SshIkeIpsecSelectedSAIndexes return_values,
                                void *context);

/* Send query to policy manager that will select one proposal for each sa, and
   select one transform from each protocol in proposal. It will also fill in
   the return spi sizes and values. When it is ready it will call callback_in
   and give IpsecSelectedSAIndexes structure in. This can also call callback
   immediate if the answer can be given immediately. */

void ssh_policy_qm_select_sa(SshIkePMPhaseQm pm_info,
                             SshIkeNegotiation negotiation,
                             int number_of_sas_in,
                             SshIkePayload *sa_table_in,
                             SshPolicyQmSACB callback_in,
                             void *callback_context_in);

/* Ask how many bytes of nonce data should we create for this connection. Call
   callback_in when the data is available (it can also be called immediately).
   */
void ssh_policy_qm_nonce_data_len(SshIkePMPhaseQm pm_info,
                                  SshPolicyNonceDataLenCB callback_in,
                                  void *callback_context_in);

/* Ask our own local id for quick mode negotiation. Call callback_in when the
   data is available (it can also be called immediately). Only initiator
   identities are set in the pm_info. */
void ssh_policy_qm_local_id(SshIkePMPhaseQm pm_info,
                            SshPolicyIsakmpIDCB callback_in,
                            void *callback_context_in);

/* Ask our own user id for isakmp_sa negotiation. Call callback_in when the
   data is available (it can also be called immediately). Only initiator
   identities are set in the pm_info. */
void ssh_policy_qm_remote_id(SshIkePMPhaseQm pm_info,
                             SshPolicyIsakmpIDCB callback_in,
                             void *callback_context_in);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Function call when ssh_policy_cfg_fill_attrs wants to return data. When it
   is finished, it will call this function and provide mallocate structure
   containing reply to all attribute queries. If the number_of_attrs is zero
   then no attributes will be returned. The ISAKMP library will free
   return_attributes data after it is no longer needed. The values pointed by
   attributes are assumed to be combined with the table, so freeing the table
   should also free the values pointed by data attributes entries. */
typedef void (*SshPolicyCfgFillAttrsCB)(int number_of_attrs,
                                        SshIkePayloadAttr *return_attributes,
                                        void *context);

/* Request policy manager to process configuration mode exchange values. It
   should fill in or accept all values to newly allocated table of attributes
   and call SshPolicyCfgFillAttrsCB callback with that table. */
void ssh_policy_cfg_fill_attrs(SshIkePMPhaseII pm_info,
                               int number_of_attrs,
                               SshIkePayloadAttr *return_attributes,
                               SshPolicyCfgFillAttrsCB callback_in,
                               void *callback_context_in);

/* Inform policy manager about configuration mode exchange values
   received from remote side. This occurs when we already have local
   variables, and no query for them is necessary. */
void ssh_policy_cfg_notify_attrs(SshIkePMPhaseII pm_info,
                                 int number_of_attrs,
                                 SshIkePayloadAttr *return_attributes);

#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Request policy manager to delete following spi values. Note that if
   authenticated is TRUE this negotiation was under isakmp sa protection. */
void ssh_policy_delete(SshIkePMPhaseII pm_info,
                       Boolean authenticated,
                       SshIkeProtocolIdentifiers protocol_id,
                       int number_of_spis,
                       unsigned char **spis,
                       size_t spi_size);

/* Request policy manager to process notification message. Note that if
   authenticated is TRUE this negotiation was under isakmp sa protection. */
void ssh_policy_notification(SshIkePMPhaseII pm_info,
                             Boolean authenticated,
                             SshIkeProtocolIdentifiers protocol_id,
                             unsigned char *spi,
                             size_t spi_size,
                             SshIkeNotifyMessageType notify_message_type,
                             unsigned char *notification_data,
                             size_t notification_data_size);

/* Request policy manager to process phase I status notification message. This
   status notification is always within the phase I packets, so the pm_info is
   for Phase I. Never authenticated, but may have been encrypted. */
void ssh_policy_phase_i_notification(SshIkePMPhaseI pm_info,
                                     Boolean encrypted,
                                     SshIkeProtocolIdentifiers protocol_id,
                                     unsigned char *spi,
                                     size_t spi_size,
                                     SshIkeNotifyMessageType
                                     notify_message_type,
                                     unsigned char *notification_data,
                                     size_t notification_data_size);

/* Request policy manager to process phase QM status notification message. This
   status notification is always within the quick mode packets, so the pm_info
   is for quick mode. Always authenticated and encrypted. */
void ssh_policy_phase_qm_notification(SshIkePMPhaseQm pm_info,
                                      SshIkeProtocolIdentifiers protocol_id,
                                      unsigned char *spi,
                                      size_t spi_size,
                                      SshIkeNotifyMessageType
                                      notify_message_type,
                                      unsigned char *notification_data,
                                      size_t notification_data_size);

/* Tell the policy manager that ISAKMP SA is now freed. */
void ssh_policy_isakmp_sa_freed(SshIkePMPhaseI pm_info);

/* Tell the policy manager that quick mode negotiation is now freed. */
void ssh_policy_qm_sa_freed(SshIkePMPhaseQm pm_info);

/* Tell the policy manager that other phase II negotiation is now freed. */
void ssh_policy_phase_ii_sa_freed(SshIkePMPhaseII pm_info);

/* Tell the policy manager that ISAKMP SA is now finished. This is always
   called before the ssh_policy_isakmp_sa_freed, and before notify_callback if
   it is registered. */
void ssh_policy_negotiation_done_isakmp(SshIkePMPhaseI pm_info,
                                        SshIkeNotifyMessageType code);

/* Tell the policy manager that quick mode negotiation is now finished. This is
   always called before ssh_policy_qm_sa_freed, and before notify_callback if
   it is registered. This is called after sa handler callback. */
void ssh_policy_negotiation_done_qm(SshIkePMPhaseQm pm_info,
                                    SshIkeNotifyMessageType code);

/* Tell the policy manager that other phase II negotiation is now freed. This
   is always called before ssh_policy_phase_ii_sa_freed, and before
   notify_callback if it is registered. */
void ssh_policy_negotiation_done_phase_ii(SshIkePMPhaseII pm_info,
                                          SshIkeNotifyMessageType code);

/* Private payload policy manager functions */
/* Following three functions are called while the packet is being decoded, to
   check if the private_payload_id is know. If this returns TRUE the payload is
   accepted, and processing continues, if this returns FALSE then the
   negotiation is aborted immediately with INVALID-PAYLOAD-TYPE
   notification. */
typedef Boolean (*SshIkePrivatePayloadPhaseICheck)(SshIkePMPhaseI pm_info,
                                                   int private_payload_id,
                                                   void
                                                   *private_payload_context);
/* Same for phase II negotiations */
typedef Boolean (*SshIkePrivatePayloadPhaseIICheck)(SshIkePMPhaseII pm_info,
                                                    int private_payload_id,
                                                    void
                                                    *private_payload_context);
/* Same for Quick Mode negotiations */
typedef Boolean (*SshIkePrivatePayloadPhaseQmCheck)(SshIkePMPhaseQm pm_info,
                                                    int private_payload_id,
                                                    void
                                                    *private_payload_context);

/* Following three functions are called to process private payloads. They do
   not return anything, and they can just ignore the payload if they want so.
   The packet_number is the number of packets from the beginning of the
   negotiation including this one we are now processing. I.e if this is first
   packet of the main mode (we receive it from the other end) then it is 1,
   the next packet sent by the responder to the initiator (first packet he
   receives) it is 2 etc. */
typedef void (*SshIkePrivatePayloadPhaseIIn)(SshIkePMPhaseI pm_info,
                                             int packet_number,
                                             int private_payload_id,
                                             unsigned char *data,
                                             size_t data_len,
                                             void *private_payload_context);
/* Same for phase II negotiations */
typedef void (*SshIkePrivatePayloadPhaseIIIn)(SshIkePMPhaseII pm_info,
                                              int packet_number,
                                              int private_payload_id,
                                              unsigned char *data,
                                              size_t data_len,
                                              void *private_payload_context);
/* Same for Quick Mode negotiations */
typedef void (*SshIkePrivatePayloadPhaseQmIn)(SshIkePMPhaseQm pm_info,
                                              int packet_number,
                                              int private_payload_id,
                                              unsigned char *data,
                                              size_t data_len,
                                              void *private_payload_context);

/* Callback function to call when policy manager wants to add new private
   payload to the packet. IF the private_payload_id is 0 then there will not be
   more private payloads, and the packet can be sent out. */
typedef void (*SshPolicyPrivatePayloadOutCB)(int private_payload_id,
                                             unsigned char *data,
                                             size_t data_len,
                                             void *policy_context);

/* Following three functions are called to add new private payloads. They can
   call the given callback function to add private payloads to the packet.
   When they are ready, and don't want to add any other private payloads they,
   must call the given callback and set the private_payload_id to zero.
   The packet_number is the number of packets from the beginning of the
   negotiation including this one we are now processing. I.e if this is first
   packet of the main mode (we receive it from the other end) then it is 1,
   the next packet sent by the responder to the initiator (first packet he
   receives) it is 2 etc.

   Returning callback duplicates the new data, and thus the original
   can be freed after the callback.
*/
typedef void (*SshIkePrivatePayloadPhaseIOut)(SshIkePMPhaseI pm_info,
                                              int packet_number,
                                              SshPolicyPrivatePayloadOutCB
                                              policy_callback,
                                              void *policy_context,
                                              void *private_payload_context);
/* Same for phase II negotiations */
typedef void (*SshIkePrivatePayloadPhaseIIOut)(SshIkePMPhaseII pm_info,
                                               int packet_number,
                                               SshPolicyPrivatePayloadOutCB
                                               policy_callback,
                                               void *policy_context,
                                               void *private_payload_context);
/* Same for Quick Mode negotiations */
typedef void (*SshIkePrivatePayloadPhaseQmOut)(SshIkePMPhaseQm pm_info,
                                               int packet_number,
                                               SshPolicyPrivatePayloadOutCB
                                               policy_callback,
                                               void *policy_context,
                                               void *private_payload_context);


#endif /* ISAKMP_POLICY_H */
