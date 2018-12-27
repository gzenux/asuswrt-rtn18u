/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface functions to Security Association Database (SAD).
*/

#ifndef SSH_SAD_H
#define SSH_SAD_H

#include "sshadt.h"
#include "sshadt_list.h"
#include "sshikev2-payloads.h"

typedef struct SshSADHandleRec *SshSADHandle;

#include "sshikev2-payloads.h"
#include "sshikev2-sad.h"
#include "sshikev2-pad.h"
#include "sshikev2-spd.h"

/** SAD interface structure. */
typedef struct SshSADInterfaceRec {
  /** SAD (Security Association Database) function. */
  SshIkev2SadIkeSaAllocate ike_sa_allocate;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIPsecSpiAllocate ipsec_spi_allocate;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIkeSaDelete ike_sa_delete;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIPsecSpiDelete ipsec_spi_delete;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIPsecSpiDeleteReceived ipsec_spi_delete_received;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIkeSaRekey ike_sa_rekey;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIkeSaGet ike_sa_get;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIkeSaTakeRef ike_sa_take_ref;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIkeSaFreeRef ike_sa_free_ref;
  /** SAD (Security Association Database) function. */
  SshIkev2SadExchangeDataAlloc exchange_data_alloc;
  /** SAD (Security Association Database) function. */
  SshIkev2SadExchangeDataFree exchange_data_free;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIkeSaEnumerate ike_enumerate;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIPsecSaInstall ipsec_sa_install;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIPsecSaUpdate ipsec_sa_update;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIkeSaDone ike_sa_done;
  /** SAD (Security Association Database) function. */
  SshIkev2SadIPsecSaDone ipsec_sa_done;

  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadNewConnection new_connect;
#ifdef SSHDIST_IKE_REDIRECT
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadIkeRedirect ike_redirect;
#endif /* SSHDIST_IKE_REDIRECT */
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadID id;
#ifdef SSHDIST_IKE_CERT_AUTH
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadGetCAs get_cas;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadGetCertificates get_certificates;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadNewCertificateRequest new_certificate_request;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadPublicKey public_key;
#endif /* SSHDIST_IKE_CERT_AUTH */
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadSharedKey shared_key;
#ifdef SSHDIST_IKE_CERT_AUTH
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadNewCertificate new_certificate;
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadEapReceived eap_received;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadEapRequest eap_request;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadEapKey eap_shared_key;
#endif /* SSHDIST_IKE_EAP_AUTH */
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadConfReceived conf_received;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadConfRequest conf_request;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadVendorId vendor_id;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadVendorIDRequest vendor_id_request;
#ifdef SSHDIST_IKE_MOBIKE
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadGetAddressPair get_address_pair;
  /** PAD (Peer Authorization Database) function. */
  SshIkev2PadGetAdditionalAddressList get_additional_address_list;
#endif /* SSHDIST_IKE_MOBIKE */

  /** SPD (Security Policy Database) function. */
  SshIkev2SpdFillIkeSa fill_ike_sa;
  /** SPD (Security Policy Database) function. */
  SshIkev2SpdFillIPsecSa fill_ipsec_sa;
  /** SPD (Security Policy Database) function. */
  SshIkev2SpdSelectIkeSa select_ike_sa;
  /** SPD (Security Policy Database) function. */
  SshIkev2SpdSelectIPsecSa select_ipsec_sa;
  /** SPD (Security Policy Database) function. */
  SshIkev2SpdNarrow narrow;
  /** SPD (Security Policy Database) function. */
  SshIkev2SpdNotifyRequest notify_request;
  /** SPD (Security Policy Database) function. */
  SshIkev2SpdNotifyReceived notify_received;
  /** SPD (Security Policy Database) function. */
  SshIkev2SpdResponderExchangeDone responder_exchange_done;
#ifdef SSHDIST_IKE_XAUTH
  /** SPD (Security Policy Database) function. */
  SshIkev2FbXauth xauth_request;
#endif /* SSHDIST_IKE_XAUTH */
} *SshSADInterface, SshSADInterfaceStruct;

#endif /* SSH_SAD_H */
