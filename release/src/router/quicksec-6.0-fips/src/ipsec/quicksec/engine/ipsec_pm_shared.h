/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Shared definitions for IPsec between QuickSec Engine and Policy Manager.
*/

#ifndef IPSEC_PM_SHARED_H
#define IPSEC_PM_SHARED_H

#include "core_pm_shared.h"

/* ********************* Flag bits for IPSec tunnels ************************/

/*  These bit masks define additional behavior of the initiator and
    responder for IPSec tunnels.  The SSH_PM_T_* values are common to
    initiator and responder; the SSH_PM_TR_* values affect the
    responder only, and the SSH_PM_TI_* flags affect the initiator
    only.  Note that a gateway may act as both an initiator and as a
    responder for a tunnel, and thus none of the flags may overlap. */

/*  Flags common to both initiator and responder. */
#define SSH_PM_T_PER_HOST_SA            0x00000001 /** Use per-host SAs. */
#define SSH_PM_T_PER_PORT_SA            0x00000002 /** Use per-port SAs. */
#define SSH_PM_T_TRANSPORT_MODE         0x00000004  /** As initiator propose
                                                        transport mode,
                                                        as responder allow
                                                        transport mode. */
#define SSH_PM_T_DISABLE_ANTI_REPLAY    0x00000008 /** Disable anti-replay. */
#define SSH_PM_T_PORT_NAT               0x00000010 /** NAT decapsulated pkts.*/
#define SSH_PM_T_NO_CERT_CHAINS         0x00000020 /** Do not send chains. */
#define SSH_PM_T_SET_EXTENSION_SELECTOR 0x00000040 /** Set extension selector*/
#ifdef SSHDIST_IPSEC_MOBIKE
#define SSH_PM_T_MOBIKE                 0x00000080 /** Enable MOBIKE. */
#endif /* SSHDIST_IPSEC_MOBIKE */
#define SSH_PM_T_NO_NATS_ALLOWED        0x00000100 /** Fail negotiation if NAT
                                                       is detected. */
#define SSH_PM_T_TCPENCAP               0x00000200 /** Enable IPsec over TCP.*/
#define SSH_PM_T_DISABLE_NATT           0x00000400 /** Do not initiate NAT-T
                                                       or reply NAT-T. */
#define SSH_PM_T_XAUTH_METHODS          0x00000800 /** IKEv1 Xauth methods.*/

/* Flags that affect the initiator only. */
#define SSH_PM_TI_DONT_INITIATE         0x00001000 /** Don't initiate IKE SA.*/
#define SSH_PM_TI_DELAYED_OPEN          0x00002000 /** Open on first packet.*/
#ifdef SSHDIST_IKEV1
#define SSH_PM_TI_AGGRESSIVE_MODE       0x00004000 /** Aggressive mode for
                                                       PSK. */
#endif /* SSHDIST_IKEV1 */
#define SSH_PM_TI_NO_TRIGGER_PACKET     0x00008000 /** No trigger packet sent.
                                                    */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#define SSH_PM_TI_CFGMODE               0x00010000 /** Use IKE config mode. */
#define SSH_PM_TI_L2TP                  0x00020000 /** L2TP encapsulate. */

#define SSH_PM_TI_INTERFACE_TRIGGER     0x00040000 /** Virtual interface
                                                       trigger. */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
#define SSH_PM_TI_START_WITH_NATT       0x00080000 /** Start IKE with NAT-T. */
/* For backwards compatibility */
#define SSH_PM_TI_DONT_INITIATE_NATT    SSH_PM_T_DISABLE_NATT

/* Flags that affect the responder only. */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#define SSH_PM_TR_ALLOW_CFGMODE         0x00100000 /** Allow config mode. */
#define SSH_PM_TR_ALLOW_L2TP            0x00200000 /** Allow L2TP. */
#define SSH_PM_TR_REQUIRE_CFGMODE       0x00400000 /** Require config mode for
                                                       IKEv2 SAs. */
#define SSH_PM_TR_PROXY_ARP             0x00800000 /** Proxy ARP for clients.*/
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#define SSH_PM_TR_ENABLE_OUT_SA_SEL     0x01000000 /** Enable out SA selectors.
                                                    */
#ifdef SSHDIST_IKE_EAP_AUTH
#define SSH_PM_TR_EAP_REQUEST_ID        0x02000000 /** EAP, request client ID.
                                                    */
#define SSH_PM_T_EAP_ONLY_AUTH          0x04000000 /** EAP only authentication
                                                    */
#endif /* SSHDIST_IKE_EAP_AUTH */

#endif /* IPSEC_PM_SHARED_H */
