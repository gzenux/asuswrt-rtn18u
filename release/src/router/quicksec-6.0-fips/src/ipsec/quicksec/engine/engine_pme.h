/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal engine functions that implement the API between the policy
   manager and the engine. For each function in engine_pm_api.h the
   name of which begins with `ssh_pme_', here is a corresponding
   function with name beginning with `ssh_engine_pme_'.
*/

#ifndef ENGINE_PME_H
#define ENGINE_PME_H

#include "engine_pm_api.h"

void ssh_engine_pme_set_engine_params(SshEngine engine,
                                      const SshEngineParams pm_params);

void ssh_engine_pme_disable_policy_lookup(SshEngine engine,
                                          SshPmeStatusCB callback,
                                          void *context);

void ssh_engine_pme_enable_policy_lookup(SshEngine engine,
                                         SshPmeStatusCB callback,
                                         void *context);

void ssh_engine_pme_set_debug_level(SshEngine engine,
                                    const char *level_string);

void ssh_engine_pme_process_packet(SshEngine engine,
                                   SshUInt32 tunnel_id,
                                   SshInterceptorProtocol protocol,
                                   SshEngineIfnum ifnum,
                                   SshVriId routing_instance_id,
                                   SshUInt32 flags,
                                   SshUInt32 prev_transform_index,
                                   const unsigned char *data,
                                   size_t len);

#ifdef SSHDIST_IPSEC_NAT

void ssh_engine_pme_set_interface_nat(SshEngine engine,
                                      SshUInt32 ifnum,
                                      SshPmNatType type,
                                      SshPmNatFlags flags,
                                      const SshIpAddr host_nat_int_base,
                                      const SshIpAddr host_nat_ext_base,
                                      SshUInt32 host_nat_num_ips);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
void ssh_engine_pme_configure_internal_nat(SshEngine engine,
                                           const SshIpAddr first_ip,
                                           const SshIpAddr last_ip,
                                           SshPmeStatusCB callback,
                                           void *context);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

void ssh_engine_pme_create_transform(SshEngine engine,
                                     SshEngineTransform params,
                                     SshUInt32 life_seconds,
                                     SshUInt32 life_kilobytes,
                                     SshPmeIndexCB callback, void *context);

void ssh_engine_pme_delete_transform(SshEngine engine,
                                     SshUInt32 transform_index);

void
ssh_engine_pme_rekey_transform_inbound(SshEngine engine,
                                       SshUInt32 transform_index,
                                       const SshUInt32 new_in_spis[3],
                                       const unsigned char
                                       keymat_in[SSH_IPSEC_MAX_KEYMAT_LEN/2],
                                       SshUInt32 life_seconds,
                                       SshUInt32 life_kilobytes,
                                       SshUInt32 flags,
                                       SshPmeTransformCB callback,
                                       void *context);

void ssh_engine_pme_rekey_transform_outbound(SshEngine engine,
                                     SshUInt32 transform_index,
                                     const SshUInt32 new_out_spis[3],
                                     const unsigned char
                                     keymat_out[SSH_IPSEC_MAX_KEYMAT_LEN/2],
#ifdef SSH_IPSEC_TCPENCAP
                                     unsigned char *tcp_encaps_conn_spi,
#endif /* SSH_IPSEC_TCPENCAP */
                                     SshUInt32 flags,
                                     SshPmeStatusCB callback, void *context);

void ssh_engine_pme_transform_invalidate_old_inbound(SshEngine engine,
                                                    SshUInt32 transform_index,
                                                    SshUInt32 inbound_spi,
                                                    SshPmeTransformCB callback,
                                                    void *context);

#ifdef SSHDIST_L2TP
void ssh_engine_pme_update_transform_l2tp_info(SshEngine engine,
                                               SshUInt32 transform_index,
                                               SshUInt8 flags,
                                               SshUInt16 local_tunnel_id,
                                               SshUInt16 local_session_id,
                                               SshUInt16 remote_tunnel_id,
                                               SshUInt16 remote_session_id);
#endif /* SSHDIST_L2TP */

void ssh_engine_pme_add_rule(SshEngine engine, Boolean rekey,
                             const SshEnginePolicyRule rule,
                             SshPmeAddRuleCB callback, void *context);

void ssh_engine_pme_delete_rule(SshEngine engine,
                                SshUInt32 rule_index,
                                SshPmeDeleteCB callback, void *context);

void ssh_engine_pme_find_transform_rule(SshEngine engine,
                                        SshUInt32 tunnel_id,
                                        SshUInt32 ifnum,
                                        const SshIpAddr src_ip,
                                        const SshIpAddr dst_ip,
                                        SshUInt8 ipproto,
                                        SshUInt16 src_port,
                                        SshUInt16 dst_port,
                                        SshUInt32 impl_tunnel_id,
                                        SshUInt32 trd_index,
                                        SshUInt32 flags,
                                        SshPmeSAIndexCB callback,
                                        void *context);

void ssh_engine_pme_find_matching_transform_rule(
                                         SshEngine engine,
                                         const SshEnginePolicyRule rule,
                                         SshPmTransform transform,
                                         SshUInt32 cipher_key_size,
                                         const SshIpAddr peer_ip,
                                         const SshIpAddr local_ip,
                                         SshUInt16 local_port,
                                         SshUInt16 remote_port,
                                         const unsigned char *peer_id,
                                         SshUInt32 flags,
                                         SshPmeSAIndexCB callback,
                                         void *context);

void ssh_engine_pme_have_transform_with_peer(SshEngine engine,
                                             const SshIpAddr ip_addr,
                                             SshUInt16 remote_ike_port,
                                             SshPmeStatusCB callback,
                                             void *context);
void ssh_engine_pme_delete_by_spi(SshEngine engine, SshUInt32 transform_index,
                                  SshPmeTransformCB callback, void *context);

void ssh_engine_pme_delete_by_peer_handle(SshEngine engine,
                                          SshUInt32 peer_handle,
                                          SshPmeDeleteTransformCB callback,
                                          void *context);

void ssh_engine_pme_update_by_peer_handle(SshEngine engine,
                                          SshUInt32 peer_handle,
                                          Boolean enable_natt,
                                          SshVriId routing_instance_id,
                                          SshIpAddr local_ip,
                                          SshIpAddr remote_ip,
                                          SshUInt16 remote_port,
#ifdef SSH_IPSEC_TCPENCAP
                                          unsigned char *tcp_encaps_conn_spi,
#endif /* SSH_IPSEC_TCPENCAP */
                                          SshPmeStatusCB callback,
                                          void *context);

void ssh_engine_pme_get_rule(SshEngine engine, SshUInt32 rule_index,
                             SshPmeRuleCB callback, void *context);

void ssh_engine_pme_get_transform(SshEngine engine, SshUInt32 trd_index,
                                  SshPmeTransformCB callback, void *context);

void ssh_engine_pme_add_reference_to_rule(SshEngine engine,
                                          SshUInt32 rule_index,
                                          SshUInt32 transform_index,
                                          SshPmeStatusCB callback,
                                          void *context);

#ifdef SSH_IPSEC_STATISTICS

void ssh_engine_pme_get_global_stats(SshEngine engine,
                                     SshPmeGlobalStatsCB callback,
                                     void *context);

void ssh_engine_pme_get_next_flow_index(SshEngine engine,
                                        SshUInt32 flow_index,
                                        SshPmeIndexCB callback,
                                        void *context);

void ssh_engine_pme_get_flow_info(SshEngine engine, SshUInt32 flow_index,
                                  SshPmeFlowInfoCB callback, void *context);

void ssh_engine_pme_get_flow_stats(SshEngine engine, SshUInt32 flow_index,
                                   SshPmeFlowStatsCB callback, void *context);

void ssh_engine_pme_get_next_transform_index(SshEngine engine,
                                             SshUInt32 transform_index,
                                             SshPmeIndexCB callback,
                                             void *context);

void ssh_engine_pme_get_transform_stats(SshEngine engine,
                                        SshUInt32 transform_index,
                                        SshPmeTransformStatsCB callback,
                                        void *context);

void ssh_engine_pme_get_next_rule_index(SshEngine engine,
                                        SshUInt32 rule_index,
                                        SshPmeIndexCB callback,
                                        void *context);

void ssh_engine_pme_get_rule_stats(SshEngine engine, SshUInt32 rule_index,
                                   SshPmeRuleStatsCB callback, void *context);
#endif /** SSH_IPSEC_STATISTICS */

void ssh_engine_pme_route(SshEngine engine, SshUInt32 flags,
                          SshInterceptorRouteKey key,
                          SshPmeRouteCB callback, void *context);

void ssh_engine_pme_route_add(SshEngine engine,
                              SshInterceptorRouteKey key,
                              const SshIpAddr gateway,
                              SshUInt32 ifnum,
                              SshRoutePrecedence precedence,
                              SshUInt32 flags,
                              SshPmeRouteSuccessCB callback,
                              void *context);

void ssh_engine_pme_route_remove(SshEngine engine,
                                 SshInterceptorRouteKey key,
                                 const SshIpAddr gateway,
                                 SshUInt32 ifnum,
                                 SshRoutePrecedence precedence,
                                 SshUInt32 flags,
                                 SshPmeRouteSuccessCB callback,
                                 void *context);

#ifdef SSH_IPSEC_INTERNAL_ROUTING

void ssh_engine_pme_configure_route_clear(SshEngine engine);

void ssh_engine_pme_configure_route_add(SshEngine engine,
                                        const SshIpAddr dst_and_mask,
                                        const SshIpAddr next_hop,
                                        SshUInt32 ifnum,
                                        SshPmeStatusCB callback,
                                        void *context);
#endif /** SSH_IPSEC_INTERNAL_ROUTING */

void ssh_engine_pme_arp_add(SshEngine engine,
                            const SshIpAddr ip,
                            SshEngineIfnum ifnum,
                            const unsigned char *media_addr,
                            size_t media_addr_len,
                            SshUInt32 flags,
                            SshPmeStatusCB callback, void *context);

void ssh_engine_pme_arp_remove(SshEngine engine,
                               const SshIpAddr ip,
                               SshEngineIfnum ifnum);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

void
ssh_engine_pme_virtual_adapter_configure(SshEngine engine,
                                         SshUInt32 adapter_ifnum,
                                         SshVirtualAdapterState state,
                                         SshUInt32 num_addresses,
                                         SshIpAddr addresses,
                                         SshVirtualAdapterParams params,
                                         SshPmeVirtualAdapterStatusCB callback,
                                         void *context);

void
ssh_engine_pme_virtual_adapter_list(SshEngine engine,
                                    SshUInt32 adapter_ifnum,
                                    SshPmeVirtualAdapterStatusCB callback,
                                    void *context);

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

void ssh_engine_pme_flow_set_status(SshEngine engine,
                                    SshUInt32 flow_index,
                                    SshPmeFlowStatus flow_status,
                                    SshPmeStatusCB callback, void *context);

void ssh_engine_pme_redo_flows(SshEngine engine);

void
ssh_engine_pme_get_audit_events(SshEngine engine, SshUInt32 num_events,
                                SshPmeAuditCB audit_callback,
                                void *callback_context);



#ifdef SSH_IPSEC_TCPENCAP

void
ssh_engine_pme_tcp_encaps_create_ike_mapping(SshEngine engine,
                                           SshIpAddr local_addr,
                                           SshIpAddr peer_addr,
                                           SshUInt16 local_port,
                                           SshUInt16 peer_port,
                                           unsigned char *ike_initiator_cookie,
                                           SshUInt16 local_ike_port,
                                           SshUInt16 remote_ike_port,
                                           SshPmeIndexCB callback,
                                           void *callback_context);

void
ssh_engine_pme_tcp_encaps_get_ike_mapping(SshEngine engine,
                                          SshIpAddr local_addr,
                                          SshIpAddr peer_addr,
                                          unsigned char *ike_initiator_cookie,
                                          SshPmeIndexCB callback,
                                          void *callback_context);


void
ssh_engine_pme_tcp_encaps_update_ike_mapping(SshEngine engine,
                                       Boolean keep_address_matches,
                                       SshIpAddr local_addr,
                                       SshIpAddr peer_addr,
                                       unsigned char *ike_initiator_cookie,
                                       unsigned char *new_ike_initiator_cookie,
                                       SshPmeIndexCB callback,
                                       void *callback_context);
Boolean
ssh_engine_pme_tcp_encaps_add_configuration(SshEngine engine,
                                            SshIpAddr local_addr,
                                            SshUInt16 local_port,
                                            SshIpAddr peer_lo_addr,
                                            SshIpAddr peer_hi_addr,
                                            SshUInt16 peer_port,
                                            SshUInt16 local_ike_port,
                                            SshUInt16 remote_ike_port);

void
ssh_engine_pme_tcp_encaps_clear_configurations(SshEngine engine);

#endif /* SSH_IPSEC_TCPENCAP */

#endif /* ENGINE_PME_H */
