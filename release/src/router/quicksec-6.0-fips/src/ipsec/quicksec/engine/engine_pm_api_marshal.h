/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Definitions for the `engine_pm_api.h' marshal code.
*/

#ifndef ENGINE_PM_API_MARSHAL_H
#define ENGINE_PM_API_MARSHAL_H

/************************** Types and definitions ***************************/

/* Version numbers of the RPC protocol between engine and PM. */
#define SSH_PM_API_RPC_VERSION_MAJOR 2
#define SSH_PM_API_RPC_VERSION_MINOR 0

typedef enum
{
  /* Calls from engine to policy manager.  The values are still a bit
     strange since the interceptors are compiled agains the old engine
     definitions and they use old version numbers for DEBUG and
     WARNING messages. */
  SSH_EPA_VERSION,
  SSH_EPA_INTERFACE,
  SSH_EPA_DEBUG =                           6,
  SSH_EPA_WARNING =                         7,
  SSH_EPA_STATUS_CB =                       8,
  SSH_EPA_INDEX_CB =                        9,
  SSH_EPA_ADD_RULE_CB =                    10,
  SSH_EPA_INIT_ERROR =                     11,

  SSH_EPA_SA_INDEX_CB =                    21,
  SSH_EPA_GLOBAL_STATS_CB =                22,
  SSH_EPA_FLOW_INFO_CB =                   23,
  SSH_EPA_FLOW_STATS_CB =                  24,
  SSH_EPA_RULE_STATS_CB =                  25,
  SSH_EPA_TRANSFORM_STATS_CB =             26,
  SSH_EPA_DELETE_CB =                      27,
  SSH_EPA_DELETE_TRANSFORM_CB =            28,
  SSH_EPA_GET_RULE_CB =                    29,
  SSH_EPA_GET_TRANSFORM_CB =               30,
  SSH_EPA_ROUTE_CB =                       31,
  SSH_EPA_ROUTE_SUCCESS_CB =               32,

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  SSH_EPA_VIRTUAL_ADAPTER_STATUS_CB =      44,
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
  SSH_EPA_CONTROL_REPLY_CB =               45,
  SSH_EPA_TRIGGER =                        46,
  SSH_EPA_TRANSFORM_EVENT =                47,
  SSH_EPA_AUDIT_ENGINE_EVENT =             48,
  SSH_EPA_FLOW_FREE =                      49,
  SSH_EPA_AUDIT_POLL_REQUEST =             51,





  /* Calls from policy manager to engine. */

  SSH_PEA_ENGINE_INIT =                    87,
  SSH_PEA_ENGINE_SALT =                    88,
  SSH_PEA_POLICY_LOOKUP =                  89,
  SSH_PEA_DEBUG =                          90,
  SSH_PEA_SET_PARAMS =                     91,
  SSH_PEA_PROCESS_PACKET =                 92,
  SSH_PEA_SET_INTERFACE_NAT =              93,
  SSH_PEA_SET_INTERFACE_VPN_NAT =          94,
  SSH_PEA_CONFIGURE_INTERNAL_NAT =         95,
  SSH_PEA_CREATE_APPGW_MAPPINGS =          96,

  SSH_PEA_CREATE_TRANSFORM =              107,
  SSH_PEA_DELETE_TRANSFORM =              108,
  SSH_PEA_REKEY_INBOUND =                 109,
  SSH_PEA_REKEY_OUTBOUND =                110,
  SSH_PEA_REKEY_INVALIDATE_OLD_INBOUND =  111,
#ifdef SSHDIST_L2TP
  SSH_PEA_UPDATE_L2TP =                   112,
#endif /* SSHDIST_L2TP */
  SSH_PEA_DELETE_BY_SPI =                 113,

  SSH_PEA_ADD_RULE =                      124,
  SSH_PEA_DELETE_RULE =                   125,
  SSH_PEA_FIND_TRANSFORM_RULE =           126,
  SSH_PEA_FIND_MATCHING_TRANSFORM_RULE =  127,
  SSH_PEA_HAVE_TRANSFORM_WITH_PEER =      128,

  SSH_PEA_DELETE_BY_PEER_HANDLE =         130,

  SSH_PEA_GET_RULE =                      133,
  SSH_PEA_GET_TRANSFORM =                 134,
  SSH_PEA_ADD_REFERENCE_TO_RULE =         135,

  SSH_PEA_GET_GLOBAL_STATS =              156,
  SSH_PEA_GET_NEXT_FLOW_INDEX =           157,
  SSH_PEA_GET_FLOW_INFO =                 158,
  SSH_PEA_GET_FLOW_STATS =                159,
  SSH_PEA_GET_NEXT_TRANSFORM_INDEX =      160,
  SSH_PEA_GET_TRANSFORM_STATS =           161,
  SSH_PEA_GET_NEXT_RULE_INDEX =           162,
  SSH_PEA_GET_RULE_STATS =                163,

  SSH_PEA_ARP_ADD =                       174,
  SSH_PEA_ARP_REMOVE =                    175,
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  SSH_PEA_VIRTUAL_ADAPTER_CONFIGURE =     176,
  SSH_PEA_VIRTUAL_ADAPTER_LIST =          177,
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  SSH_PEA_ROUTE =                         189,
  SSH_PEA_ROUTE_ADD =                     190,
  SSH_PEA_ROUTE_REMOVE =                  191,
  SSH_PEA_CONFIGURE_ROUTE_CLEAR =         192,
  SSH_PEA_CONFIGURE_ROUTE_ADD =           193,
  SSH_PEA_FLOW_SET_STATUS =               194,

#ifdef SSH_IPSEC_TCPENCAP
  SSH_PEA_TCP_ENCAPS_ADD_CONFIG =         212,
  SSH_PEA_TCP_ENCAPS_CLEAR_CONFIG =       213,
  SSH_PEA_TCP_ENCAPS_CREATE_IKE_MAPPING = 214,
  SSH_PEA_TCP_ENCAPS_GET_IKE_MAPPING =    215,
  SSH_PEA_TCP_ENCAPS_UPDATE_IKE_MAPPING = 216,
#endif /* SSH_IPSEC_TCPENCAP */

  SSH_PEA_GET_AUDIT_EVENTS =              217,





  /* Re-route and re-policy flows. */
  SSH_PEA_REDO_FLOWS =                    225,

  SSH_PEA_UPDATE_BY_PEER_HANDLE =         227

} SshEnginePmApiCallType;


/***************** Help function for encoding and decoding ******************/

/* Create a bit mask of configurable build options. This fills in
   `build_flags' with a bit set for each enabled build option. */
void ssh_pm_api_build_flags(SshUInt32 *build_flags);

/* Create a bit mask of supported PM API call types. The buffer must have
   enough bits to accomodate all above PM API call types. If the buffer
   is too short then this returns FALSE, otherwise this fills in `buf'
   with a bit set for each supported PM API call type. */
Boolean ssh_pm_api_supported_api_calls(unsigned char *buf, size_t buf_size);

/* Create a bit mask of supported transforms. This fills in `transform' with
   a bit set for each supported transform. */
void ssh_pm_api_supported_transforms(SshPmTransform *transform);

/* Encode policy rule `rule' into internal linearized format.  If the
   operation is successful, the function returns the length of the
   encoded blob and a ssh_malloc()ated blob in `data_return'.  if the
   operation fails, the function returns 0 and sets `data_return' to
   NULL. */
size_t ssh_pm_api_encode_policy_rule(unsigned char **data_return,
                                     const SshEnginePolicyRule rule);

/* Decode an encoded policy rule `data', `data_len' into policy rule
   structure `rule'.  Then function returns TRUE if the operation was
   successful and FALSE otherwise. */
Boolean ssh_pm_api_decode_policy_rule(const unsigned char *data,
                                      size_t data_len,
                                      SshEnginePolicyRule rule);

/* Encode 'num_events' audit events 'events' into a internal linearized
   format, 'events' points to an array of 'num_events'
   SshEngineAuditEventStruct objects. If the operation is successful,
   the function returns the length of the encoded blob and a
   ssh_malloc()ated blob in `data_return'. If the operation fails,
   the function returns 0 and sets `data_return' to NULL. */
size_t
ssh_pm_api_encode_engine_audit_events(unsigned char **data_return,
                                      SshUInt32 num_events,
                                      const SshEngineAuditEvent events);

/* Decode 'num_events' encoded audit events `data', `data_len' into an
   array of 'num_events' SshEngineAuditEventStruct structures 'events'.
   Then function returns TRUE if the operation was successful and
   FALSE otherwise. */
Boolean
ssh_pm_api_decode_engine_audit_events(const unsigned char *data,
                                      size_t data_len,
                                      SshUInt32 num_events,
                                      SshEngineAuditEvent events);

/* Encode transform data `trd' into internal linearized format.  If
   the operation is successful, the function returns the length of the
   encoded blob and a ssh_malloc()ated blob in `data_return'.  If the
   encoding fails, the function returns 0 and sets `data_return' to
   NULL. */
size_t ssh_pm_api_encode_transform_data(unsigned char **data_return,
                                        const SshEngineTransform tr);


/* Decode an encoded transform data `data', `data_len' into transform
   data structure `trd'.  Then function returns TRUE if the operation
   was successful and FALSE otherwise. */
Boolean ssh_pm_api_decode_transform_data(const unsigned char *data,
                                         size_t data_len,
                                         SshEngineTransform tr);

/* Encode an SshUInt64 value `value' into the buffer `buf'. */
void ssh_pm_api_encode_uint64(unsigned char buf[8], SshUInt64 value);

/* Decode an SshUInt64 value from the buffer `buf'. */
SshUInt64 ssh_pm_api_decode_uint64(unsigned char buf[8]);

void ssh_pm_api_encode_time(unsigned char *buf, size_t buf_len,
                            SshTime time);
SshTime ssh_pm_api_decode_time(unsigned char *buf, size_t buf_len);

#ifndef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

#define SSH_ENGINE_PM_HANDLER_DEFINE(what)                                    \
Boolean ssh_engine_pm_handler_ ## what(SshEngine engine,                      \
                                       const unsigned char *data,             \
                                       size_t data_len)

#define SSH_ENGINE_PM_HANDLER(what)                             \
  if (!ssh_engine_pm_handler_ ## what(engine, data, data_len))  \
     goto format_error;

/* We do not have unified address space.  Implement kind of RPC interface
   between the engine in the kernel and the policy manager in user space. */

/* Convert SshUInt32 value `value' into a `void *' pointer. 'ptr' */
#define SSH_UINT32_TO_PTR(value)   ((void *)(size_t)(value))

/* Convert `void *' pointer `pointer' into SshUInt32 value. */
#define SSH_PTR_TO_UINT32(pointer)  ((SshUInt32)(size_t)(pointer))
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

#endif /* not ENGINE_PM_API_MARSHAL_H */
