/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal policy manager functions that implement the API between
   the policy manager and the engine. For each function in
   engine_pm_api.h the name of which begins with `ssh_pmp_', here is a
   corresponding function with name beginning with `ssh_pm_pmp_'.
*/

#ifndef ENG_PM_API_PM_H
#define ENG_PM_API_PM_H

#include "engine_pm_api.h"

void ssh_pm_pmp_interface_change(SshPm pm,
                                 const struct SshIpInterfacesRec *ifs);

void ssh_pm_pmp_trigger(SshPm pm,
                        const SshEnginePolicyRule policy_rule,
                        SshUInt32 flow_index,
                        const SshIpAddr nat_src_ip,
                        SshUInt16 nat_src_port,
                        const SshIpAddr nat_dst_ip,
                        SshUInt16 nat_dst_port,
                        SshUInt32 tunnel_id,
                        SshVriId routing_instance_id,
                        SshUInt32 prev_transform_index,
                        SshUInt32 ifnum,
                        SshUInt32 flags, /** As in ssh_pme_process_packet */
                        unsigned char *data, size_t len);

Boolean ssh_pm_pmp_transform_event(SshPm pm, SshPmeFlowEvent event,
                                   SshUInt32 transform_index,
                                   const SshEngineTransform tr,
                                   SshUInt32 rule_index,
                                   const SshEnginePolicyRule rule,
                                   SshTime run_time);

void ssh_pm_pmp_flow_free_notification(SshPm pm, SshUInt32 flow_index);

#endif /* ENG_PM_API_PM_H */
