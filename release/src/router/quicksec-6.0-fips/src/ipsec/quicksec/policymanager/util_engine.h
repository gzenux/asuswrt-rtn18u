/**
   @copyright
   Copyright (c) 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header for utility functions that are engine dependent or are used by
   engine dependent fucntions..
*/


#ifndef UTIL_ENGINE_H
#define UTIL_ENGINE_H


void ssh_pm_audit_engine_event(SshPm pm, SshEngineAuditEvent event);
void ssh_pm_audit_get_engine_events_timer(void *context);
void
pm_freelist_index_put(SshPmFreelistItem *list, SshPmFreelistItem item,
                          size_t item_size, SshUInt32 *index);

#endif /* UTIL_ENGINE_H */
