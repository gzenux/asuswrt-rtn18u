/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/
/**
         Datatypes and utility functions for Virtual Routing and Forwarding.
         This file contains data types and utility macros for VRF routing
         instance identifiers.
*/
#ifndef SSHVRF_H
#define SSHVRF_H

typedef const char * (*SshVrfNameCB)(int routing_instance_id, void * context);

typedef int (*SshVrfIdCB)(const char * routing_instance_name, void * context);

typedef int (*SshVrfIfaceCB)(SshUInt32 ifnum, void * context);

void ssh_vrf_register_cb(SshVrfNameCB name_cb, SshVrfIdCB id_cb,
                         SshVrfIfaceCB iface_cb, void *context);

const char *ssh_vrf_find_name_by_id(int routing_instance_id);

int ssh_vrf_find_id_by_name(const char *routing_instance_name);

int ssh_vrf_find_id_by_iface(SshUInt32 ifnum);

#endif /* SSHVRF_H */
