/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/
/**
 Utility functions for Virtual Routing and Forwarding.

*/

#include "sshincludes.h"
#include "sshvrf.h"

struct SshVrfInstance {
  SshVrfNameCB name_cb;
  SshVrfIdCB id_cb;
  SshVrfIfaceCB iface_cb;
  void *context;
};

static struct SshVrfInstance vrf_instance;

void ssh_vrf_register_cb(SshVrfNameCB name_cb, SshVrfIdCB id_cb,
                         SshVrfIfaceCB iface_cb, void *context)
{
  vrf_instance.name_cb = name_cb;
  vrf_instance.id_cb = id_cb;
  vrf_instance.iface_cb = iface_cb;
  vrf_instance.context = context;
}

const char *ssh_vrf_find_name_by_id(int routing_instance_id)
{
  SshVrfNameCB callback = vrf_instance.name_cb;

  const char *vrf_name = (*callback)(routing_instance_id,
                                     vrf_instance.context);

  return vrf_name;
}

int ssh_vrf_find_id_by_name(const char *routing_instance_name)
{
  SshVrfIdCB callback = vrf_instance.id_cb;
  int routing_instance_id = (*callback)(routing_instance_name,
                                        vrf_instance.context);

  return routing_instance_id;
}

int ssh_vrf_find_id_by_iface(SshUInt32 ifnum)
{
  SshVrfIfaceCB callback = vrf_instance.iface_cb;
  int routing_instance_id = (*callback)(ifnum, vrf_instance.context);

  return routing_instance_id;
}
