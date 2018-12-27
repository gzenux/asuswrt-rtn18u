/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Extended authentication using RADIUS.
*/

#include "sshincludes.h"

#ifdef SSHDIST_RADIUS

#include "sshfsm.h"
#include "pad_auth_radius.h"




/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmAuthRadius"


/* A RADIUS authentication object. */
struct SshPmAuthRadiusRec
{
  /* The radius client instance. */
  SshRadiusClient client;

  /* The radius servers. */
  SshRadiusClientServerInfo servers;

  /* SSH FSM instance. */
  SshFSMStruct fsm;
};

typedef struct SshPmAuthRadiusRec SshPmAuthRadiusStruct;


/***************************** Public functions *****************************/

SshPmAuthRadius
ssh_pm_auth_radius_create(SshRadiusClient client,
                          SshRadiusClientServerInfo servers)
{
  SshPmAuthRadius auth_radius;

  auth_radius = ssh_calloc(1, sizeof(*auth_radius));
  if (auth_radius == NULL)
    return NULL;

  auth_radius->client = client;
  auth_radius->servers = servers;

  ssh_fsm_init(&auth_radius->fsm, auth_radius);

  return auth_radius;
}


void
ssh_pm_auth_radius_get_clientinfo(SshPmAuthRadius auth_radius,
                                  SshRadiusClient *client,
                                  SshRadiusClientServerInfo *servers)
{
  *client = auth_radius->client;
  *servers = auth_radius->servers;
}

void
ssh_pm_auth_radius_destroy(SshPmAuthRadius auth_radius)
{
  if (auth_radius == NULL)
    return;

  ssh_fsm_uninit(&auth_radius->fsm);

  ssh_free(auth_radius);
}


void
ssh_pm_set_auth_radius(SshPm pm, SshPmAuthRadius auth_radius)
{
  ;
}
#endif /* SSHDIST_RADIUS */
