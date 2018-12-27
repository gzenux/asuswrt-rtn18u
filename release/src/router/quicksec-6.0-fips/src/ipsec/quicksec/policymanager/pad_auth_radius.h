/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Extended authentication using RADIUS.
*/

#ifndef PM_AUTH_RADIUS_H
#define PM_AUTH_RADIUS_H

#include "quicksec_pm_low.h"
#include "sshradius.h"

/* ************************* Types and definitions ***************************/

/** A RADIUS extended authentication object. */
typedef struct SshPmAuthRadiusRec *SshPmAuthRadius;


/* ***************** Creating RADIUS authentication objects ******************/

/** Create a RADIUS extended authentication object.

    The objects, pointed by arguments 'client' and 'servers' must
    remain valid as long as the created AUTH object is valid.

    @param client
    Specifies a RADIUS client that is used in the authentication.

    @param servers
    Specifies the RADIUS servers which are used in the authentication.

    */
SshPmAuthRadius ssh_pm_auth_radius_create(SshRadiusClient client,
                                          SshRadiusClientServerInfo servers);

/** Destroy authentication object 'auth_radius'.

    @param auth_radius
    The RADIUS authentication object to be destroyed.

*/
void ssh_pm_auth_radius_destroy(SshPmAuthRadius auth_radius);


/* ************ RADIUS extended authentication for IPSec tunnels *************/

/** Use RADIUS for extended authentication with the Policy Manager
    'pm'.

    This module does not implement other (L2TP/PPP) authentication.
    The L2TP/PPP RADIUS integration is handled separately at the
    native L2TP code.

    @param pm
    The Policy Manager to be used for the extended RADIUS
    authentication.

    @param auth_radius
    Specifies the RADIUS authentication object that is used for the
    authentication.  It must remain valid as long as the callback is
    set for the Policy Manager 'pm'.

    */
void ssh_pm_set_auth_radius(SshPm pm, SshPmAuthRadius auth_radius);


/** Get client information.

    @param auth_radius
    The RADIUS authentication object.

    @param client
    Specifies a RADIUS client that is used in the authentication.

    @param servers
    Specifies the RADIUS servers which are used in the authentication.

*/

void
ssh_pm_auth_radius_get_clientinfo(SshPmAuthRadius auth_radius,
                                  SshRadiusClient *client,
                                  SshRadiusClientServerInfo *servers);

#endif /* not PM_AUTH_RADIUS_H */
