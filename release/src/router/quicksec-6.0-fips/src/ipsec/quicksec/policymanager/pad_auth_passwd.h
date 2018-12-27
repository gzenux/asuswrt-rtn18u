/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A simple user-name password list for authentication.
*/

#ifndef PM_AUTH_PASSWD_H
#define PM_AUTH_PASSWD_H

#include "quicksec_pm_low.h"

/* ************************* Types and definitions ***************************/

/** A password list extended authentication object. */
typedef struct SshPmAuthPasswdRec *SshPmAuthPasswd;


/* *********************** Creating password objects *************************/

/** Create a password extended authentication object. */
SshPmAuthPasswd ssh_pm_auth_passwd_create(void);

/** Destroy the password extended authentication object 'auth_passwd'. */
void ssh_pm_auth_passwd_destroy(SshPmAuthPasswd auth_passwd);

/** Add the username 'user_name' and password 'password' to the
    password AUTH object 'auth_passwd'.

    @param auth_passwd
    Password AUTH object.

    @param user_name
    User name.

    @param user_name_len
    The length of user_name.

    @param password
    Password.

    @param password_len
    Length of password.

    @return
    The function returns TRUE if the new entry could be used,
    and FALSE otherwise.

    */
Boolean ssh_pm_auth_passwd_add(SshPmAuthPasswd auth_passwd,
                               const unsigned char *user_name,
                               size_t user_name_len,
                               const unsigned char *password,
                               size_t password_len);

/** Remove the username 'user_name' from the password AUTH object
    'auth_passwd'.

    @param auth_passwd
    Password AUTH object.

    @param user_name
    The username to be removed.

    @param user_name_len
    The length of user_name.

    @return
    The function returns TRUE if the name was removed,
    and FALSE otherwise.

    */
Boolean ssh_pm_auth_passwd_remove(SshPmAuthPasswd auth_passwd,
                                  const unsigned char *user_name,
                                  size_t user_name_len);

/* ********************** Password list authentication ***********************/

/** Use the password list 'auth_passwd' for extended (and L2TP)
    authentication with the policy manager 'pm'.  The password object
    'auth_passwd' must remain valid as long as the callback is set for
    the policy manager 'pm'.

    @param pm
    Policy Manager.

    @param auth_password
    Password list.

    @param client
    Client.

    @param servers
    Servers.

    */
void ssh_pm_set_auth_passwd(SshPm pm, SshPmAuthPasswd auth_passwd);

#ifdef SSHDIST_RADIUS
void ssh_pm_set_auth_passwd_radius(SshPm pm,
                                   SshPmAuthPasswd auth_passwd,
                                   SshRadiusClient client,
                                   SshRadiusClientServerInfo servers);
#endif /* SSHDIST_RADIUS */
#endif /* not PM_AUTH_PASSWD_H */
