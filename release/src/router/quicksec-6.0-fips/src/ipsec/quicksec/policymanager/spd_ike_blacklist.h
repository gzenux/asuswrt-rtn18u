/**
   @copyright
   Copyright (c) 2011 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Public header for the QuickSec Blacklisting functionality.
*/

#ifndef SPD_IKE_BLACKLIST_H
#define SPD_IKE_BLACKLIST_H

/*
  The QuickSec Blacklisting functionality can be used to prevent remote IKE
  peers from connecting to the system. This is done by comparing the IKE ID of
  the remote IKE peer to the IKE blacklist. User can freely select blacklisted
  IKE IDs which can be set to system by using proper API function. Internally
  all blacklisted IKE IDs are stored to the blacklist database which is
  consulted every time an IKE negotiation is started and when remote IKE ID is
  first seen during negotiation. If IKE ID is found proper error notify message
  will be send to other end and IKE negotiation will be finished. If IKE ID is
  not found IKE negotiation continues normally. In current implementation
  blacklist check is only done in responder side.

  -- Configuration --

  IKE IDs can be set to the blacklist database by using ssh_pm_blacklist_set()
  function. New IKE IDs in database will be activated when ssh_pm_commit()
  function is called. Normal usage cases of ssh_pm_blacklist_set() function
  are shown below.

  1) Setting and activating new blacklist configuration.

     ssh_pm_blacklist_set(pm, config, config_len);
     ssh_pm_commit(pm, callback, context);

  2) Setting and activating empty blacklist configuration.

     ssh_pm_blacklist_set(pm, NULL, 0);
     ssh_pm_commit(pm, callback, context);

  3) Error case if blacklist configuration has to be aborted.

     ssh_pm_blacklist_set(pm, config, config_len);
     ssh_pm_abort(pm);


  Blacklist configuration data is passed to ssh_pm_blacklist_set() function
  via config argument. It contains list of IKE IDs which should be blocked
  from the system. Each individual IKE ID is stored to own line containing
  type and data information separated with tabulator(s) or space(s).

  In default string format data is surrounded with quotation marks. Currently
  the following types are supported in this format.

    * ip:     IP address (IPv4 or IPv6)
    * fqdn:   fully qualified domain name
    * email:  rfc822 identity
    * dn:     distinguished name
    * key-id: key id

  It is also possible to represent data in hexadecimal string format. In
  this case data should start with "0x" followed by data in hexadecimal
  format. The following types are supported in hexadecimal representation.

    * dn:     distinguished name
    * key-id: key id

  Configuration data may also contain commenting lines. Text comments can be
  inserted by adding # character at the beginning of the line followed by
  commenting text. It is also possible to add empty lines which may contain
  tabulator(s) or space(s).

  Example of the simple configuration data is shown below.

  # AP: IP
  ip     "10.2.3.4"

  # AP: FQDN
  fqdn   "ipsec.com"

  # AP: EMAIL
  email  "a@ipsec.com"

  # AP: KEY-ID
  key-id "1234567890"

  #AP: KEY-ID HEX
  key-id 0x1234567890


  -- Statistics --

  Statistics can be fetched by calling ssh_pm_blacklist_get_stats() function.
  This function internally calls callback function that has to be implemented
  by user. Statistics are gathered if SSH_IPSEC_STATISTICS is defined. Usage
  examples are shown below.

  1) Get statistics when statistics collection is enabled

  ssh_pm_blacklist_get_stats(pm, callback, context);
     |
     +---->  callback(pm, blacklist_stats, context);

  2) Get statistics when statistics collection is disabled

  ssh_pm_blacklist_get_stats(pm, callback, context);
     |
     +---->  callback(pm, NULL, context);


  -- Deleting IKE and IPsec SA --

  It is possible to delete all IKE and IPsec SA associated with a particular
  remote IKE ID. Deletion can be executed by using function
  ssh_pm_blacklist_delete_sas_by_ike_id(). IKE ID is passed via ike_id
  argument by using same syntax than in ssh_pm_blacklist_set() function case
  explained above. Anyhow, only one configuration line containing one IKE ID
  should be given in this case. Usage example is shown below.

  ssh_pm_blacklist_delete_sas_by_ike_id(pm, "key-id 0x1234567890", 19);

  Please note that function ssh_pm_blacklist_delete_sas_by_ike_id() is distinct
  from the blacklist check and the IKE ID's given as argument are not compared
  against the blacklist database.


  -- Dumping content of the blacklist database --

  Content of the blacklist database can be dumped by using function
  ssh_pm_blacklist_foreach_ike_id(). Function will iterate through the database
  and call callback function for each individual IKE ID entry found from
  database. When iteration is done callback function is called once by giving
  NULL value in info argument. This informs that iteration is completed. Usage
  example is shown below. In this example we assume that configuration data
  stored to blacklist database is same than in configuration section above.

  ssh_pm_blacklist_foreach_ike_id(pm, callback, context);
     |
     +-----> callback(pm, { ip, "10.2.3.4" }, context);
     +-----> callback(pm, { fqdn, "ipsec.com" }, context);
     +-----> callback(pm, { email, "a@ipsec.com" }, context);
     +-----> callback(pm, { key-id, "1234567890" }, context);
     +-----> callback(pm, { key-id, 0x1234567890 }, context);
     +-----> callback(pm, NULL, context);


  The second way to dump content of the blacklist database is to use function
  ssh_pm_blacklist_dump(). This function returns database content in one
  continuous buffer that is dynamically allocated. Content of buffer uses same
  syntax than in ssh_pm_blacklist_set() function case explained above. Anyhow,
  possible commenting lines are not returned even if original configuration
  data may contain such lines and configuration lines may be shown in different
  order. Usage example is shown below.

  ssh_pm_blacklist_dump(pm, &content, &len);
  ...
  ssh_free(content);

  Example of content is shown below. In here we assume that configuration data
  stored to blacklist database is same than in configuration section above.

  ip     "10.2.3.4"
  fqdn   "ipsec.com"
  email  "a@ipsec.com"
  key-id "1234567890"
  key-id 0x1234567890


  -- Converting error code to string --

  It is possible to convert the blacklist error code to string that describes
  the error. This can be done by using ssh_pm_blacklist_error_to_string()
  function. Usage example is shown below.

  err = ssh_pm_blacklist_delete_sas_by_ike_id(pm, ike_id, ike_id_len);
  if (err != SSH_PM_BLACKLIST_OK)
    {
      printf("ssh_pm_blacklist_delete_sas_by_ike_id() failed with error: %s",
             ssh_pm_blacklist_error_to_string(err));
    }

*/


/* ************************* Types and definitions ***************************/

/* Parameter to define whether the QuickSec Blacklisting functionality is
 * enabled. */
#define SSH_PM_BLACKLIST_ENABLED

#ifdef SSH_PM_BLACKLIST_ENABLED

/* The maximun amount of entries which can be stored to blacklist database. */
#define SSH_PM_BLACKLIST_MAX_DB_ENTRIES 10000

/* This define can be commented out if duplicate IKE IDs are not allowed in
   configuration data. */
/* #define SSH_PM_BLACKLIST_DENY_DUPLICATE_IKE_ID_ENTRIES */

/** Error codes used in QuickSec Blacklisting functionality. */
typedef enum
{
  /** Successful  case */
  SSH_PM_BLACKLIST_OK = 0,

  /** Database limit exceeded */
  SSH_PM_BLACKLIST_ERROR_DB_LIMIT_EXCEEDED,

  /** Out of memory */
  SSH_PM_BLACKLIST_ERROR_OUT_OF_MEMORY,

  /** Syntax error in configuration data */
  SSH_PM_BLACKLIST_ERROR_CONF_DATA_SYNTAX_ERROR,

  /** Failure when trying to decode IKE ID from configuration data */
  SSH_PM_BLACKLIST_ERROR_IKE_ID_DECODE_FAILURE,

  /** Invalid argument */
  SSH_PM_BLACKLIST_ERROR_INVALID_ARGUMENT,

  /** Duplicate IKE ID found from configuration data */
  SSH_PM_BLACKLIST_ERROR_DUPLICATE_IKE_ID

} SshPmBlacklistError;

/** Set the new blacklist configuration. The argument 'config' must be valid
    for the duration of the function call and it can be freed after the
    function has returned. The new configuration is activated when
    ssh_pm_commit() function is called or cancelled if ssh_pm_abort() function
    is called.

    @param pm
    The Policy Manager object

    @param config
    The blacklist configuration data

    @param config_len
    The length of blacklist configuration data

    @return
    The function returns SSH_PM_BLACKLIST_OK on success and appropriate error
    code on failure.
*/
SshPmBlacklistError
ssh_pm_blacklist_set(SshPm pm,
                     unsigned char *config,
                     size_t config_len);


/** Statistics for Blacklisting functionality */
typedef struct SshPmBlacklistStatsRec
{
  /* Number of entries in blacklist database */
  SshUInt32 blacklist_entries;

  /* Allowed IKEv2 initial exchanges in responder side */
  SshUInt32 allowed_ikev2_r_initial_exchanges;
  /* Allowed IKEv2 create child exchanges in responder side */
  SshUInt32 allowed_ikev2_r_create_child_exchanges;
  /* Allowed IKEv2 IPsec SA rekeys in responder side */
  SshUInt32 allowed_ikev2_r_ipsec_sa_rekeys;
  /* Allowed IKEv2 IKE SA rekeys in responder side */
  SshUInt32 allowed_ikev2_r_ike_sa_rekeys;
  /* Allowed initiated IKEv2 IPsec SA rekeys in original responder side */
  SshUInt32 allowed_ikev2_i_ipsec_sa_rekeys;
  /* Allowed initiated IKEv2 IKE SA rekeys in original responder side */
  SshUInt32 allowed_ikev2_i_ike_sa_rekeys;

  /* Allowed IKEv1 main mode exchanges in responder side */
  SshUInt32 allowed_ikev1_r_main_mode_exchanges;
  /* Allowed IKEv1 aggressive mode exchanges in responder side */
  SshUInt32 allowed_ikev1_r_aggressive_mode_exchanges;
  /* Allowed IKEv1 quick mode exchanges in responder side */
  SshUInt32 allowed_ikev1_r_quick_mode_exchanges;
  /* Allowed initiated IKEv1 IPsec SA rekeys in original responder side */
  SshUInt32 allowed_ikev1_i_ipsec_sa_rekeys;
  /* Allowed initiated IKEv1 SA creations due to DPD in original responder
     side */
  SshUInt32 allowed_ikev1_i_dpd_sa_creations;

  /* Blocked IKEv2 initial exchanges in responder side */
  SshUInt32 blocked_ikev2_r_initial_exchanges;
  /* Blocked IKEv2 create child  exchanges in responder side */
  SshUInt32 blocked_ikev2_r_create_child_exchanges;
  /* Blocked IKEv2 IPsec SA rekeys in responder side */
  SshUInt32 blocked_ikev2_r_ipsec_sa_rekeys;
  /* Blocked IKEv2 IKE SA rekeys in responder side */
  SshUInt32 blocked_ikev2_r_ike_sa_rekeys;
  /* Blocked initiated IKEv2 IPsec SA rekeys in original responder side */
  SshUInt32 blocked_ikev2_i_ipsec_sa_rekeys;
  /* Blocked initiated IKEv2 IKE SA rekeys in original responder side */
  SshUInt32 blocked_ikev2_i_ike_sa_rekeys;

  /* Blocked IKEv1 main mode exchanges in responder side */
  SshUInt32 blocked_ikev1_r_main_mode_exchanges;
  /* Blocked IKEv1 aggressive mode exchanges in responder side */
  SshUInt32 blocked_ikev1_r_aggressive_mode_exchanges;
  /* Blocked IKEv1 quick mode exchanges in responder side */
  SshUInt32 blocked_ikev1_r_quick_mode_exchanges;
  /* Blocked initiated IKEv1 IPsec SA rekeys in original responder side */
  SshUInt32 blocked_ikev1_i_ipsec_sa_rekeys;
  /* Blocked initiated IKEv1 SA creations due to DPD in original responder
     side */
  SshUInt32 blocked_ikev1_i_dpd_sa_creations;

} SshPmBlacklistStatsStruct, *SshPmBlacklistStats;


/** A callback function of this type is called to return Blacklist statistics.

    @param pm
    The Policy Manager object

    @param stats
    The blacklist statistics or NULL if statistics collection is disabled.

    @param context
    The context data

    @return
    The function should return TRUE on success and FALSE on failure.
*/
typedef Boolean
(*SshPmBlacklistStatsCB)(SshPm pm,
                         const SshPmBlacklistStats stats,
                         void *context);

/** Get the blacklist statistics.

    @param pm
    The Policy Manager object

    @param callback
    The callback function used to pass statistics.

    @param context
    The context data for the statistics callback.

    @return
    The function returns TRUE on success and FALSE on failure.
*/
Boolean
ssh_pm_blacklist_get_stats(SshPm pm,
                           SshPmBlacklistStatsCB callback,
                           void *context);

/** Delete all IKE and IPsec SA associated with a particular remote IKE ID.

    @param pm
    The Policy Manager object

    @param ike_id
    The remote IKE ID

    @param ike_id_len
    The length of remote IKE ID

    @return
    The function returns SSH_PM_BLACKLIST_OK on success and appropriate error
    code on failure.
*/
SshPmBlacklistError
ssh_pm_blacklist_delete_sas_by_ike_id(SshPm pm,
                                      unsigned char *ike_id,
                                      size_t ike_id_len);

/** IKE ID information for Blacklisting functionality */
typedef struct SshPmBlacklistIkeIdInfoRec
{
  const unsigned char *type; /* Type */
  const unsigned char *data; /* Data */

#ifdef SSH_IPSEC_STATISTICS
  SshUInt32 stat_blocked; /* Statistics counter for blocked attempts */
#endif /* SSH_IPSEC_STATISTICS */

} SshPmBlacklistIkeIdInfoStruct, *SshPmBlacklistIkeIdInfo;

/** A callback function of this type is called to return IKE ID information
    from the blacklist database.

    @param pm
    The Policy Manager object

    @param info
    The IKE ID information

    @param context
    The context data

    @return
    The function should return TRUE on success and FALSE on failure. If FALSE
    is returned database iteration will be cancelled too.
*/
typedef Boolean
(*SshPmBlacklistIkeIdInfoCB)(SshPm pm,
                             SshPmBlacklistIkeIdInfo info,
                             void *context);

/** Get content of the blacklist database. This function calls the callback
    function 'callback' once for each IKE ID entry found from the blacklist
    database and finally once with NULL 'info' argument to indicate that the
    iteration has completed.

    @param pm
    The Policy Manager object

    @param callback
    The callback function used to pass IKE ID information.

    @param context
    The context data for the IKE ID Info callback.

    @return
    The function returns TRUE on success and FALSE on failure.
*/
Boolean
ssh_pm_blacklist_foreach_ike_id(SshPm pm,
                                SshPmBlacklistIkeIdInfoCB callback,
                                void *context);

/** Dump content of the blacklist database. The database content is returned
    in 'content' argument which is dynamically allocated. This memory has to
    be freed by using ssh_free() function.

    @param pm
    The Policy Manager object

    @param content
    The content of blacklist database

    @param content_len
    The length of content of blacklist databse

    @return
    The function returns TRUE on success and FALSE on failure.
*/
Boolean
ssh_pm_blacklist_dump(SshPm pm,
                      unsigned char **content,
                      size_t *content_len);

/** Function returns pointer to string that describes the blacklist error code.

    @param error
    The blacklist error code

    @return
    The function returns pointer to error string.
*/
const char *
ssh_pm_blacklist_error_to_string(SshPmBlacklistError error);

#endif /* SSH_PM_BLACKLIST_ENABLED */

#endif /* SPD_IKE_BLACKLIST_H */
