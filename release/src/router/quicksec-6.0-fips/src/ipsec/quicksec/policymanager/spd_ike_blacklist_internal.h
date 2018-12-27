/**
   @copyright
   Copyright (c) 2011 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for the QuickSec Blacklisting functionality.
*/

#ifndef SPD_IKE_BLACKLIST_INTERNAL_H
#define SPD_IKE_BLACKLIST_INTERNAL_H

#ifdef SSH_PM_BLACKLIST_ENABLED

/** Initialize the blacklist functionality.

    @param pm
    The Policy Manager object

    @return
    The function returns TRUE on success and FALSE on failure.
*/
Boolean
ssh_pm_blacklist_init(SshPm pm);

/** Uninitialize the blacklist functionality.

    @param pm
    The Policy Manager object

    @return
    None.
*/
void
ssh_pm_blacklist_uninit(SshPm pm);

/** Commit changes done to the blacklist database.

    @param pm
    The Policy Manager object

    @return
    None.
*/
void
ssh_pm_blacklist_commit(SshPm pm);

/** Abort changes done to the blacklist database.

    @param pm
    The Policy Manager object

    @return
    None.
*/
void
ssh_pm_blacklist_abort(SshPm pm);

/** Codes for different blacklist check cases. */
typedef enum
{
  /* IKEv2 codes */

  /** IKEv2 initial exchange in responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV2_R_INITIAL_EXCHANGE = 0,

  /** IKEv2 create child exchange in responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV2_R_CREATE_CHILD_EXCHANGE,

  /** IKEv2 IPsec SA rekey in responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV2_R_IPSEC_SA_REKEY,

  /** IKEv2 IKE SA rekey in responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV2_R_IKE_SA_REKEY,

  /** Initiated IKEv2 IPsec SA rekey in original responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV2_I_IPSEC_SA_REKEY,

  /** Initiated IKEv2 IKE SA rekey in original responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV2_I_IKE_SA_REKEY,

  /* IKEv1 codes */

  /** IKEv1 main mode exchange in responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV1_R_MAIN_MODE_EXCHANGE,

  /** IKEv1 aggressive mode exchange in responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV1_R_AGGRESSIVE_MODE_EXCHANGE,

  /** IKEv1 quick mode exchange in responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV1_R_QUICK_MODE_EXCHANGE,

  /** Initiated IKEv1 IPsec SA rekey in original responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV1_I_IPSEC_SA_REKEY,

  /** Initiated IKEv1 SA creation due to DPD in original responder side */
  SSH_PM_BLACKLIST_CHECK_IKEV1_I_DPD_SA_CREATION,

  /** This should be the last check code. */
  SSH_PM_BLACKLIST_CHECK_LAST

} SshPmBlacklistCheckCode;

/** Check against the blacklist database if access is allowed or denied for
    the particular IKE ID.

    @param pm
    The Policy Manager object

    @param ike_id
    The IKE ID

    @param check_code
    The check code

    @return
    The function returns TRUE if access is allowed and FALSE if access is
    denied.
*/
Boolean
ssh_pm_blacklist_check(SshPm pm,
                       SshIkev2PayloadID ike_id,
                       SshPmBlacklistCheckCode check_code);

#endif /* SSH_PM_BLACKLIST_ENABLED */

#endif /* SPD_IKE_BLACKLIST_INTERNAL_H */
