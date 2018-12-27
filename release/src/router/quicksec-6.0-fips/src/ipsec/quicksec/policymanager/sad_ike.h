/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SAD handle structure.
*/

#ifndef PM_IKE_SAD_H
#define PM_IKE_SAD_H

#include "sshincludes.h"
#include "sshadt.h"
#include "sshadt_list.h"
#include "sshikev2-payloads.h"
#include "quicksecpm_internal.h"

struct SshSADHandleRec {
  SshADTContainer ts_free_list;
  SshADTContainer sa_free_list;
  SshADTContainer conf_free_list;

  SshADTContainer ike_sa_by_spi;

  /** Back pointer to the policymanager */
  SshPm pm;
};

typedef struct SshSADHandleRec  SshSADHandleStruct;

#endif /* PM_IKE_SAD_H */
