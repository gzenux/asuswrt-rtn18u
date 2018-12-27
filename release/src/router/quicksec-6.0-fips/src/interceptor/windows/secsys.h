/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Function for removing the WORLD (i.e. everyone's) access allowed
   entry from a device object's security descriptor.
*/

#ifndef SSH_SECSYS_H
#define SSH_SECSYS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "sshdistdefs.h"

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  Removes the WORLD (i.e. "everyone") access allowed entry from the security
  descriptor's access control list. Instead of modifying the original SD,
  this function creates a new one without World access alloved ACE. (Windows
  XP and all later operating systems use security descriptors that are shared 
  between multiple device objects. We MUST NOT touch these shared security
  descriptors!)
  --------------------------------------------------------------------------*/
BOOLEAN ssh_access_permissions_limit(PSECURITY_DESCRIPTOR old_sd,
                                     PSECURITY_DESCRIPTOR *new_sd);


#ifdef __cplusplus
}
#endif

#endif /* SSH_SECSYS_H */ 
