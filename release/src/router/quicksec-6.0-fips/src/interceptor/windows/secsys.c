/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This source file implements a function for removing the WORLD (i.e.
   "everyone") access allowed entry from a device object's security
   descriptor.

   This operation fills one potential security hole by allowing only the
   system services and users having administrator privileges to access our
   device.
*/

#ifdef SSH_IM_INTERCEPTOR

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#pragma warning(push, 3)  /* Warning level 3 for Microsoft's header files */

#include <windef.h>
#include <winnt.h>

#include <wdm.h>
#include <ntifs.h>

#pragma warning(pop)
#pragma warning(push, 4)  /* Warning level 4 */
#include "secsys.h"

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

/*--------------------------------------------------------------------------
  EXTERNAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

/* Unfortunately we have to use some undocumented kernel API functions: */

NTSYSAPI BOOLEAN NTAPI
RtlValidSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor);

NTSYSAPI NTSTATUS NTAPI
RtlGetDaclSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor,
                             PBOOLEAN DaclPresent,
                             PACL *Dacl,
                             PBOOLEAN DaclDefaulted);

NTSYSAPI ULONG NTAPI
RtlLengthRequiredSid(UCHAR nSubAuthorityCount);

NTSYSAPI PULONG NTAPI
RtlSubAuthoritySid(PSID pSid, DWORD nSubAuthority);

NTSYSAPI NTSTATUS NTAPI
RtlInitializeSid(PSID Sid,
                 PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                 BYTE nSubAuthorityCount);

NTSYSAPI BOOLEAN NTAPI
RtlEqualSid(PSID pSid1, PSID pSid2);

NTSYSAPI ULONG NTAPI
RtlLengthSecurityDescriptor(PSECURITY_DESCRIPTOR SecurityDescriptor);

/* Undefine RtlMoveMemory macro and force linker to use the actual function */
#undef RtlMoveMemory
NTSYSAPI VOID
RtlMoveMemory(PVOID destination, const VOID *source, SIZE_T length);

/* SSH specific memory allocation/deallocation functions */

void *ssh_malloc(size_t size);
void ssh_free(void *ptr);


/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_world_sid_allocate()

  Allocates and initializes a new WORLD access SID (security identifier).

  Arguments:
    sid_ptr - Pointer to variable to receive the address of newly created
              SID.

  Returns:
    TRUE    World SID successfully created.
    FALSE   Error occurred.

  Notes:
    This function should be called at IRQL passive level only. (Because we
    use some undocumented kernel API functions, we can't know whether it's
    safe to call them at a raised IRQL.)
  --------------------------------------------------------------------------*/

static BOOLEAN 
ssh_world_sid_allocate(PSID *sid_ptr)
{
  ULONG sid_length = RtlLengthRequiredSid(1);
  BOOLEAN status = FALSE;

  if (sid_length > 0)
    {
      /* Allocate and initialize WORLD SID */
      PSID  world_sid = ssh_malloc(sid_length);

      if (world_sid != NULL)
        {
          SID_IDENTIFIER_AUTHORITY  world_sia = SECURITY_WORLD_SID_AUTHORITY;

          if (NT_SUCCESS(RtlInitializeSid(world_sid, &world_sia, 1)))
            {
              PULONG  sub_authority = RtlSubAuthoritySid(world_sid, 0);

              if (sub_authority != NULL)
                {
                  *sub_authority = SECURITY_WORLD_RID;
                  *sid_ptr = world_sid;

                  status = TRUE;
                }
            }

          if (status == FALSE)
            ssh_free(world_sid);
        }
    }

  return (status);
}


/*--------------------------------------------------------------------------
  ssh_sd_copy()

  Copies a self-relative security descriptor.

  Arguments:
    orig_sd - descriptor to copy
    new_sd  - copy of the previous, returned

  Returns:
    TRUE    Copy successful
    FALSE   Error occurred, (no memory, descriptor not valid)

  Notes:
    Functions used are documented from Win2K up, but present
    at NT4.0 kernel also.

    We need to make the copy of the original SD on WinXP, because
    there the original is a shared SD, and by modifying that
    we break some other things also. On other platform
    we (NT, 2k) we just consume some extra memory.

    Self-relative SD is contiguous block of memory, so this
    operation is safe.

  --------------------------------------------------------------------------*/
static BOOLEAN 
ssh_sd_copy(PSECURITY_DESCRIPTOR orig_sd,
            PSECURITY_DESCRIPTOR *new_sd)
{
   ULONG sdlen = RtlLengthSecurityDescriptor(orig_sd);
   BOOLEAN status = FALSE;
   PSECURITY_DESCRIPTOR sd = NULL;

   if ((sdlen > 0) && ((sd = ssh_malloc(sdlen)) != NULL))
     {



       RtlCopyMemory(sd, orig_sd, sdlen);
       status = RtlValidSecurityDescriptor(sd);
       if (!status)
         {
           ssh_free(sd);
           sd = NULL;
         }
     }

   *new_sd = sd;
   return status;

}

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_access_permissions_limit()

  Removes the WORLD (i.e. 'everyone') access allowed ACE (access control
  entry) from the DACL (discretionary access control list) of the given
  security descriptor.

  This operation ensures that the device object can be opened only by
  system services and users having administrator privileges.

  Arguments:
    sd - Pointer to security descriptor to be modified.
    new_sd - Pointer to a new descriptor without WORLD access

  Returns:
    TRUE    Security descriptor successfully modified.
    FALSE   Error occurred. Function fails if the
            original descriptor did not contain WORLD access.

  Notes:
    This function should be called at IRQL passive level only. (Because we
    use some undocumented kernel API functions, we can't know whether it's
    safe to call them at a raised IRQL.)
  --------------------------------------------------------------------------*/

BOOLEAN 
ssh_access_permissions_limit(PSECURITY_DESCRIPTOR sd,
                             PSECURITY_DESCRIPTOR *new_sd)
{
  BOOLEAN status = FALSE;
  PSECURITY_DESCRIPTOR tmp_sd = NULL;

  if (RtlValidSecurityDescriptor(sd))
    {
      BOOLEAN dacl_present;
      BOOLEAN dacl_defaulted;
      PACL  dacl = NULL;

      status =  ssh_sd_copy(sd, &tmp_sd);

      if (status)
        {

          /* Check that security descriptor contains a valid DACL
             (Discretionary access control list), which we understand... */
          if (NT_SUCCESS(RtlGetDaclSecurityDescriptor(tmp_sd, &dacl_present,
                                                      &dacl,
                                                      &dacl_defaulted)) &&
              (dacl_present != FALSE) &&
              (dacl_defaulted == FALSE &&
               (dacl != NULL) &&
               (dacl->AclRevision <= ACL_REVISION)))
            {
              PSID  world_sid;

              /* Create a temporary WORLD access SID */
              if (ssh_world_sid_allocate(&world_sid))
                {
                  PACCESS_ALLOWED_ACE aa_ace;
                  UINT  ace_index;
                  UINT  move_size = dacl->AclSize - sizeof(ACL);

                  /* Pointer to first ACE */
                  aa_ace = (PACCESS_ALLOWED_ACE)((PBYTE)dacl + sizeof(ACL));

                  for (ace_index = 0; ace_index < dacl->AceCount; ace_index++)
                    {
                      move_size -= aa_ace->Header.AceSize;

                      /* Remove the WORLD (i.e. "everyone") access allowed ACE
                         from the DACL. */
                      if ((aa_ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
                          && RtlEqualSid((PSID)&aa_ace->SidStart, world_sid))
                        {
                          RtlMoveMemory(aa_ace, 
                                        ((unsigned char *)aa_ace 
                                         + aa_ace->Header.AceSize), 
                                        move_size);

                          /* Remember to decrement the AceCount of DACL. */
                          dacl->AceCount--;

                          /* Make sure we didn't invalidate the security
                             descriptor */
                          if (RtlValidSecurityDescriptor(tmp_sd))
                              status = TRUE;

                          break;  /* done! */
                        }

                      /* Pointer to next ACE (if any) */
                      aa_ace = (PACCESS_ALLOWED_ACE)
                        ((unsigned char *)aa_ace + aa_ace->Header.AceSize);
                    }

                  /* Delete the temporary WORLD SID */
                  ssh_free(world_sid);
                }
            }
        }
    }

  *new_sd = tmp_sd;
  return (status);
}

#pragma warning(disable : 4514)

#endif /* SSH_IM_INTERCEPTOR */
