/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHMSPROV_UTIL_H
#define SSHMSPROV_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Returns the list of Installed providers. Caller must free
   the returned strings and the array of string pointers. */
void
ssh_ms_prov_enum_providers(char ***providers_ret,
                           SshUInt32 *num_providers_ret);

#ifdef __cplusplus
}
#endif

#endif /* SSHMSPROV_UTIL_H */
