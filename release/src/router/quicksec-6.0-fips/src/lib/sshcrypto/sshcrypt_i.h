/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Private interfaces within the crypto library.
*/

#ifndef SSHCRYPT_I_H
#define SSHCRYPT_I_H

#include "sshcrypt.h"



/* Different types of crypto objects */
typedef enum {
  SSH_CRYPTO_OBJECT_TYPE_CIPHER,
  SSH_CRYPTO_OBJECT_TYPE_HASH,
  SSH_CRYPTO_OBJECT_TYPE_MAC,
  SSH_CRYPTO_OBJECT_TYPE_RANDOM,
  SSH_CRYPTO_OBJECT_TYPE_PRIVATE_KEY,
  SSH_CRYPTO_OBJECT_TYPE_PUBLIC_KEY,
  SSH_CRYPTO_OBJECT_TYPE_PK_GROUP
} SshCryptoObjectType;

typedef enum {
  SSH_CRYPTO_ERROR_RNG,
  SSH_CRYPTO_ERROR_KEY_TEST_FAILURE,
  SSH_CRYPTO_ERROR_GROUP_TEST_FAILURE,
  SSH_CRYPTO_ERROR_OTHER
} SshCryptoError;

/* An crypto library error has occured. Set the global state to
   error. */
void
ssh_crypto_library_error(SshCryptoError error);

/* Returns TRUE if the current crypto library state is in a good state
   with regards to creation or use of a crypto object, otherwise FALSE
   and sets the `status_ret' value to a value to be signaled to the
   caller. `status_ret' may be NULL. */
Boolean
ssh_crypto_library_object_check_use(SshCryptoStatus *status_ret);

/* Returns TRUE if the current crypto library state is in a good state
   with regards to destruction (release) of an existing crypto object,
   otherwise FALSE and sets the `status_ret' value to a value to be
   signaled to the caller. `status_ret' may be NULL.. */
Boolean
ssh_crypto_library_object_check_release(SshCryptoStatus *status_ret);

/* Indicates to crypto library that a crypto object has been
   initialized. Depending on exact settings of the crypto library,
   this might be a no-operation. However, it might keep reference to
   the object and call type-specific zeroizaion function if necessary,
   etc. etc. If this function returns FALSE, the caller should not
   pass the object to caller, but should free it and return
   SSH_CRYPTO_LIBRARY_NO_MEMORY. */
Boolean
ssh_crypto_library_object_use(void *obj, SshCryptoObjectType type);

/* Indicates to the crypto library that a crypto object has been
   released and is no longer available to the caller (crypto library
   user). This must be called by all gen* or free routines at
   appropriate point. This routine will call ssh_fatal if it is called
   at inappropriate state. The `obj' must be same as for
   ssh_crypto_library_object_use. */
void
ssh_crypto_library_object_release(void *obj);

/* Returns TRUE if the crypto library is in an error state. This
   returns TRUE if and only if the crypto library is in error state.
   so it is the caller's responsibility to check that we're not in the
   uninitialized state first. */
Boolean
ssh_crypto_library_in_error_state(void);

/* Returns TRUE if the crypto library is in a "good" state: in this
   state you can create and destroy crypto object instances. The
   "good" states are "initializing" and "initialized". (The
   "initializing" is a good state because self-test routines need to
   create crypto objects to run the tests! However, since
   initialization is a synchronous operation, external access will
   never happen while in "initializing" state). */
Boolean
ssh_crypto_library_in_good_state(void);

/* Secure memory allocation and release. These functions should be
   used for allocating memory for all cipher data which is a potential
   security hazard if leaked.

   These routines might allocate the memory from secure non-paged
   memory, but *at least* the ssh_crypto_free_i will perform memory
   zeroization before returning the memory block to system allocator
   (or ssh_free) */

/* Allocate `len' of memory, can return NULL on failure */
void *
ssh_crypto_malloc_i(size_t len);

/* Allocate `nitems * len' of memory, which is zeroed before being
   returned. Can return NULL on failure. */
void *
ssh_crypto_calloc_i(size_t nitems, size_t len);

/* Free memory `ptr'. `ptr' must be allocated by ssh_crypto_malloc or
   ssh_crypto_calloc (if not, behavior is undefined). This will
   *always* overwrite the memory with zeros before releasing it for
   other use. */
void
ssh_crypto_free_i(void *ptr);

/* Heavy-duty zeroization: this in effect is equal to memset(), but
   memset is rather hard to get correctly with some highly optimizing
   compilers, since they can do variable liveness analysis, and
   optimize the memset away.. thus this function does under-the-hood
   per-compiler things to ensure that the memset (or equal function)
   is not optimized away. */
void
ssh_crypto_zeroize(void *ptr, size_t size); /* eq: memset(ptr, 0, size) */

/* Internal routine which can be used to change the default RNG to a
   given RNG. This will return a failure if it is called while any
   crypto object is allocated (apart from the given RNG). Also, if the
   given RNG is not certified to the current level, or the
   certification level is tried to change and the RNG does not support
   the new level, then that will fail. */
SshCryptoStatus
ssh_crypto_set_default_rng(SshRandom rng);

unsigned int ssh_random_object_get_byte(void);

/* Internal routine called by PRNG implemenetations. This causes the
   crytpo library to request random noise from all registered random
   noise sources. */
void
ssh_crypto_library_request_noise(void);

/************************************************************************/

#ifndef SSH_CRYPTO_HANDLE_TO_CIPHER
#define SSH_CRYPTO_HANDLE_TO_CIPHER(H) (SshCipherObject) (H)
#endif /* SSH_CRYPTO_HANDLE_TO_CIPHER */

#ifndef SSH_CRYPTO_HANDLE_TO_HASH
#define SSH_CRYPTO_HANDLE_TO_HASH(H) (SshHashObject) (H)
#endif /* SSH_CRYPTO_HANDLE_TO_HASH */

#ifndef SSH_CRYPTO_HANDLE_TO_MAC
#define SSH_CRYPTO_HANDLE_TO_MAC(H) (SshMacObject) (H)
#endif /* SSH_CRYPTO_HANDLE_TO_MAC */

#ifndef SSH_CRYPTO_HANDLE_TO_RANDOM
#define SSH_CRYPTO_HANDLE_TO_RANDOM(H) (SshRandomObject) (H)
#endif /* SSH_CRYPTO_HANDLE_TO_RANDOM */

#ifndef SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY
#define SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(H) (SshPrivateKeyObject) (H)
#endif /* SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY */

#ifndef SSH_CRYPTO_HANDLE_TO_PUBLIC_KEY
#define SSH_CRYPTO_HANDLE_TO_PUBLIC_KEY(H) (SshPublicKeyObject) (H)
#endif /* SSH_CRYPTO_HANDLE_TO_PUBLIC_KEY */

#ifndef SSH_CRYPTO_HANDLE_TO_PK_GROUP
#define SSH_CRYPTO_HANDLE_TO_PK_GROUP(H) (SshPkGroupObject) (H)
#endif /* SSH_CRYPTO_HANDLE_TO_PK_GROUP */

/************************************************************************/

#ifndef SSH_CRYPTO_CIPHER_TO_HANDLE
#define SSH_CRYPTO_CIPHER_TO_HANDLE(H)  (SshCipher) (H)
#endif /* SSH_CRYPTO_CIPHER_TO_HANDLE */

#ifndef SSH_CRYPTO_HASH_TO_HANDLE
#define SSH_CRYPTO_HASH_TO_HANDLE(H)  (SshHash) (H)
#endif /* SSH_CRYPTO_HASH_TO_HANDLE */

#ifndef SSH_CRYPTO_MAC_TO_HANDLE
#define SSH_CRYPTO_MAC_TO_HANDLE(H)  (SshMac) (H)
#endif /* SSH_CRYPTO_MAC_TO_HANDLE */

#ifndef SSH_CRYPTO_RANDOM_TO_HANDLE
#define SSH_CRYPTO_RANDOM_TO_HANDLE(H)  (SshRandom) (H)
#endif /* SSH_CRYPTO_RANDOM_TO_HANDLE */

#ifndef SSH_CRYPTO_PRIVATE_KEY_TO_HANDLE
#define SSH_CRYPTO_PRIVATE_KEY_TO_HANDLE(H) (SshPrivateKey) (H)
#endif /* SSH_CRYPTO_PRIVATE_KEY_TO_HANDLE */

#ifndef SSH_CRYPTO_PUBLIC_KEY_TO_HANDLE
#define SSH_CRYPTO_PUBLIC_KEY_TO_HANDLE(H) (SshPublicKey) (H)
#endif /* SSH_CRYPTO_PUBLIC_KEY_TO_HANDLE */

#ifndef SSH_CRYPTO_PK_GROUP_TO_HANDLE
#define SSH_CRYPTO_PK_GROUP_TO_HANDLE(H) (SshPkGroup) (H)
#endif /* SSH_CRYPTO_PK_GROUP_TO_HANDLE */

/************************************************************************/

#ifndef SSH_CRYPTO_OBJECT_HEADER
#define SSH_CRYPTO_OBJECT_HEADER
#endif /* SSH_CRYPTO_OBJECT_HEADER */


#ifndef KERNEL
/* Get current time as 64-bit integer. If time is set in the global state, use
   that (that is used during the static random number tests for random number
   generators which depend on current time), otherwise use ssh_time to get the
   current time. */
SshTime ssh_crypto_get_time(void);

/* Sets the current time used by the crypto library. Setting time to zero
   indicates that crypto library should use ssh_time every time
   ssh_crypto_get_time is called. */
void ssh_crypto_set_time(SshTime t);
#endif /* !KERNEL */

#endif /* SSHCRYPT_I_H */
