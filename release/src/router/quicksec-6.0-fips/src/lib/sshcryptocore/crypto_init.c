/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions which initialize the crypto library and manipulate its
   global state.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "crypto_tests.h"
#include "sshgetput.h"

#ifndef KERNEL
#include "sshglobals.h"
#include "sshentropy.h"
#ifdef SSHDIST_CRYPT_NIST_SP_800_90
#include "nist-sp-800-90.h"
#endif /* SSHDIST_CRYPT_NIST_SP_800_90 */
#endif /* !KERNEL */
#ifndef KERNEL
#include "sshglobals.h"
#endif /* !KERNEL */








#define SSH_DEBUG_MODULE "SshCryptoInit"

typedef struct SshCryptoNoiseRequestRec {

  SshCryptoNoiseRequestCB callback;
  void *context;
  struct SshCryptoNoiseRequestRec *next;
} SshCryptoNoiseRequestStruct, *SshCryptoNoiseRequest;

typedef struct SshCryptoStateRec
{
  SshCryptoLibraryStatus state;

  /* Handles (SshCipher, SshHash, SshMac, SshPK, ...) allocated out */
  SshUInt32 handle_count;

  /* Random number generator */
  SshRandomObject rng;

  /* Registered noise request callbacks */
  SshCryptoNoiseRequest noise_requests;

#ifndef KERNEL
  /* Current time settable by ssh_crypto_set_time. If set then ssh_time is not
     used. If zero then ssh_crypto_get_time uses ssh_time to get the current
     time each time. */
  SshTime current_time;
#endif /* !KERNEL */
} SshCryptoStateStruct, *SshCryptoState;

/* SSH Globals cannot be used in kernel mode. */
#ifndef KERNEL
SSH_GLOBAL_DEFINE(SshCryptoStateStruct, ssh_crypto_library_state);
SSH_GLOBAL_DECLARE(SshCryptoStateStruct, ssh_crypto_library_state);
#define ssh_crypto_library_state SSH_GLOBAL_USE(ssh_crypto_library_state)
#else /* !KERNEL */
static SshCryptoStateStruct ssh_crypto_library_state;
#endif /* !KERNEL */

#ifdef SSHDIST_CRYPT_NIST_SP_800_90
#define DEFAULT_RNG "nist-sp-800-90"
#else /* SSHDIST_CRYPT_NIST_SP_800_90 */
#define DEFAULT_RNG "ssh"
#endif /* SSHDIST_CRYPT_NIST_SP_800_90 */

/* Forward declaration. */
static void ssh_random_object_add_light_noise(SshRandomObject random);

SshCryptoStatus ssh_crypto_library_initialize(void)
{
  SshCryptoStateStruct s;
#ifndef KERNEL
  SshCryptoStatus status;
#endif /* KERNEL */
  memset(&s, 0, sizeof(s));
  s.state = SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED;

  /* Init only possible if in uninit state. */
#ifndef KERNEL
  if (SSH_GLOBAL_CHECK(ssh_crypto_library_state))
#endif /* KERNEL */
  if (ssh_crypto_library_state.state !=
      SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED)
    return SSH_CRYPTO_LIBRARY_ERROR;

#ifdef KERNEL
  ssh_crypto_library_state = s;
#else /* KERNEL */
  SSH_GLOBAL_INIT(ssh_crypto_library_state, s);
#endif /* KERNEL */

#ifndef KERNEL
  /* Register the keys types here. */
#ifdef SSHDIST_CRYPT_RSA
  status = ssh_pk_provider_register(&ssh_pk_if_modn_generator);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not register if-modn key type"));
      return status;
    }
#endif /* SSHDIST_CRYPT_RSA */

#ifdef SSHDIST_CRYPT_DL
#ifdef SSHDIST_CRYPT_DL_GENERATE
  status = ssh_pk_provider_register(&ssh_pk_dl_modp_generator);
#else /* SSHDIST_CRYPT_DL_GENERATE */
  status = ssh_pk_provider_register(&ssh_pk_dl_modp);
#endif /* SSHDIST_CRYPT_DL_GENERATE */
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not register dl-modp key type"));
      return status;
    }
#endif /* SSHDIST_CRYPT_DL */

#ifdef SSHDIST_CRYPT_ECP
  status = ssh_pk_provider_register(&ssh_pk_ec_modp_generator);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not register ec-modp key type"));
      return status;
    }
#endif /* SSHDIST_CRYPT_ECP */
#endif /* !KERNEL */

  /* enter self test state for the duration of the tests */
  ssh_crypto_library_state.handle_count = 0;
  ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST;

  /* Math library is needed for PK, PK is not available in KERNEL */
#ifdef SSHDIST_MATH
#ifndef KERNEL
  /* Initialize the math library (necessary for public key operations). */
  if (!ssh_math_library_initialize())
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not initialize math library"));
      status = SSH_CRYPTO_MATH_INIT;
      ssh_crypto_library_state.state =
        SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED;
      goto failed_at_math;
    }
#endif /* !KERNEL */
#endif /* SSHDIST_MATH */

  /* Both the crypto and math library self tests have succeeded (if
     performed). Set the global state to OK. */
  ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_OK;

#ifndef KERNEL
  /* Initialize default RNG */
  status = ssh_random_object_allocate(DEFAULT_RNG,
                                      &ssh_crypto_library_state.rng);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate RNG `%s'", DEFAULT_RNG));
      ssh_crypto_library_state.state =
        SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED;
      goto failed_after_math;
    }
#endif /* !KERNEL */

  ssh_random_object_add_light_noise(ssh_crypto_library_state.rng);
  return SSH_CRYPTO_OK;

#ifndef KERNEL
  /* Failure point, math library has been initialized (if required) */
 failed_after_math:
#ifdef SSHDIST_MATH
  ssh_math_library_uninitialize();

  /* Failure point, when math library failed to initialize */
 failed_at_math:
#endif /* SSHDIST_MATH */

  /* appropriate library state was set already above */
  return status;
#endif /* !KERNEL */
}

/* Uninitialize the library. */
SshCryptoStatus ssh_crypto_library_uninitialize(void)
{
  /* Can't uninit in uninit and self test states. */
  if (ssh_crypto_library_state.state ==
      SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED)
    {
      return SSH_CRYPTO_LIBRARY_UNINITIALIZED;
    }

  if (ssh_crypto_library_state.state ==
      SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST)
    return SSH_CRYPTO_LIBRARY_ERROR;

#ifndef KERNEL
  /* Free RNG */
  if (ssh_crypto_library_state.rng)
    {
      ssh_random_object_free(ssh_crypto_library_state.rng);
      ssh_crypto_library_state.rng = NULL;
    }
#endif /* !KERNEL */

  if (ssh_crypto_library_state.handle_count > 0)
    {
      ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_ERROR;
      return SSH_CRYPTO_LIBRARY_ERROR;
    }

  ssh_crypto_library_unregister_noise_request(NULL_FNPTR, NULL);

#ifdef SSHDIST_MATH
#ifndef KERNEL
  ssh_math_library_uninitialize();
#endif /* !KERNEL */
#endif /* SSHDIST_MATH */

  ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED;
  return SSH_CRYPTO_OK;
}

/* Just return the status */
SshCryptoLibraryStatus ssh_crypto_library_get_status(void)
{
  return ssh_crypto_library_state.state;
}

void ssh_crypto_library_error(SshCryptoError error)
{
  /* There is no transition to error status from uninitialized state */
  SSH_ASSERT(ssh_crypto_library_state.state
             != SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED);

  ssh_crypto_library_state.state = SSH_CRYPTO_LIBRARY_STATUS_ERROR;
}

/* Public */
SshCryptoStatus ssh_crypto_library_self_tests(void)
{
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  return SSH_CRYPTO_OK;
}

/* Take of reference to crypto object. */
Boolean
ssh_crypto_library_object_use(void *obj, SshCryptoObjectType type)
{
  ssh_crypto_library_state.handle_count++;

  return TRUE;
}

void
ssh_crypto_library_object_release(void *obj)
{
  ssh_crypto_library_state.handle_count--;
}

#ifdef HAVE_AES_INTEL_INSTRUCTION_SET
/* If Intel AES instructions are used the cipher context needs to be
   16-aligned. As QS library does not have native support for such
   feature, this is done here and all allocations using this
   function will be 16-aligned.
*/
void *ssh_crypto_malloc_i(size_t size)
{
  void *ptr;
  SshUInt32 offset, size_t_len;
  void *position;

  size_t_len = sizeof(size_t);

  ptr = ssh_malloc(size + 16 + size_t_len);

  ((size_t*) ptr)[0] = size;

  position = ptr + size_t_len;

  offset =
    0xffffffff & (16 - ((*(long long unsigned int *)&(position)) % 16));

  position = position + offset - 1;

  *(unsigned char *)position = (unsigned char) (offset + size_t_len);

  ptr += (offset + size_t_len);

  return ptr;
}

void ssh_crypto_free_i(void *ptr)
{
  size_t size;
  SshUInt32 offset;

  if (!ptr)
    return;

  offset = *(unsigned char *)(ptr - 1);

  SSH_ASSERT(offset < (17 + sizeof(size_t)));

  size = *(size_t *)(ptr - offset);
  memset(ptr - offset, 0x00, (size + sizeof(size_t) + 16));

  ssh_free(ptr - offset);
}
#else /* HAVE_AES_INTEL_INSTRUCTION_SET */

void *ssh_crypto_malloc_i(size_t size)
{
  void *ptr;

  ptr = ssh_malloc(size + sizeof(size_t));

  if (!ptr)
    return NULL;

  ((size_t*) ptr)[0] = size;

  return &(((size_t *) ptr)[1]);
}

void ssh_crypto_free_i(void *ptr)
{
  size_t *size_p = ptr;

  if (size_p == NULL)
    return;

  size_p--;
  memset(size_p + 1, 0, *size_p);

  ssh_free(size_p);
}
#endif /* HAVE_AES_INTEL_INSTRUCTION_SET */

void *ssh_crypto_calloc_i(size_t nelems, size_t size)
{
  void *ptr;

  ptr = ssh_crypto_malloc_i(nelems * size);

  if (ptr)
    memset(ptr, 0, nelems * size);

  return ptr;
}

#ifdef _MSC_VER
/* turn compiler optimizations off for this func */
#pragma optimize("",off)
#endif /* _MSC_VER */

void ssh_crypto_zeroize(void *ptr, size_t n)
{
  unsigned char *p = (unsigned char *)ptr;
  int i;
  for (i = 0; i < n; i++) p[i] = '\0';
}

#ifdef _MSC_VER
#pragma optimize("",on)
#endif /* _MSC_VER */

unsigned int ssh_random_object_get_byte(void)
{
  unsigned char buf[1];

#ifndef KERNEL
  SshCryptoStatus status;

  status = ssh_random_object_get_bytes(ssh_crypto_library_state.rng,
                                       buf, 1);

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Fatal failure in ssh_random_get_bytes: %s (%d)",
              ssh_crypto_status_message(status), status);
#else /* KERNEL */
  buf[0] = 0;
#endif /* !KERNEL */

  return buf[0];
}

unsigned int ssh_random_get_byte(void)
{
#ifndef KERNEL
  if (!ssh_crypto_library_object_check_use(NULL))
    ssh_fatal("ssh_random_get_byte called while crypto is uninitialized");
  return ssh_random_object_get_byte();
#else /* KERNEL */
  {
    unsigned char buf[1];

    buf[0] = 0;
    return buf[0];
  }
#endif /* !KERNEL */
}

SshUInt32 ssh_random_get_uint32(void)
{
#ifndef KERNEL
  SshCryptoStatus status;
  unsigned char buf[4];

  if (!ssh_crypto_library_object_check_use(NULL))
    ssh_fatal("ssh_random_get_byte called while crypto is uninitialized");

  status = ssh_random_object_get_bytes(ssh_crypto_library_state.rng,
                                       buf, 4);

  if (status != SSH_CRYPTO_OK)
    ssh_fatal("Fatal failure in ssh_random_get_bytes: %s (%d)",
              ssh_crypto_status_message(status), status);

  return SSH_GET_32BIT(buf);
#else /* KERNEL */
  ssh_fatal("This function is not implemented in kernel");
  return 0;
#endif /* !KERNEL */
}

void
ssh_random_object_add_noise(const unsigned char *buf, size_t bytes,
                            size_t estimated_entropy_bits)
{
#ifndef KERNEL
  ssh_random_object_add_entropy(ssh_crypto_library_state.rng,
                                (const unsigned char *)buf, bytes,
                                estimated_entropy_bits);
#endif /* !KERNEL */
}


void
ssh_random_add_noise(const unsigned char *buf, size_t bytes,
                     size_t estimated_entropy_bits)
{
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adding %d bytes of noise, estimated entropy bits %d",
             (int) bytes, (int) estimated_entropy_bits));

#ifndef KERNEL
  if (!ssh_crypto_library_object_check_use(NULL))
    ssh_fatal("ssh_random_add_noise called while crypto is uninitialized");

  ssh_random_object_add_noise(buf, bytes, estimated_entropy_bits);
#endif /* !KERNEL */
}

void ssh_random_stir(void)
{
  if (!ssh_crypto_library_object_check_use(NULL))
    ssh_fatal("ssh_random_stir called while crypto is uninitialized");

  /* This function has no effect. */
}

/* This routine checks validity of object use/creation within the
   library. It returns TRUE if so, and FALSE otherwise (and sets
   (*status_ret) if not NULL). State is good when it is
   SSH_CRYPTO_LIBRARY_STATE_OK. */

Boolean ssh_crypto_library_object_check_use(SshCryptoStatus *status_ret)
{
  SshCryptoLibraryStatus status;
  SshCryptoStatus dummy;

  if (!status_ret)
    status_ret = &dummy;

  status = ssh_crypto_library_state.state;

  if (status == SSH_CRYPTO_LIBRARY_STATUS_OK)
    {
      *status_ret = SSH_CRYPTO_OK;
      return TRUE;
    }

  if (status == SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST)
    {
      *status_ret = SSH_CRYPTO_LIBRARY_INITIALIZING;
      return FALSE;
    }

  if (status == SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED)
    {
      *status_ret = SSH_CRYPTO_LIBRARY_UNINITIALIZED;
      return FALSE;
    }

  if (status == SSH_CRYPTO_LIBRARY_STATUS_ERROR)
    {
      *status_ret = SSH_CRYPTO_LIBRARY_ERROR;
      return FALSE;
    }

  *status_ret = SSH_CRYPTO_LIBRARY_ERROR;
  SSH_NOTREACHED;
  return FALSE;
}

/* This routine checks validity of object release within the
   library. It returns TRUE if so, and FALSE otherwise (and sets
   (*status_ret) if not NULL). State is good when it is
   SSH_CRYPTO_LIBRARY_STATE_OK or
   SSH_CRYPTO_LIBRARY_STATE_ERROR. Eg. crypto objects can be freed in
   the error state. */

Boolean ssh_crypto_library_object_check_release(SshCryptoStatus *status_ret)
{
  SshCryptoLibraryStatus status;
  SshCryptoStatus dummy;

  if (!status_ret)
    status_ret = &dummy;

  status = ssh_crypto_library_state.state;

  if (status == SSH_CRYPTO_LIBRARY_STATUS_OK ||
      status == SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST ||
      status == SSH_CRYPTO_LIBRARY_STATUS_ERROR)
    {
      *status_ret = SSH_CRYPTO_OK;
      return TRUE;
    }

  if (status == SSH_CRYPTO_LIBRARY_STATUS_UNINITIALIZED)
    {
      *status_ret = SSH_CRYPTO_LIBRARY_UNINITIALIZED;
      return FALSE;
    }

  SSH_NOTREACHED;
  return FALSE;
}

SshCryptoStatus
ssh_crypto_set_default_rng(SshRandom handle)
{
  SshRandomObject rng;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(rng = SSH_CRYPTO_HANDLE_TO_RANDOM(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

#ifndef KERNEL
  ssh_random_object_free(ssh_crypto_library_state.rng);
#endif /* !KERNEL */
  ssh_crypto_library_state.rng = rng;

  return SSH_CRYPTO_OK;
}

void
ssh_crypto_free(void *ptr)
{
  ssh_free(ptr);
}

/* Get current time as 64-bit integer. If time is set in the global state, use
   that (that is used during the static random number tests for random number
   generators which depend on current time), otherwise use ssh_time to get the
   current time. */

#ifndef KERNEL
SshTime ssh_crypto_get_time(void)
{
  if (ssh_crypto_library_state.current_time != -1)
    return ssh_crypto_library_state.current_time;
  return ssh_time();
}

/* Sets the current time used by the crypto library. Setting time to zero
   indicates that crypto library should use ssh_time every time
   ssh_crypto_get_time is called. */

void ssh_crypto_set_time(SshTime t)
{
  ssh_crypto_library_state.current_time = t;
}
#endif /* !KERNEL */


/******************* Retrieve noise from operating env ******************/

/* The kernel and non-kernel version are separated, since they have so
   little in common between them. This helps a little on understanding
   of the routines, since by nature they are heavily
   ifdef-cluttered. */

#ifdef KERNEL
static void
ssh_random_object_add_light_noise(SshRandomObject random)
{
  return;
}

void
ssh_random_add_light_noise(SshRandom handle)
{
  return;
}

#endif /* KERNEL */

#ifndef KERNEL
static void
ssh_random_object_add_light_noise(SshRandomObject random)
{
  unsigned char noise_bytes[512];
  size_t noise_size, entropy_size;

  memset(noise_bytes, 0x00, 512);

  if (random == NULL)
    random = ssh_crypto_library_state.rng;

  if (!ssh_get_system_noise(noise_bytes, 512, &noise_size, &entropy_size))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get system noise"));
      return;
    }

  ssh_random_object_add_entropy(random, noise_bytes, noise_size,
                                entropy_size);
}

void
ssh_random_add_light_noise(SshRandom handle)
{
  SshRandomObject random;
  SshCryptoStatus status;

  if (!ssh_crypto_library_object_check_use(&status))
    ssh_fatal("ssh_random_add_light_noise called while crypto is "
              "uninitialized");

  if (handle == NULL)
    {
      ssh_random_object_add_light_noise(NULL);
      return;
    }

  random = SSH_CRYPTO_HANDLE_TO_RANDOM(handle);

  ssh_random_object_add_light_noise(random);
}


#endif /* !KERNEL */

/******************* End of env noise retrieval *************************/


/************************** Noise sources *******************************/

Boolean
ssh_crypto_library_register_noise_request(SshCryptoNoiseRequestCB request_cb,
                                          void *context)
{
  SshCryptoNoiseRequest noise;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Registering noise source request callback %p to crypto library",
             request_cb));

  if (request_cb == NULL_FNPTR)
    return FALSE;

  noise = ssh_calloc(1, sizeof(SshCryptoNoiseRequestStruct));
  if (noise == NULL)
    return FALSE;

  noise->callback = request_cb;
  noise->context = context;
  noise->next = ssh_crypto_library_state.noise_requests;
  ssh_crypto_library_state.noise_requests = noise;

  /* Request noise from the newly added noise source. */
  (*request_cb)(context);

  return TRUE;
}

Boolean
ssh_crypto_library_unregister_noise_request(SshCryptoNoiseRequestCB request_cb,
                                            void *context)
{
  SshCryptoNoiseRequest curr, prev;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Unregistered noise source request callback %p from "
             "crypto library", request_cb));

  prev = curr = ssh_crypto_library_state.noise_requests;

  /* Remove all registered callbacks on NULL input parameters. */
  if (request_cb == NULL_FNPTR && context == NULL)
    {
      while (prev != NULL)
        {
          curr = prev->next;
          ssh_free(prev);
          prev = curr;
        }
      ssh_crypto_library_state.noise_requests = NULL;
      return TRUE;
    }

  while (curr != NULL)
    {
      if (curr->callback == request_cb && curr->context == context)
        {
          if (curr == ssh_crypto_library_state.noise_requests)
            ssh_crypto_library_state.noise_requests = curr->next;
          else
            prev->next = curr->next;
          ssh_free(curr);
          return TRUE;
        }

      prev = curr;
      curr = curr->next;
    }
  return FALSE;
}

void
ssh_crypto_library_request_noise(void)
{
  SshCryptoNoiseRequest request = ssh_crypto_library_state.noise_requests;

  /* Request random noise from all registered sources. */
  while (request != NULL)
    {
      (*request->callback)(request->context);
      request = request->next;
    }
}

