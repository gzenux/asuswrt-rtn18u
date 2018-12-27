/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Get entropy from system source.
*/

#include "sshincludes.h"

#define SSH_DEBUG_MODULE "SshEntropy"

/******************* Retrieve noise from operating env ******************/

#define UNIX_ENTROPY_SOURCE "/dev/urandom"
#define MAX_ENTROPY_RETURN_SIZE 4096

#define ESTIMATED_ENTROPY_BITS_PER_BYTE 8

Boolean ssh_get_system_entropy(unsigned char *return_buffer,
                               size_t return_buffer_size,
                               size_t *returned_bytes,
                               size_t *returned_entropy)
{
  *returned_bytes = 0;
  *returned_entropy = 0;

  if (return_buffer_size == 0 || return_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Empty return buffer for entropy"));
      return FALSE;
    }

#if !defined(WIN32) && !defined(VXWORKS)
  {
    size_t len;
    int f;

    SSH_DEBUG(SSH_D_MIDOK, ("Starting read from %s", UNIX_ENTROPY_SOURCE));

    f = open(UNIX_ENTROPY_SOURCE, O_RDONLY);

    if (f == -1)
      {
        SSH_DEBUG(SSH_D_FAIL, ("Opening %s failed", UNIX_ENTROPY_SOURCE));
        return FALSE;
      }

    /* Set the descriptor into non-blocking mode. */
#if defined(O_NONBLOCK) && !defined(O_NONBLOCK_BROKEN)
    (void)fcntl(f, F_SETFL, O_NONBLOCK);
#else /* O_NONBLOCK && !O_NONBLOCK_BROKEN */
    (void)fcntl(f, F_SETFL, O_NDELAY);
#endif /* O_NONBLOCK && !O_NONBLOCK_BROKEN */

    if (return_buffer_size > MAX_ENTROPY_RETURN_SIZE)
      len = MAX_ENTROPY_RETURN_SIZE;
    else
      len = return_buffer_size;

    len = read(f, return_buffer, len);
    close(f);

    if (len > 0)
      {
        *returned_bytes = len;
      }
    else
      {
        SSH_DEBUG(SSH_D_FAIL, ("Read from %s failed",
                               UNIX_ENTROPY_SOURCE));
        *returned_bytes = 0;
        return FALSE;
      }
  }
#endif /* !WIN32 && !VXWORKS */

#ifdef WIN32
  /* additional noise on Windows */
  {
    HCRYPTPROV provider;

    if (CryptAcquireContext(&provider, NULL, NULL,
                            PROV_RSA_FULL, CRYPT_SILENT) ||
        CryptAcquireContext(&provider, NULL, NULL,
                            PROV_RSA_FULL, CRYPT_SILENT | CRYPT_NEWKEYSET))
      {
        size_t len;

        if (return_buffer_size > MAX_ENTROPY_RETURN_SIZE)
          len = MAX_ENTROPY_RETURN_SIZE;
        else
          len = return_buffer_size;

        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Using MS RSA CSP's random number generator to "
                   "generate additional random noise"));

        if (CryptGenRandom(provider, len, return_buffer))
          {
            *returned_bytes = len;
          }
        else
          {
            SSH_DEBUG(SSH_D_FAIL, ("CryptGenRandom call failed"));
            *returned_bytes = 0;
            return FALSE;
          }

        CryptReleaseContext(provider, 0);
      }
    else
      {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Failed to acquire CSP context (error = 0x%08X)",
                   GetLastError()));
        return FALSE;
      }
  }
#endif /* WIN32 */

  if (*returned_bytes == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get entropy"));
      return FALSE;
    }
  else
    {
      *returned_entropy = *returned_bytes * ESTIMATED_ENTROPY_BITS_PER_BYTE;

      SSH_DEBUG(SSH_D_LOWSTART,
                ("Got %d bytes, estimated entropy bits %d",
                 *returned_bytes, *returned_entropy));
      return TRUE;
    }
}

/* Utility macros */
#define NOISE_ADD_BYTE(B)                                       \
  do {                                                          \
    return_buffer[buffer_index++ % return_buffer_size] ^= (B);  \
  } while (0)

#define NOISE_ADD_WORD(W)                       \
  do {                                          \
    SshUInt32 __w = (W);                        \
    NOISE_ADD_BYTE(__w & 0xff);                 \
    NOISE_ADD_BYTE((__w & 0xff00) >> 8);        \
    NOISE_ADD_BYTE((__w & 0xff0000) >> 16);     \
    NOISE_ADD_BYTE((__w & 0xff000000) >> 24);   \
  } while (0)

Boolean ssh_get_system_noise(unsigned char *return_buffer,
                             size_t return_buffer_size,
                             size_t *returned_bytes,
                             size_t *returned_entropy)
{
  int buffer_index = 0;
  SshTime now = ssh_time();

  *returned_bytes = 0;
  *returned_entropy = 0;

#ifdef WIN32
  {
    LARGE_INTEGER ticks;

    if (QueryPerformanceCounter(&ticks))
      NOISE_ADD_WORD((SshUInt32) ticks.LowPart);
    else
      NOISE_ADD_WORD((SshUInt32)GetTickCount());

    NOISE_ADD_WORD((SshUInt32)_getpid());
    NOISE_ADD_WORD((SshUInt32)GetCurrentThreadId());
  }
#endif /* WIN32 */

  /* Get miscellaneous noise from various system parameters and statistics. */

  /* Add current time to noise pool. */
  NOISE_ADD_WORD((SshUInt32) now);

#ifdef HAVE_CLOCK
  NOISE_ADD_WORD((SshUInt32)clock());
#endif /* HAVE_CLOCK */
#ifdef HAVE_GETTIMEOFDAY
  {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    NOISE_ADD_WORD((SshUInt32)tv.tv_usec);
    NOISE_ADD_WORD((SshUInt32)tv.tv_sec);
  }
#endif /* HAVE_GETTIMEOFDAY */
#ifdef HAVE_TIMES
  {
    struct tms tm;
    NOISE_ADD_WORD((SshUInt32)times(&tm));
    NOISE_ADD_WORD((SshUInt32)(tm.tms_utime ^
                               (tm.tms_stime << 8) ^
                               (tm.tms_cutime << 16) ^
                               (tm.tms_cstime << 24)));
  }
#endif /* HAVE_TIMES */
#ifdef HAVE_GETRUSAGE
  {
    struct rusage ru, cru;
    getrusage(RUSAGE_SELF, &ru);
    getrusage(RUSAGE_CHILDREN, &cru);

    NOISE_ADD_WORD((SshUInt32)(ru.ru_utime.tv_usec +
                               cru.ru_utime.tv_usec));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_stime.tv_usec +
                               cru.ru_stime.tv_usec));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_maxrss + cru.ru_maxrss));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_ixrss + cru.ru_ixrss));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_idrss + cru.ru_idrss));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_minflt + cru.ru_minflt));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_majflt + cru.ru_majflt));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_nswap + cru.ru_nswap));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_inblock + cru.ru_inblock));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_oublock + cru.ru_oublock));
    NOISE_ADD_WORD((SshUInt32)((ru.ru_msgsnd ^ ru.ru_msgrcv ^
                                ru.ru_nsignals) +
                               (cru.ru_msgsnd ^ cru.ru_msgrcv ^
                                cru.ru_nsignals)));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_nvcsw + cru.ru_nvcsw));
    NOISE_ADD_WORD((SshUInt32)(ru.ru_nivcsw + cru.ru_nivcsw));
  }
#endif /* HAVE_GETRUSAGE */
#if !defined(WINDOWS) && !defined(DOS)
#ifdef HAVE_GETPID
  NOISE_ADD_WORD((SshUInt32)getpid());
#endif /* HAVE_GETPID */
#ifdef HAVE_GETPPID
  NOISE_ADD_WORD((SshUInt32)getppid());
#endif /* HAVE_GETPPID */
#ifdef HAVE_GETUID
  NOISE_ADD_WORD((SshUInt32)getuid());
#endif /* HAVE_GETUID */
#ifdef HAVE_GETGID
  NOISE_ADD_WORD((SshUInt32)(getgid()));
#endif /* HAVE_GETGID */
#ifdef HAVE_GETPGRP
  NOISE_ADD_WORD((SshUInt32)getpgrp());
#endif /* HAVE_GETPGRP */
#endif /* !WINDOWS && !DOS */
#ifdef _POSIX_CHILD_MAX
  NOISE_ADD_WORD((SshUInt32)(_POSIX_CHILD_MAX << 16));
#endif /* _POSIX_CHILD_MAX */
#if defined(CLK_TCK) && !defined(WINDOWS) && !defined(DOS)
  NOISE_ADD_WORD((SshUInt32)(CLK_TCK << 16));
#endif /* CLK_TCK && !WINDOWS && !DOS */

#ifdef SSH_TICKS_READ64
  {
    SshUInt64 tick;
    SSH_TICKS_READ64(tick);
    NOISE_ADD_WORD((tick >> 32) & 0xfffffff);
    NOISE_ADD_WORD(tick & 0xffffff);
  }
#else /* !SSH_TICKS_READ64 */
#ifdef SSH_TICKS_READ32
  {
    SshUInt32 tick;
    SSH_TICKS_READ32(tick);
    NOISE_ADD_WORD(tick);
  }
#endif /* SSH_TICKS_READ32 */
#endif /* SSH_TICKS_READ64 */

  {
    unsigned char entropy[32];
    size_t entropy_return;
    int i;

    if (!ssh_get_system_entropy(entropy, 32,
                                &entropy_return,
                                returned_entropy))
      {
        SSH_DEBUG(SSH_D_FAIL, ("Failed to get system entropy"));
        return FALSE;
      }

    for (i = 0; i < entropy_return; i++)
      NOISE_ADD_BYTE(entropy[i]);
  }

  /* Check if noise pool was filled up. */
  if (buffer_index > return_buffer_size)
    buffer_index = return_buffer_size;

  *returned_bytes = buffer_index;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Got %d bytes of noise with %d bits of entropy",
             *returned_bytes, *returned_entropy));

  return TRUE;
}
#undef NOISE_ADD_BYTE
#undef NOISE_ADD_WORD

