/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Crypto library monitoring, header for internal use.
*/

#ifndef LIBMONITOR_H
#define LIBMONITOR_H

/* The internal progress monitor function, which shall call the
   application supplied callback function. SshCryptoProgressID is
   defined in sshcrypt.h and time_value is an increasing counter
   indicating that library is working. */

void ssh_crypto_progress_monitor(SshCryptoProgressID id,
                                 unsigned int time_value);

#endif /* LIBMONITOR_H */
