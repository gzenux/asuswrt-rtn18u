/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Example externalkey provider that works like a crypto
   accelerator.  The soft accelerator is added to the externalkey
   with the name "software". Flags should have
   SSH_EK_PROVIDER_FLAG_ACCELERATOR set if the applications
   wishes to use the software provider as an "accelerator".
   Initialization string should be a comma-separated list of
   entries using the format "keyword(value)". Currently defined
   keywords include:

   directory(<directory_name>)

   The softprovider will poll the specified directory and will
   notify about all found keys in the notification
   callback. The keys are scanned for in all given directories
   and the files which share the same base name (e.g foo and
   foo.pub) in the same directory are assumed to belong to the
   same private key. If at least one private key is found, the
   key is reported.

   Supported private key formats are all the ones that the prvkey.h
   from src/apputils supports. (SSH, X.509, SSH_1, SSH_2, PKSC1, PKCS8,
   PKCS#12).

   The public keys are imported from certificates or derived from
   private keys if they are not available as files.

   If the private key is in encrypted file, but the public key is
   available, then the key that is returned is "proxy key", which
   asks for the passphrase when the key is used.

   If the private key is encrypted and there is no public key, then
   the private key passphrase is queried when the key is asked from
   the externalkey.

   If the public key/certificate is available only in encrypted format
   (as in PKCS#12) then the passphrase is queried when the object is
   queried from externalkey.

   How often the directory is polled for keys can be adjusted using the
   polling_interval_ms keyword.

   polling_interval_ms(<time_ms>)

   Defines in milli seconds how often the directories given in
   initialization string are polled for keys.

   key_files(<key_spec>)

   The software provider will announce the key defined in <key_spec>
   using the notification callback. The init string may contain zero
   or more key_file keywords.

   The <key_spec> is a comma separated list of files, which must
   contain one private key, zero or more certificate files,
   and optionally one public key.

   Private key files must end with ".prv", certificates with ".crt"
   or ".crt?", where ? is a number. Public keys are assumed to end
   with ".pub". If there is no public keys, the softprovider will
   try to extract the public key from a certificate.

   Example:  key_files(foo.prv, foo.crt, foo.crt1, foo.crt2)

   async_time_ms(number)

   The software can simulate true asynchronous behavior. Number
   is the amount of time (in milliseconds) each operation
   should take.

   random_async_completion

   If this keyword is included, the provider completes only
   some requests asynchronously. This option is primarily for
   testing.

   use_proxy

   If this keyword is included, private keys are converted to
   proxy format which may be useful in certain situations.
   The default value is not to convert keys to proxy format.

   The provider understands a message "reset_pins", which removes
   all the cached keys from memory and forgets the cached
   passphrases. The reset_pin message does not take any
   arguments.

   This provider can also used for access keys that are not
   announced by te notification callback. The keypath may contain
   the following data elemtns:
   {prvkey|pubkey|cert}{file|data}. E.g the keypath:
   software://0/prvkeydata=<base64>?certdata=<base64> could be
   used to query private and public keys and a certificate.
   The keypath:
   software://0/prvkeyfile=filename?certfile=filename2 could be
   used to read the private key information from file.

   The soft accelerator provides the externalkey application
   a way to test accelerator functionality by adding an
   accelerator to a system and then using it in a way the real
   accelerators work.

   It also providers also an example of the following things:
   - how actual accelerators should be implemented.
   - how to add dynamic public key types to crypto library.
*/


#ifndef SOFTPROVIDER_H
#define SOFTPROVIDER_H

#include "extkeyprov.h"


/* This is the structure (provided by softprovider.c) that is used in
   sshexteralkey.c to get handles to software accelerator
   functions. See extkeyprov.h for details. */
extern struct SshEkProviderOpsRec ssh_ek_soft_ops;

#endif /* SOFTPROVIDER_H */
