/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header file for the generic accelerator provider. This provides interface
   code between the externalkey API and accelerated devices configured in
   genaccprov.h. The devices configured in genaccprov.h accelerate the
   modular exponentation operation and optionally return random bytes from
   the device.

   An initialization information string should be provided to the externalkey
   API using the function call ssh_ek_add_provider. For this provider it
   should be a comma-separated list of entries using the format
   "keyword(value)". Currently defined keywords include:

   name()             The name by which the accelerated device is known as.

   device-info()      Use this to pass any other device specific information
                      to the SshAccDeviceInit function in the SshAccDeviceDef
                      object (see genaccprov.h).

   initialize-using-message (yes/no) If "yes", the device initialization is
                      delayed until a message has been passed to the
                      provider, using ssh_ek_send_message(). The message
                      string should be "Initializing Message" and
                      'message_arg' a void pointer that is passed to the
                      SshAccDeviceInit function (the extra_args parameter)
                      in the SshAccDeviceDef object (see genaccprov.h).

                      If "no", the device initialization is performed
                      immediately after ssh_ek_add_provider() is called.

    rsa-crt (yes/no) If "yes", RSA private key operations are performed using
                     the CRT (Chinese Remainder Theorem). This will delegate
                     two modexp operations to the accelerator for each RSA
                     private key operation. This should result in better
                     performance, but will also cause less offloading
                     to the accelerator, as some work is performed in
                     software to patch the two CRT computations together.

                     The default is "yes".


   e.g. "name(hifn-hsp),initialize_using_message(yes)"

   This provider currently supports the externalkey API functions,

   ssh_ek_generate_accelerated_private_key(),
   ssh_ek_generate_accelerated_public_key(),
   ssh_ek_generate_accelerated_group(),

   for generating accelerated keys and groups. To generate an accelerated
   key/group, the relevant unaccelerated (software) SshPrivateKey,
   SshPublicKey or SshPkGroup should first be generated in the crypto
   library, and then used to get the accelerated object.

   To generate a public/private key pair, first generate an SshPrivateKey,
   from that get the SshPublicKey, using the crypto library API function
   ssh_private_key_derive_public_key(). Then derive the accelerated
   private key from the SshPrivateKey and the accelerated public key
   from the SshPublicKey.

   Once the accelerated key/group has been generated, the unaccelerated
   key/group may be safely freed from memory.

   If the device has a hardware random number generator, random bytes
   may be obtained from the device by calling the ssh_ek_get_random_bytes
   function. For this to work the operation to retrieve the random bytes
   from the device must be defined in the SshAccDeviceExecute function in
   the SshAccDeviceDef object (see genaccprov.h).
*/

#ifndef GEN_ACC_PROVIDER_H
#define GEN_ACC_PROVIDER_H

#include "extkeyprov.h"

extern const struct SshEkProviderOpsRec ssh_ek_gen_acc_ops;

#endif /* GEN_ACC_PROVIDER_H */


