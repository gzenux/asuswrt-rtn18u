/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal interface for crypto library self-test functions.
*/

#ifndef SSH_CRYPTO_TESTS_H
#define SSH_CRYPTO_TESTS_H

/* Notice: All test functions return either TRUE for success or FALSE
   for failure. It is up to the caller to check the crypto library
   state after these calls, since the crypto library might end up in
   an error state during these tests. (Of course, during initiated
   tests any of these routines returning FALSE would mean that the
   caller should force the crypto library into error state).  */

/* Another note: These functions take the internal object type as
   arguments. They however must and don't assume that the object has a
   valid crypto handle attached to it. Thus you can pass objects which
   have no handles to these routines. */


#include "sshrandom_i.h"

#ifndef KERNEL
#include "sshpk_i.h"

/* Group consistency check. If the given group cannot support
   Diffie-Hellman, then this routine returns TRUE. Otherwise the
   following operations are performed:

   1. Creates a copy of the given group.
   2. Set up both groups (original and copy).
   3. Agree on boths groups (original and copy, setup values exchanged)
   4. Both shared secrets are compared.

   If any of the above steps fail, the test fails and returns FALSE,
   otherwise the test succeeds and returns TRUE.

   This test satisties the requirements of FIPS 140-2 "4.9.2
   Conditional Tests" for "Pair-wise consistency test (for key
   agreement)" . */
SshCryptoStatus
ssh_crypto_test_pk_group(SshPkGroupObject pk_group);

/* Private/public key encryption/decryption test. If the key type
   doesn't support encryption/decryption, this returns TRUE (test is
   passed). If the key type does support encryption/decryption, then
   the following operations are done:

   1. A known plaintext is encrypted using the private key.
   2. Ciphertext is compared to plaintext, and they must differ.
   3. Ciphertext is decrypted.
   4. Ciphertext is compared to the known plaintext value.

   (Additional consistency checks are performed during various test phases.)

   If any of the above steps fail, the test fails and returns FALSE,
   otherwise the test succeeds and returns TRUE.

   This test satisties the requirements of FIPS 140-2 "4.9.2
   Conditional Tests" for "Pair-wise consistency test (for encryption
   keys)" . */
SshCryptoStatus
ssh_crypto_test_pk_encrypt(SshPublicKeyObject public_key,
                           SshPrivateKeyObject priv_key);

/* Private/public key signature verification test. If the key type
   doesn't support signature operations, this function returns a TRUE
   value. Otherwise the following operations are done:

   1. A known plaintext value is signed using the private key.
   2. The signature is verified using the public key.

   If any of the above steps fail, the test fails and returns FALSE,
   otherwise the test succeeds and returns TRUE.

   This test satisties the requirements of FIPS 140-2 "4.9.2
   Conditional Tests" for "Pair-wise consistency test (for signature
   keys)" . */
SshCryptoStatus
ssh_crypto_test_pk_signature(SshPublicKeyObject public_key,
                             SshPrivateKeyObject priv_key);

/* Key pair consistency check. Runs encrypt and signature tests on the
   key, and returns FALSE if either failed, and TRUE if both
   succeeded. */
SshCryptoStatus
ssh_crypto_test_pk_consistency(SshPublicKeyObject public_key,
                               SshPrivateKeyObject priv_key);

/* Private key consistency test. This routine derives a public key
   from the private key, and runs encryption
   (ssh_crypto_test_pk_encrypt) and signature
   (ssh_crypto_test_pk_signature) tests on the private/public key
   pair. If either of the individual tests fail, or no public key can
   be derived, this test returns FALSE. Otherwise it returns TRUE. */
SshCryptoStatus
ssh_crypto_test_pk_private_consistency(SshPrivateKeyObject priv_key);

#endif /* !KERNEL */
#endif /* SSH_CRYPTO_TESTS_H */
