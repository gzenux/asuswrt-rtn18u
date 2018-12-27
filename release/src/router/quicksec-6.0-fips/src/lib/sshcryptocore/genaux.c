/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"

/* Returns the string representation of the error returned (in English). */
const char *
ssh_crypto_status_message(SshCryptoStatus status)
{
  switch (status)
    {
    case SSH_CRYPTO_OK:
      return "Operation was successful";
    case SSH_CRYPTO_LIBRARY_ERROR:
      return "Persistent error has occured";
    case SSH_CRYPTO_LIBRARY_UNINITIALIZED:
      return "The cryptographic library is uninitialized";
    case SSH_CRYPTO_LIBRARY_INITIALIZING:
      return "The cryptographic library not yet initialized";
    case SSH_CRYPTO_LIBRARY_OBJECTS_EXIST:
      return "Crypto objects exists";
    case SSH_CRYPTO_UNSUPPORTED:
      return "Algorithm or key not supported";
    case SSH_CRYPTO_UNSUPPORTED_IDENTIFIER:
      return "Identifier not supported";
    case SSH_CRYPTO_SCHEME_UNKNOWN:
      return "Scheme not supported";
    case SSH_CRYPTO_UNKNOWN_GROUP_TYPE:
      return "Group type given not recognized";
    case SSH_CRYPTO_UNKNOWN_KEY_TYPE:
      return "Key type given not recognized";
    case SSH_CRYPTO_DATA_TOO_SHORT:
      return "Insufficient data to perform this operation";
    case SSH_CRYPTO_DATA_TOO_LONG:
      return "Data is too long";
    case SSH_CRYPTO_BLOCK_SIZE_ERROR:
      return "Block cipher block size constraint violation";
    case SSH_CRYPTO_KEY_UNINITIALIZED:
      return "Key should have been initialized";
    case SSH_CRYPTO_CORRUPTED_KEY_FORMAT:
      return "Key format was corrupted";
    case SSH_CRYPTO_KEY_TOO_SHORT:
      return "Key is too short for the algorithm";
    case SSH_CRYPTO_KEY_TOO_LONG:
      return "The key is too long for this operation";
    case SSH_CRYPTO_KEY_INVALID:
      return "The supplied key is invalid";
    case SSH_CRYPTO_KEY_WEAK:
      return "The supplied key is weak";
    case SSH_CRYPTO_KEY_SIZE_INVALID:
      return "The supplied key size is invalid";
    case SSH_CRYPTO_INVALID_PASSPHRASE:
      return "Invalid passphrase";
    case SSH_CRYPTO_SIGNATURE_CHECK_FAILED:
      return "Signature check failed";
    case SSH_CRYPTO_OPERATION_FAILED:
      return "Operation failed";
    case SSH_CRYPTO_HASH_COMPARISON_FAILED:
      return "Hash comparison failed";
    case SSH_CRYPTO_NO_MEMORY:
      return "Out of memory";
    case SSH_CRYPTO_PROVIDER_SLOTS_EXHAUSTED:
      return "Provider not registered because no slots were available";
    case SSH_CRYPTO_TOKEN_MISSING:
      return "Token missing";
    case SSH_CRYPTO_PROVIDER_ERROR:
      return "Externalkey provider error";
    case SSH_CRYPTO_OPERATION_CANCELLED:
      return "Operation cancelled";
    case SSH_CRYPTO_INTERNAL_ERROR:
      return "Internal error";
    case SSH_CRYPTO_HANDLE_INVALID:
      return "The supplied handle is invalid";
    case SSH_CRYPTO_UNSUPPORTED_VERSION:
      return "The version requested is not supported";
    case SSH_CRYPTO_NO_MATCH:
      return "No match. Internal error code.";
    case SSH_CRYPTO_INVALID_OPERATION:
      return "Application used invalid operation or operation "
        "sequence, application error.";
    case SSH_CRYPTO_MATH_INIT:
      return "Failed to initialize the math library.";
    case SSH_CRYPTO_TEST_MATH:
      return "Self tests of the internal math library failed.";
    case SSH_CRYPTO_TEST_CIPHER:
      return "Cipher algorithm test failed during self test.";
    case SSH_CRYPTO_TEST_HASH:
      return "Hash algorithm test failed during self test.";
    case SSH_CRYPTO_TEST_MAC:
      return "Mac algorithm test failed during self test.";
    case SSH_CRYPTO_TEST_RNG:
      return "RNG algorithm test failed during self test.";
    case SSH_CRYPTO_TEST_INTEG_INVALID:
      return "The checksum of the library is incorrect. Integrity has been "
        "compromised.";
    case SSH_CRYPTO_TEST_INTEG_LOAD:
      return "Failed to find and load the external integrity checksum of "
        "the library.";
    case SSH_CRYPTO_TEST_INTEG_DIGEST:
      return "Failed to calculate an integrity checksum of the library.";
    case SSH_CRYPTO_TEST_PK:
      return "Public key algorithm test failed during self test.";
    default:
      return "Unknown error code";
    }
}

/* Version string of the library, returned by
   ssh_crypto_library_get_version(). */
#define SSH_CRYPTO_LIB_VERSION "SSH Cryptographic Library, version 1.2"

const char *
ssh_crypto_library_get_version(void)
{
  return SSH_CRYPTO_LIB_VERSION;
}
