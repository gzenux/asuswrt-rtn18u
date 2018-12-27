/**
   @copyright
   Copyright (c) 2012 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   FL-Hash - Public definitions for hash algorithms using FIPS Library.
*/

#ifndef FL_HASH_H
#define FL_HASH_H

/* Make the SHA1 defining structures visible everywhere. */
extern const SshHashDefStruct fl_hash_sha_def;
extern const SshHashDefStruct fl_hash_sha_96_def;
extern const SshHashDefStruct fl_hash_sha_80_def;


/* Make the SHA-256 defining structures visible everywhere. */
extern const SshHashDefStruct fl_hash_sha256_def;
extern const SshHashDefStruct fl_hash_sha256_128_def;
extern const SshHashDefStruct fl_hash_sha256_96_def;
extern const SshHashDefStruct fl_hash_sha256_80_def;
/* Make the SHA-224 defining structure visible everywhere. */
extern const SshHashDefStruct fl_hash_sha224_def;


/* Make the SHA-512 defining structure visible everywhere. */
extern const SshHashDefStruct fl_hash_sha512_def;
/* Make the SHA-384 defining structure visible everywhere. */
extern const SshHashDefStruct fl_hash_sha384_def;

#endif /* FL_HASH_H */
