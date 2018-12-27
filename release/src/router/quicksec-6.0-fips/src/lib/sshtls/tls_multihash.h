/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   tls_multihash.h
*/

#ifndef TLS_MULTIHASH_INCLUDED
#define TLS_MULTIHASH_INCLUDED

#include "sshincludes.h"

#define SSH_TLS_MH_DELETED ((void *)1)

typedef struct ssh_tls_mhtab *SshTlsMultiHashTable;

/* Allocate a new hash table. */
SshTlsMultiHashTable ssh_tls_mh_allocate(void);

/* Free a hash table. */
void ssh_tls_mh_free(SshTlsMultiHashTable table);

/* Clear the hash table but do not free it. */
void ssh_tls_mh_clear(SshTlsMultiHashTable table);

/* Find all the data pointers that have been stored to the hash table
   with the key `key'. The return value is the number of values found,
   and `*ptr' is set to point to the beginning of a table that
   contains that number of void pointers, the values.

   The value returned remains valid until the hash table is cleared
   or the values associated with the `key' are changed. The pointer
   returned points to an internal structure of the hash table. */
int ssh_tls_mh_find(SshTlsMultiHashTable table,
                    const unsigned char *key, int key_len, void ***ptr);

/* Delete all the entries stored with the key `key'. */
void ssh_tls_mh_delete_all(SshTlsMultiHashTable table,
                           const unsigned char *key, int key_len);

/* Set the set of values associated with `key' to be the array that
   starts at `ptr' and has `array_size' elements.
   The caller-supplied array `ptr' can be invalidated after the
   function has been called.

   Partial overlap with a value returned from `ssh_tls_mh_find' is not
   allowed but total is.

   It is an error if there were no values associated with
   the given key.

   There is a special feature: those elements in the array that have
   the value SSH_TLS_MH_DELETED are removed from the array.  This can be
   used for selective deletion of values using the following idiom:

   num_values = ssh_tls_mh_find(tab, key, len, &ptr);
   for (i = 0; i < num_values; i++)
     {
       if (condition(ptr[i]))
         {
           ptr[i] = SSH_TLS_MH_DELETED;
         }
     }
   ssh_tls_mh_set(tab, key, len, ptr, num_values);

   */
void ssh_tls_mh_set(SshTlsMultiHashTable table,
                    const unsigned char *key, int key_len,
                    void **ptr, int array_size);


/* Add a single new value under the given key. This adds the value even
   it if already exists in the set of values associated with the key.

   In any case, `key' is copied internally. */
void ssh_tls_mh_add_nonuniq(SshTlsMultiHashTable table,
                            const unsigned char *key, int key_len,
                            void *ptr);

/* Similar, but add only if the value doesn't already exist. */
void ssh_tls_mh_add_uniq(SshTlsMultiHashTable table,
                         const unsigned char *key, int key_len,
                         void *ptr);

/* Similar to the two functions above, but add multiple values at a single
   shot. */
void ssh_tls_mh_add_multiple_nonuniq(SshTlsMultiHashTable table,
                                     const unsigned char *key, int key_len,
                                     void **ptr, int array_size);

/* This function also detects those multiply occurring values that
   occur many times in the array `*ptr' and handles them correctly. */
void ssh_tls_mh_add_multiple_uniq(SshTlsMultiHashTable table,
                                  const unsigned char *key, int key_len,
                                  void **ptr, int array_size);


#endif /* TLS_MULTIHASH_INCLUDED */
