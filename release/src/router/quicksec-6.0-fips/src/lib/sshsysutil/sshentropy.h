/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Get entropy from system source.
*/

/** Get system entropy, amount of entropy in the return buffer is
    not guaranteed to match return length but should be close to
    it.

    @return_buffer
    Buffer for the entropy

    @return_buffer_size
    Return buffer size

    @returned_bytes
    Size of the entropy inserted to buffer

    @returned_entropy
    Estimated bits of entropy in return buffer

    @return
    TRUE if operation was success
*/
Boolean ssh_get_system_entropy(unsigned char *return_buffer,
                               size_t return_buffer_size,
                               size_t *returned_bytes,
                               size_t *returned_entropy);


/** Get noise from various system resources and combine it with
    system entropy. Amount of entropy is not guaranteed.

    @return_buffer
    Buffer for the noise

    @return_buffer_size
    Return buffer size

    @returned_bytes
    Size of the noise inserted to buffer

    @returned_entropy
    Estimated bits of entropy in return buffer

    @return
    TRUE if operation was success
*/
Boolean ssh_get_system_noise(unsigned char *return_buffer,
                             size_t return_buffer_size,
                             size_t *returned_bytes,
                             size_t *returned_entropy);
