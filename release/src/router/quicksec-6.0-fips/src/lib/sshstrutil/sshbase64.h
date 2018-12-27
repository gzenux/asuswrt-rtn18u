/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions to convert to and from base64.
*/

#ifndef SSHBASE64_H
#define SSHBASE64_H

/* Figure out whether this buffer contains base64 data. Returns number
   of base64 characters. */
size_t ssh_is_base64_buf(const unsigned char *buf, size_t buf_len);

/* Convert to and from base64 representation. */

/* Convert data from binary to format to base 64 format. Returns null
   terminated xmallocated string. */
unsigned char *ssh_buf_to_base64(const unsigned char *buf, size_t buf_len);

/* Convert data from base64 format to binary. Returns xmallocated data
   buffer and length in buf_len. */
unsigned char *ssh_base64_to_buf(const unsigned char *str, size_t *buf_len);

/* Remove unneeded whitespace (everything that is not in base64!).
   Returns new xmallocated string containing the string. If len is 0
   use strlen(str) to get length of data. */
unsigned char *ssh_base64_remove_whitespace(const unsigned char *str,
                                            size_t len);

/* Removes headers/footers (and other crud) before and after the
   base64-encoded data.  Pointer to the string is supplied in str and
   length in len. Stores the starting and ending indexes of the
   base64-data to start_ret and end_ret and returns TRUE if
   successful. In case of an error, returns FALSE. Will not modify
   the contents of str. */
Boolean ssh_base64_remove_headers(const unsigned char *str, size_t len,
                                  size_t *start_ret, size_t *end_ret);

#endif /* SSHBASE64_H */
