/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   General small utilities which are yet too long to be written again every
   time.
*/

#ifndef SSHGENUTILSH
#define  SSHGENUTILSH

/* String handling stuff **************************************************/


/* Extracts a substring from a string. Substrings are limited with delimiter
   char. Function returns substring specified in occurance parameter. The
   offset of the first substring. Function allocates enough memory for the
   return string. User gives a pointer to uninitialized string pointer as
   a parameter.
*/
char *ssh_str_extract(const char *source,
                      char **target,
                      char delimiter,
                      int occurence);



/* non classified ********************************************************/

/* Waits the given time in microseconds. Uses ssh_time_measure.
   This function waits in busy loop, in order to prevent event loop
   from continuing while waiting.  USE THIS FUNCTION CAREFULLY!!!*/

void ssh_busy_wait_usec(const SshUInt64 time_us);

/* Generate a `name string' from the binary buffer.  The returned
   string consisits of user provided string and an arbitrary
   hash value calculated from the binary buffer and encoded as
   a hex string.  The hash value IS NOT cryptorgaphically safe
   and it DOES leak information about the buffer.  Neither is
   it collision free. */

char *ssh_generate_name_from_buffer(const char *name,
                                    const unsigned char *blob,
                                    size_t bloblen);


#endif /* SSHGENUTILSH */
