/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Header file for sshsnprintf.c.

   <keywords snprintf, utility functions/snprintf>
*/

#ifndef SNPRINTF_H
#define SNPRINTF_H

#ifdef __cplusplus
extern "C" {
#endif


/** Type of functions that implement formatting `external' data types.

    `buf' is the buf where something should be written, `buf_size' the
    maximum number of characters that can be written. `precision' is
    either -1 or a non-negative number supplied by the user; its
    interpretation is chosen by the rendering function. `datum' is the
    actual value to render.

    The functions must return the number of characters written.

    If the renderer would have liked to write more characters than
    there was room in `buf_size', the renderer should return the value
    `buf_size' + 1 (but have written only `buf_size' characters, of
    course).

    As a relaxation, the functions ARE allowed to write the NUL byte
    at buf[buf_size], i.e. at the `buf_size'+1th character. However,
    this is not necessary and doing or doing not has no effect
    whatsoever. */

typedef int (*SshSnprintfRenderer)(unsigned char *buf, int buf_size,
                                   int precision, void *datum);

/** Write formatted text to buffer 'str', using format string 'format'.

    NOTE: This does NOT work identically with BSD's snprintf.

    Integers: Ansi C says that precision specifies the minimun number
    of digits to print. BSD's version however counts the prefixes (+,
    -, ' ', '0x', '0X', octal prefix '0'...) as 'digits'.

    Also, BSD implementation does not permit padding integers to
    specified width with zeros on left (in front of the prefixes), it
    uses spaces instead, even when Ansi C only forbids padding with
    zeros on the right side of numbers.

    This version can also be extended using %@, which takes
    SshSnprintfRenderer argument and void *, and calls that
    SshSnprintfRenderer function to render the actual data.

    Additionally, some versions consider running out of space an
    error; we do not, and instead return normally; this is consistent
    with C99 standard.

    @return
    Returns number of characters written, or negative if error
    occurred. Buffer's size is given in 'size'. Format string is
    understood as defined in ANSI C.

    */

int ssh_snprintf(unsigned char *str, size_t size, const char *format, ...)
       __ssh_printf_attribute__ ((format (printf, 3, 4)));
int ssh_vsnprintf(unsigned char *str, size_t size, const char *format,
                  va_list ap)
       __ssh_printf_attribute__ ((format (printf, 3, 0)));

#ifdef __cplusplus
}
#endif

#endif /* SNPRINTF_H */
