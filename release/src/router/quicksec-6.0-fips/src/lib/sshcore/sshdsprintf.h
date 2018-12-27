/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Printing utility functions.

   <keywords printing, utility functions/printing>
*/

#ifndef SSHDSPRINTF_H
#define SSHDSPRINTF_H

/** This function is similar to snprintf (indeed, this function, too,
    uses vsnprintf()); it takes a format argument which specifies the
    subsequent arguments, and writes them to a string using the
    format-string. This function differs from snprintf in that this
    allocates the buffer itself, and returns a pointer to the
    allocated string (in str). This function never fails.
    (If there is not enough memory, ssh_xrealloc() calls ssh_fatal().)

    @return
    The returned string must be freed by the caller. Returns the
    number of characters written.  */
int ssh_dsprintf(unsigned char **str, const char *format, ...)
     __ssh_printf_attribute__ ((format (printf, 2, 3)));

/** This function is similar to snprintf (indeed, this function, too,
    uses vsnprintf()); it takes a format argument which specifies the
    subsequent arguments, and writes them to a string using the
    format-string. This function differs from snprintf in that this
    allocates the buffer itself, and returns a pointer to the
    allocated string (in str). This function never fails.
    (If there is not enough memory, ssh_xrealloc() calls ssh_fatal().)

    @return
    The returned string must be freed by the caller. Returns the
    number of characters written.  */
int ssh_dvsprintf(unsigned char **str, const char *format, va_list ap)
     __ssh_printf_attribute__ ((format (printf, 2, 0)));

/** Otherwise similar to the ssh_dsprintf function, but calls
    ssh_fatal() if memory allocation fails. */
int ssh_xdsprintf(unsigned char **str, const char *format, ...)
     __ssh_printf_attribute__ ((format (printf, 2, 3)));

/** Otherwise similar to the ssh_dvsprintf function, but calls
    ssh_fatal() if memory allocation fails. */
int ssh_xdvsprintf(unsigned char **str, const char *format, va_list ap)
     __ssh_printf_attribute__ ((format (printf, 2, 0)));

#endif /* SSHDSPRINTF_H */
