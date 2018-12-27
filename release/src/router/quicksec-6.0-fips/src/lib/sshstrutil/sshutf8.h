/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Character set conversion routines. Complies with draft-yergeay-utf8-01.txt,
   (which will obsolete RFC 2044, the current UTF-8 spec).
*/

#ifndef SSHUTF8_H
#define SSHUTF8_H

/* character sets */

#define SSH_CHARSET_UNKNOWN         0    /* encoding is unknown (not used) */
#define SSH_CHARSET_USASCII         1    /* 7-bit US-ASCII */
#define SSH_CHARSET_ISO_LATIN_1     2    /* 8-bit ISO-8859-1 encoding */
#define SSH_CHARSET_UTF8            3    /* UTF-8 encoding */
#define SSH_CHARSET_UNICODE16       4    /* UCS-2 (16 bit unicode) in
                                            native byteorder */
#define SSH_CHARSET_UNICODE16_LBO   5    /* UCS-2 (16 bit unicode) in
                                            little endian byte order */
#define SSH_CHARSET_UNICODE16_NBO   6    /* UCS-2 in network byte order */
#define SSH_CHARSET_UNICODE32       7    /* UCS-4 (32 bit unicode) in
                                            native byteorder */
#define SSH_CHARSET_UNICODE32_LBO   8    /* UCS-4 in little endian byte
                                            order */
#define SSH_CHARSET_UNICODE32_NBO   9    /* UCS-4 in network byte order */


#define SSH_CHARSET_FIRST           SSH_CHARSET_USASCII
#define SSH_CHARSET_LAST            SSH_CHARSET_UNICODE32_NBO

/* A datatype for expressing character set encodings */
typedef int SshCharsetEncoding;

/* SshUCS4Char can hold characters of any type */
typedef unsigned int SshChUCS4;

/* An unknown character */
#define SSH_CHARACTER_UNKNOWN 0xffffffff

/* the context type */
typedef struct SshChrConvRec *SshChrConv;

/* Initialize a context for charset conversion
   (this way the conversion can be done in parts).
   Returns NULL on failure. */

SshChrConv ssh_charset_init(SshCharsetEncoding input_encoding,
                            SshCharsetEncoding output_encoding);

/* Free the charset conversion context */

void ssh_charset_free(SshChrConv ctx);


/* Convert max. input_len bytes starting from input_buf. The output is
   written to output_buf which is an array capable of holding
   output_max bytes. The actual number of bytes written is returned.

   Note that the conversion module keeps internal state about the
   conversion. If the input buffer did not contain enough data for
   decoding one character, the amount of data consumed (and the
   consumed data itself) is stored in the SshChrConv. The next time
   you call this function, it will continue processing assuming that
   the input is data following the already consumed (and stored) data.

   This function can not fail. */

size_t ssh_charset_convert(SshChrConv ctx,
                           void *input_buf, size_t input_len,
                           void *output_buf, size_t output_max);

/* Get the number of bytes of the input consumed in the latest
   operation. */
size_t ssh_charset_input_consumed(SshChrConv ctx);

#endif /* SSHUTF8_H */
