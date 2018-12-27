/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Misc string functions.
*/

#ifndef SSHMISCSTRING_H
#define SSHMISCSTRING_H
/*
 * Allocates a new string concatenating the NULL
 * terminated strings s1 and s2.  NULL pointer is translated to
 * empty string.
 */
char *ssh_string_concat_2(const char *s1, const char *s2);

/*
 * Allocates a new string concatenating the NULL
 * terminated strings s1, s2 and s3.  NULL pointer is translated to
 * empty string.
 */
char *ssh_string_concat_3(const char *s1, const char *s2, const char *s3);

/*
 * Allocates a new string where all instances of
 * substring src in string str are replaced with substring dst.
 */
char *ssh_replace_in_string(const char *str, const char *src, const char *dst);

/*
 * Like strlen, but if the string is longer than `len' return len.
 */
size_t ssh_strnlen(const char *str, size_t len);
size_t ssh_ustrnlen(const unsigned char *str, size_t len);

/*
 * Pretty print numbers using kilo/mega etc abbrevs to `buffer'. The resulting
 * string is at maximum 3 numbers + letter (kMGTPE) + null, so the buffer must
 * be large enough to hold at least 5 characters. Scale can be either 1024, or
 * 1000, and it will specify if the kMGTPE are for 2^10 or for 10^3 multiples.
 */
unsigned char *ssh_format_number(unsigned char *buffer, size_t len,
                        SshUInt64 number, int scale);

/*
 * Pretty print numbers using kilo/mega etc abbrevs as snprintf renderer. The
 * resulting string is at maximum 3 numbers + letter (kMGTPE) + null, so the
 * buffer must be large enough to hold at least 5 characters. Scale is given in
 * the precision field, and it can be either 1024, or 1000, and it will specify
 * if the kMGTPE are for 2^10 or for 10^3 multiples. If it is omitted, then
 * 1024 is used. Datums is pointer to SshUInt64.
 */
int ssh_format_number64_render(unsigned char *buf, int buf_size, int precision,
                               void *datum);

/*
 * Pretty print numbers using kilo/mega etc abbrevs as snprintf renderer. The
 * resulting string is at maximum 3 numbers + letter (kMGTPE) + null, so the
 * buffer must be large enough to hold at least 5 characters. Scale is given in
 * the precision field, and it can be either 1024, or 1000, and it will specify
 * if the kMGTPE are for 2^10 or for 10^3 multiples. If it is omitted, then
 * 1024 is used. Datums is pointer to SshUInt32.
 */
int ssh_format_number32_render(unsigned char *buf, int buf_size, int precision,
                               void *datum);

/*
 * Pretty print time using 23:59:59, 999+23:59, 99999+23, 99999999 format to
 * the `buffer'. Suitable for printing time values from few seconds up to
 * years. The output string at maximum of 9 charcaters, so the buffer must be
 * large enough to hold at least 9 characters.
 */
unsigned char *ssh_format_time(unsigned char *buffer, size_t len, SshTime t);

/*
 * Pretty print time using 23:59:59, 999+23:59, 99999+23, 99999999 format as
 * snprintf renderer. Suitable for printing time values from few seconds up to
 * years. The output string at maximum of 9 charcaters, so the buffer must be
 * large enough to hold at least 9 characters. The datum is pointer to
 * SshTime.
 */
int ssh_format_time_render(unsigned char *buf, int buf_size, int precision,
                           void *datum);

/*
 * Pretty print time using 23:59:59, 999+23:59, 99999+23, 99999999 format as
 * snprintf renderer. Suitable for printing time values from few seconds up to
 * years. The output string at maximum of 9 charcaters, so the buffer must be
 * large enough to hold at least 9 characters. The datum is pointer to
 * SshUInt32.
 */
int ssh_format_time32_render(unsigned char *buf, int buf_size, int precision,
                             void *datum);

/*
 * Pretty print time using 23:59:59, 999+23:59, 99999+23, 99999999 format as
 * snprintf renderer. Suitable for printing time values from few seconds up to
 * years. The output string at maximum of 9 charcaters, so the buffer must be
 * large enough to hold at least 9 characters. The datum is pointer to
 * unsigned char * pointing to buffer having the number in network byte order.
 */
int ssh_format_time32buf_render(unsigned char *buf, int buf_size,
                                int precision, void *datum);

/* Get mallocated data from a string. Component identifies which part
 * of data to get.  The source string is assumed to be in format
 * "component1(component1_data), component2(component2_data)".  The
 * function handles parentheses correctly inside the component data.
 *
 * Occurance identifies which occurance of the data to get, 0 giving
 * the first occurance.
 *
 * Returns NULL, if the component is not found in the string and an empty
 * string, if the component is empty.  */
char *ssh_get_component_data_from_string(const char *source,
                                         const char *component,
                                         SshUInt32 occurance);


/* Free an array of strings. The strings of the array are freed individually
 * using ssh_xfree and the list is freed at last.
 */
void ssh_str_array_free(char **list, SshUInt32 num_items);

/* Text render function, which will convert all control etc characters to hex.
   The length of the string is given in the precision, or if it is -1 then use
   the strlen of buffer. Datums is unsigned char * which points to the string
   to be printed. */
int ssh_safe_text_render(unsigned char *buf, int buf_size, int precision,
                         void *datum);

/* Hex render function, which print the buffer in hex. The length of the string
   is given in the precision, or if it is -1 then use the strlen of buffer.
   Datums is unsigned char * which points to the string to be printed. */
int ssh_hex_render(unsigned char *buf, int buf_size, int precision,
                   void *datum);

/* SshUInt32 array render, which renders the numbers in hex
   if the precision is negative, and otherwise in decimal.
   The number of items in the array is taken from then
   precision. */
int ssh_uint32_array_render(unsigned char *buf, int buf_size, int precision,
                            void *datum);

/* SshUInt32 bitmap renderer. Renders a SshUInt32 bitmask field as a comma
   separated list of symbolic names. The string of symbolic names is in 'buf'
   and the length of the string is given in 'precision'. */
int ssh_uint32_bm_render(unsigned char *buf, int buf_size, int precision,
                         void *datum);

#endif /* SSHMISCSTRING_H */
/* eof (sshmiscstring.h) */
