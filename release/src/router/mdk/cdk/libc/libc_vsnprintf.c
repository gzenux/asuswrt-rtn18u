/*
 * $Id: libc_vsnprintf.c,v 1.6 Broadcom SDK $
 * $Copyright: Copyright 2013 Broadcom Corporation.
 * This program is the proprietary software of Broadcom Corporation
 * and/or its licensors, and may only be used, duplicated, modified
 * or distributed pursuant to the terms and conditions of a separate,
 * written license agreement executed between you and Broadcom
 * (an "Authorized License").  Except as set forth in an Authorized
 * License, Broadcom grants no license (express or implied), right
 * to use, or waiver of any kind with respect to the Software, and
 * Broadcom expressly reserves all rights in and to the Software
 * and all intellectual property rights therein.  IF YOU HAVE
 * NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE
 * IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE
 * ALL USE OF THE SOFTWARE.  
 *  
 * Except as expressly set forth in the Authorized License,
 *  
 * 1.     This program, including its structure, sequence and organization,
 * constitutes the valuable trade secrets of Broadcom, and you shall use
 * all reasonable efforts to protect the confidentiality thereof,
 * and to use this information only in connection with your use of
 * Broadcom integrated circuit products.
 *  
 * 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS
 * PROVIDED "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
 * REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
 * DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
 * ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
 * OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
 * 
 * 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL
 * BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL,
 * INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER
 * ARISING OUT OF OR IN ANY WAY RELATING TO YOUR USE OF OR INABILITY
 * TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF
 * THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR USD 1.00,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 *
 * CDK libc printf function implementations.
 */

#include <cdk/cdk_string.h>
#include <cdk/cdk_printf.h>

/*
 * Reasonably complete subset of ANSI-style printf routines.
 * Needs only strlen and stdarg.
 * Behavior was regressed against Solaris printf(3s) routines (below).
 *
 * Supported format controls:
 *
 *      %%      percent sign
 *      %c      character
 *      %d      integer
 *      %hd     short integer
 *      %ld     long integer
 *      %u      unsigned integer
 *      %o      unsigned octal integer
 *      %x      unsigned hexadecimal integer (lowercase)
 *      %X      unsigned hexadecimal integer (uppercase)
 *      %s      string
 *      %p      pointer
 *      %n      store number of characters output so far
 *
 * Flag modifiers supported:
 *      Field width, argument field width (*), left justify (-),
 *      zero-fill (0), alternate form (#), always include sign (+),
 *      space before positive numbers (space).
 *
 * Functions implemented:
 *
 * int vsnprintf(char *buf, size_t bufsize, const char *fmt, va_list ap);
 * int vsprintf(char *buf, const char *fmt, va_list ap);
 * int vprintf(const char *fmt, va_list ap);
 * int snprintf(char *buf, size_t bufsize, const char *fmt, ...);
 * int sprintf(char *buf, const char *fmt, ...);
 * int printf(const char *fmt, ...);
 *
 * Note that some functions are implemented in separate source files.
 */
static void
_itoa(char *buf,        /* Large enough result buffer   */
      uint32_t num,      /* Number to convert            */
      int base,         /* Conversion base (2 to 16)    */
      int caps,         /* Capitalize letter digits     */
      int prec)         /* Precision (minimum digits)   */
{
    char                tmp[36], *s, *digits;

    digits = (caps ? "0123456789ABCDEF" : "0123456789abcdef");

    s = &tmp[sizeof (tmp) - 1];

    for (*s = 0; num || s == &tmp[sizeof (tmp) - 1]; num /= base, prec--) {
        *--s = digits[num % base];
    }

    while (prec-- > 0) {
        *--s = '0';
    }

    CDK_STRCPY(buf, s);
}

#define X_STORE(c) {    \
    if (bp < be) {      \
        *bp = (c);      \
    }                   \
    bp++;               \
}

#define X_INF           CDK_VSNPRINTF_X_INF

int 
cdk_vsnprintf(char *buf, size_t bufsize, const char *fmt, va_list ap)
{
    char c, *bp, *be;
    char *p_null = NULL;
    char *b_inf = p_null - 1;

    bp = buf;
    be = (bufsize == X_INF) ? b_inf : &buf[bufsize - 1];

    while ((c = *fmt++) != 0) {
        int  width = 0, ljust = 0, plus = 0, space = 0;
        int  altform = 0, prec = 0, half = 0, base = 0;
        int  tlong = 0, fillz = 0, plen, pad;
        long num = 0;
        char tmp[36], *p = tmp;

        if (c != '%') {
            X_STORE(c);
            continue;
        }

        for (c = *fmt++; ; c = *fmt++)
            switch (c) {
            case 'h': half = 1;         break;
            case 'l': tlong = 1;        break;
            case '-': ljust = 1;        break;
            case '+': plus = 1;         break;
            case ' ': space = 1;        break;
            case '0': fillz = 1;        break;
            case '#': altform = 1;      break;
            case '*': width = -1;       break;  /* Mark as need-to-fetch */
            case '.':
                if ((c = *fmt++) == '*')
                    prec = -1;                  /* Mark as need-to-fetch */
                else {
                    for (prec = 0; c >= '0' && c <= '9'; c = *fmt++)
                        prec = prec * 10 + (c - '0');
                    fmt--;
                }
                break;
            default:
                if (c >= '1' && c <= '9') {
                    for (width = 0; c >= '0' && c <= '9'; c = *fmt++)
                        width = width * 10 + (c - '0');
                    fmt--;
                } else
                    goto break_for;
                break;
            }
    break_for:

        if (width == -1)
            width = va_arg(ap,int);
        if (prec == -1)
            prec = va_arg(ap,int);

        if (c == 0)
            break;

        switch (c) {
        case 'd':
        case 'i':
            num = tlong ? va_arg(ap, long) : va_arg(ap, int);
            if (half)
                num = (int) (short) num;
            /* For zero-fill, the sign must be to the left of the zeroes */
            if (fillz && (num < 0 || plus || space)) {
                X_STORE(num < 0 ? '-' : space ? ' ' : '+');
                if (width > 0)
                    width--;
                if (num < 0)
                    num = -num;
            }
            if (! fillz) {
                if (num < 0) {
                    *p++ = '-';
                    num = -num;
                } else if (plus)
                    *p++ = '+';
                else if (space)
                    *p++ = ' ';
            }
            base = 10;
            break;
        case 'u':
            num = tlong ? va_arg(ap, long) : va_arg(ap, int);
            if (half)
                num = (int) (short) num;
            base = 10;
            break;
        case 'p':
            altform = 0;
            /* Fall through */
        case 'x':
        case 'X':
            num = tlong ? va_arg(ap, long) : va_arg(ap, int);
            if (half)
                num = (int) (unsigned short) num;
            if (altform) {
                prec += 2;
                *p++ = '0';
                *p++ = c;
            }
            base = 16;
            break;
        case 'o':
        case 'O':
            num = tlong ? va_arg(ap, long) : va_arg(ap, int);
            if (half)
                num = (int) (unsigned short) num;
            if (altform) {
                prec++;
                *p++ = '0';
            }
            base = 8;
            break;
        case 's':
            p = va_arg(ap,char *);
            if (prec == 0)
                prec = X_INF;
            break;
        case 'c':
            p[0] = va_arg(ap,int);
            p[1] = 0;
            prec = 1;
            break;
        case 'n':
            *va_arg(ap,int *) = bp - buf;
            p[0] = 0;
            break;
        case '%':
            p[0] = '%';
            p[1] = 0;
            prec = 1;
            break;
        default:
            X_STORE(c);
            continue;
        }

        if (base != 0) {
            _itoa(p, (unsigned int) num, base, (c == 'X'), prec);
            if (prec)
                fillz = 0;
            p = tmp;
            prec = X_INF;
        }

        if ((plen = CDK_STRLEN(p)) > prec)
            plen = prec;

        if (width < plen)
            width = plen;

        pad = width - plen;

        while (! ljust && pad-- > 0)
            X_STORE(fillz ? '0' : ' ');
        for (; plen-- > 0 && width-- > 0; p++)
            X_STORE(*p);
        while (pad-- > 0)
            X_STORE(' ');
    }

    if ((be == b_inf) || (bp < be))
        *bp = 0;
    else {
        /* coverity[var_deref_op] */
        *be = 0;
    }

    return (bp - buf);
}
