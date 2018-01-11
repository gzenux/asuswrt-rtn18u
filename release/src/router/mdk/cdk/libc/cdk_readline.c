/*
 * $Id: cdk_readline.c,v 1.7 Broadcom SDK $
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
 * Simple readline implmentation
 *
 * The terminal I/O functions are passed and parameters
 * and the calling application must ensure that the
 * terminal has buffering disabled, and that it does
 * not echo the input characters as they are typed.
 *
 * Below id a sample POSIX implementaion of proper
 * terminal setup:
 *
 * #include <termios.h>
 *
 * void tio_setup(void)
 * {
 *     struct termios tio;
 *
 *     if (tcgetattr(0, &tio) >= 0) {
 *         tio.c_lflag &= ~(ECHO | ICANON | ISIG);
 *         tio.c_iflag &= ~(ISTRIP | INPCK);
 *         tio.c_cc[VMIN] = 1;
 *         tio.c_cc[VTIME] = 0;
 *         tcsetattr(0, TCSADRAIN, &tio);
 *      }
 * }
 *
 * Note that the application should restore the
 * terminal settings before exiting.
 */

#include <cdk/cdk_readline.h>
#include <cdk/cdk_string.h>

/*
 * Escape sequences:
 *
 * Sequence             Descr   Emulator
 *
 * ESC [ A              UP      xterm
 * ESC [ B              DOWN    xterm
 * ESC [ C              RIGHT   xterm
 * ESC [ D              LEFT    xterm
 *
 * ESC [ F              HOME    xterm
 * ESC [ H              END     xterm
 *
 * ESC [ 2 ~            HOME    teraterm
 * ESC [ 5 ~            END     teraterm
 *
 */

#define VKEY(x)         (0x100|(x))
#define VKEY_UP         VKEY(1)
#define VKEY_DOWN       VKEY(2)
#define VKEY_LEFT       VKEY(3)
#define VKEY_RIGHT      VKEY(4)
#define VKEY_HOME       VKEY(5)
#define VKEY_END        VKEY(6)
#define VKEY_ESC        27

#define CTRL(_x) ((_x)-'@')

#ifndef RL_MAXSAVELINES
#define RL_MAXSAVELINES 32
#endif

#ifndef RL_MAXLINESIZE
#define RL_MAXLINESIZE  256
#endif

static int rl_nextsave = 0;
static char rl_savedlines[RL_MAXSAVELINES][RL_MAXLINESIZE];

static int (*rl_getchar)(void);
static int (*rl_putchar)(int);

#define GETCHAR(_x) do { _x = rl_getchar(); } while(0)
#define PUTCHAR(_x) rl_putchar(_x)

static void
rl_readnum(int *num, unsigned char *ch)
{
    int total = 0;

    for (;;) {
        total = (total * 10) + (*ch - '0');
        GETCHAR(*ch);
        if (!((*ch >= '0') && (*ch <= '9'))) break;
    }

    *num = total;
}

static int
rl_readkey(void)
{
    unsigned char ch;
    int num;

    GETCHAR(ch);

    switch (ch) {
    case VKEY_ESC:
        GETCHAR(ch);
        switch (ch) {
        case '[':
            GETCHAR(ch);
            if ((ch >= '0') && (ch <= '9')) {
                rl_readnum(&num, &ch);
                if (ch == '~') {
                    switch (num) {
                    case 2:
                        return VKEY_HOME;
                    case 5:
                        return VKEY_END;
                    default:
                        break;
                    }
                }
            }
            else {
                switch (ch) {
                case 'A':
                    return VKEY_UP;
                case 'B':
                    return VKEY_DOWN;
                case 'C':
                    return VKEY_RIGHT;
                case 'D':
                    return VKEY_LEFT;
                case 'F':
                    return VKEY_HOME;
                case 'H':
                    return VKEY_END;
                default:
                    break;
                }
            }
            break;
        default:
            break;
        }
    default:
        break;
    }
    return (int) ch;
}

static int
rl_write(unsigned char *buffer, int length)
{
    while (length > 0) {
        if (PUTCHAR(*buffer++) < 0) {
            return -1;
        }
        length--;
    }
    return 0;                    
}

static void
rl_backspace(int n)
{
    int t;

    for (t = 0; t < n; t++) rl_write((unsigned char *)"\b",1);
}

static void
rl_whiteout(int n)
{
    int t;

    for (t = 0; t < n; t++) rl_write((unsigned char *)" ",1);
    for (t = 0; t < n; t++) rl_write((unsigned char *)"\b",1);
}


static void
rl_eraseeol(void)
{
    rl_write((unsigned char *)"\033[K",3);
}

static void
rl_crlf(void)
{
    rl_write((unsigned char *)"\r\n",2);
}

char *
cdk_readline(int (*getchar_func)(void), int (*putchar_func)(int),
             const char *prompt, char *str, int maxlen)
{
    int reading = 1;
    int ch;
    int idx = 0;
    int len = 0;
    int t;
    int nosave = 0;
    int recall;

    rl_getchar = getchar_func;
    rl_putchar = putchar_func;

    if (rl_getchar == NULL || rl_putchar == NULL) {
        return str;
    }

    str[0] = 0;

    recall = rl_nextsave;

    if (rl_savedlines[rl_nextsave][0]) {
        rl_savedlines[rl_nextsave][0] = 0;
    }

    idx = len = CDK_STRLEN(str);

    if (prompt && *prompt) {
        rl_write((unsigned char *)prompt, CDK_STRLEN(prompt));
    }
    rl_write((unsigned char *)str, idx);

    while (reading) {

        ch = rl_readkey();
        if (ch < 0) break;
        if (ch == 0) continue;

        switch (ch) {

        case CTRL('C'):                 /* Cancel line and terminate */
            rl_crlf();
            len = 0;
            nosave = 1;
            reading = 0;
            break;

        case 0x7f:                      /* Backspace, Delete */
        case CTRL('H'):
            if (idx > 0) {
                nosave = 0;
                len--;
                idx--;
                rl_write((unsigned char *)"\b",1);
                if (len != idx) {
                    for (t = idx; t < len; t++) str[t] = str[t+1];
                    rl_write((unsigned char *)&str[idx],len-idx);
                    rl_whiteout(1);
                    rl_backspace(len-idx);
                }
                else {
                    rl_whiteout(1);
                }
            }
            break;

        case CTRL('D'):                 /* Ctrl-D */
            if ((idx >= 0) && (len != idx)) {
                nosave = 0;
                len--;
                for (t = idx; t < len; t++) str[t] = str[t+1];
                rl_write((unsigned char *)&str[idx],len-idx);
                rl_whiteout(1);
                rl_backspace(len-idx);
            }
            break;

        case CTRL('B'):                 /* Cursor left */
        case VKEY_LEFT:
            if (idx > 0) {
                idx--;
                rl_backspace(1);
            }
            break;

        case CTRL('F'):                 /* Cursor right */
        case VKEY_RIGHT:
            if (idx < len) {
                rl_write((unsigned char *)&str[idx],1);
                idx++;
            }
            break;

        case CTRL('A'):                 /* Cursor to BOL */
            rl_backspace(idx);
            idx = 0;
            break;

        case CTRL('E'):                 /* Cursor to EOL */
            if (len-idx > 0) rl_write((unsigned char *)&str[idx],len-idx);
            idx = len;
            break;

        case CTRL('K'):                 /* Kill to EOL */
            if (idx != len) {
                str[len] = '\0';
                rl_whiteout(len-idx);
                len = idx;
                nosave = 0;
            }
            break;

        case CTRL('R'):                 /* Redisplay line */
            str[len] = 0;
            rl_crlf();
            if (prompt && *prompt) {
                rl_write((unsigned char *)prompt, CDK_STRLEN(prompt));
            }
            rl_write((unsigned char *)str,len);
            rl_backspace(len-idx);
            break;

        case CTRL('U'):                 /* Cancel line */
            rl_backspace(idx);
            rl_eraseeol();
            if (len > 0) nosave = 1;
            idx = 0;
            len = 0;
            break;

        case CTRL('M'):                 /* Terminate */
        case CTRL('J'):
            rl_crlf();
            reading = 0;
            break;

        case CTRL('P'):                 /* Recall previous line */
        case VKEY_UP:
            t = recall;
            t--;
            if (t < 0) t = RL_MAXSAVELINES-1;
            if (rl_savedlines[t][0] == 0) break;
            recall = t;
            rl_backspace(idx);
            CDK_STRLCPY(str, rl_savedlines[recall], RL_MAXLINESIZE);
            len = idx = CDK_STRLEN(rl_savedlines[recall]);
            rl_eraseeol();
            rl_write((unsigned char *)str, len);
            nosave = (t == ((rl_nextsave - 1) % RL_MAXSAVELINES));
            break;

        case CTRL('N'):                 /* Recall next line */
        case VKEY_DOWN:
            if (rl_savedlines[recall][0] == 0) break;
            t = recall; 
            t++;
            if (t == RL_MAXSAVELINES) t = 0;
            recall = t;
            rl_backspace(idx);
            CDK_STRLCPY(str, rl_savedlines[recall], RL_MAXLINESIZE);
            len = idx = CDK_STRLEN(rl_savedlines[recall]);
            rl_eraseeol();
            rl_write((unsigned char *)str,len);
            nosave = 1;
            break;

        default:                        /* Insert character */
            if (ch >= ' ') {
                if (idx < (maxlen-1)) {
                    nosave = 0;
                    for (t = len; t > idx; t--) {
                        str[t] = str[t-1];
                    }
                    str[idx] = ch;
                    len++;
                    if (len != idx) {
                        rl_write((unsigned char *)&str[idx],len-idx);
                        rl_backspace(len-idx-1);
                    }
                    idx++;
                }
            }
            break;
        }
    }

    str[len] = 0;

    rl_savedlines[rl_nextsave][0] = 0;
    if ((len != 0) && !nosave) {
        CDK_STRLCPY(rl_savedlines[rl_nextsave], str, RL_MAXLINESIZE);
        rl_nextsave++;
        if (rl_nextsave == RL_MAXSAVELINES) rl_nextsave = 0;
    }

    return str;
}
