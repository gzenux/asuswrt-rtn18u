/*
 * $Id: cdk_shell.h,v 1.20 Broadcom SDK $
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
 * CDK Shell definitions.
 */

#ifndef __CDK_SHELL_H__
#define __CDK_SHELL_H__

#include <cdk_config.h>
#include <cdk/cdk_types.h>
#include <cdk/cdk_chip.h>
#include <cdk/cdk_symbols.h>


/*
 * Shell input function prototype.
 *
 * When the shell is started is must be provided a function for
 * reading user input. The function should display the supplied
 * 'prompt' and return the null-terminated user input in 'str',
 * which is a buffer of size 'max'.
 */
typedef char *(*cdk_shell_gets_t)(const char *prompt, char* str, int max); 

/*
 * Shell command type.
 *
 * Shell commands are added via the command structure below.
 * It consists of a command name (no whitespace allowed.) and
 * a command function, which will be called with the standard
 * argc and argv parameters. The function should return one of
 * the return codes below. A one-line description must also
 * be supplied.
 * It is recommend that also a synopsis/syntax string and one
 * or more help strings are supplied. The synopsis string may
 * contain newlines to distinguish multiple way of invoking
 * the command. Helplines may also contain newlines, but
 * should not contain more than 500 characters for portability
 * reasons. If more than 500 characters are needed, the help
 * string should be split into two or more pieces.
 */
typedef struct cdk_shell_command_s {
    /* Mandatory fields */
    char *name;
    int (*func)(int argc, char *argv[]);
    char *desc;
    /* Recommended fields */
    char *synop;
    char *help[CDK_CONFIG_SHELL_MAX_HELP_LINES];
    /* Fields for internal use */
    struct cdk_shell_command_s *next;
    uint32_t flags;
} cdk_shell_command_t;

/* These are the valid return values from shell commands */
#define CDK_SHELL_CMD_OK         0
#define CDK_SHELL_CMD_ERROR     -1
#define CDK_SHELL_CMD_EXIT      -2
#define CDK_SHELL_CMD_INVALID   -3
#define CDK_SHELL_CMD_BAD_ARG   -4
#define CDK_SHELL_CMD_NO_SYM    -5


/* Initialize the CDK Shell */
extern int cdk_shell_init(void); 

/* Run the CDK Shell */
extern int cdk_shell(const char *sh_prompt, cdk_shell_gets_t sh_gets); 

/* Dispatch a shell command */
extern int cdk_shell_cmd_dispatch(const char *str); 

/* Add a command to the CDK Shell */
extern int cdk_shell_add_command(cdk_shell_command_t *shcmd, uint32_t flags);

/* Look up a command in the currently installed command table */
extern int cdk_shell_cmd_lookup(int unit, const char *name, cdk_shell_command_t **shcmd);

/* Access to current unit number */
extern int cdk_shell_unit_get(void);
extern int cdk_shell_unit_set(int unit);

/* Access to device-specific flags */
extern int cdk_shell_unit_flags_get(int unit, uint32_t *dev_flags);

/* Split a string into tokens */
extern int cdk_shell_split(char *str, char *argv[], int max, const char *delim);

/* Extract unit number from argument list */
extern int cdk_shell_unit_arg_extract(int *argc, char *argv[], int strip);

/* Extract value from command line option */
extern char *cdk_shell_opt_val(int argc, char *argv[], const char *name, int *idx);

/* Output CDK error message string */
extern int cdk_shell_error(int cdk_rv);

/* Tokens structure used for storing command line arguments */
typedef struct cdk_shell_tokens_s {
    char str[CDK_CONFIG_SHELL_IO_MAX_LINE];        /* Local storage for tokens */
    int argc;                               /* Number of tokens */
    char *argv[CDK_CONFIG_SHELL_MAX_ARGS + 1];     /* Token strings */
} cdk_shell_tokens_t; 

/* Parse string into tokens structure */
extern int cdk_shell_tokenize(const char *str, cdk_shell_tokens_t *tok, const char *delim);

/*
 * Structures and parsing function for handling the main symbol ID, i.e.
 * a register/memory name and its instances, indices, port range, etc.
 */
typedef struct cdk_shell_basic_id_s {
    int valid;                              /* Structure is valid */
    char id[CDK_CONFIG_SHELL_IO_MAX_LINE];         /* Original source string */
    char name[CDK_CONFIG_SHELL_IO_MAX_LINE];       /* First argument */
    uint32_t name32;
    uint32_t ext32;                         /* Optional address extension */
    int start;                              /* First index (if given) */
    int end;                                /* Last index (if given) */
} cdk_shell_basic_id_t; 
    
typedef struct cdk_shell_id_s {
    char id[CDK_CONFIG_SHELL_IO_MAX_LINE];         /* Original source string */
    cdk_shell_basic_id_t addr;              /* Symbol address */
    cdk_shell_basic_id_t block;             /* Block info (if applicable) */
    cdk_shell_basic_id_t port;              /* Port range (if applicable) */

#define CDK_SHELL_IDF_RAW       0x1         /* Do not decode fields */
#define CDK_SHELL_IDF_NONZERO   0x2         /* Only show contents if non-zero */
    uint32_t flags;
} cdk_shell_id_t; 
        
extern int cdk_shell_parse_id(const char *str, cdk_shell_id_t *sid, int intaddr); 

/* Vectors for parsing sub-commands */
typedef struct cdk_shell_vect_s {
    const char *id; 
    int (*v)(int argc, char *argv[], void *context); 
} cdk_shell_vect_t; 

/* Parse and dispatch sub-command vectors */
extern int cdk_shell_parse_vect(int argc, char **argv, void *context,
				cdk_shell_vect_t *v, int *rc); 

/* Check if string is a valid integer */
extern int cdk_shell_parse_is_int(const char *s);

/* Parse string into an integer value */
extern int cdk_shell_parse_int(const char *s, int *d);

/* Parse string into a 32-bit word */
extern int cdk_shell_parse_uint32(const char *s, uint32_t *d);

/* Print parsing error message */
extern int cdk_shell_parse_error(const char *desc, const char *arg);

/* Create logical port number string, e.g. " 2 ->  1" */
extern int cdk_shell_lport(char *buf, int size, int unit, int port);

/* Add basic commands (like quit and help) to shell */
extern void cdk_shell_add_core_cmds(void);

/* Check valid number of command arguments */
#define CDK_SHELL_CMD_ARGCHECK(min, max) \
    do { \
        if (argc < min || argc > max) { \
            return CDK_SHELL_CMD_BAD_ARG; \
        } \
    } while (0)

/* Some commands require a valid symbol table */
#define CDK_SHELL_CMD_REQUIRE_SYMBOLS(sym) \
    do { \
        if (!sym) { \
            return CDK_SHELL_CMD_NO_SYM; \
        } \
    } while(0)


/* Create bit range string, e.g. "<2:6>" */
extern int cdk_shell_bit_range(char *buf, int size, int minbit, int maxbit);

/* Create port bitmap string */
extern int cdk_shell_port_bitmap(char *buf, int size,
                                 const cdk_pbmp_t *pbmp, const cdk_pbmp_t *mask);

/* List fields of a register/memory */
extern int cdk_shell_list_fields(const cdk_symbol_t *symbol, const char **fnames);

/* Output fields and values of a register/memory */
extern int cdk_shell_show_fields(const cdk_symbol_t *symbol, const char** fnames, 
                                 uint32_t *data);

/* Encode field name/value strings into data for modifying register/memory */
extern int cdk_shell_encode_field(const cdk_symbol_t *symbol, 
                                  const char** fnames, 
                                  const char *field, const char *value, 
                                  uint32_t *and_masks, uint32_t *or_masks);

/* Encode token structures into data for modifying register/memory */
extern int cdk_shell_encode_fields_from_tokens(const cdk_symbol_t *symbol, 
                                               const char** fnames, 
                                               const cdk_shell_tokens_t *csts, 
                                               uint32_t *and_masks,
                                               uint32_t *or_masks,
                                               int max);

/* Convert binary flag to string */
extern const char *cdk_shell_symflag_type2name(uint32_t flag);

/* Convert flag string to binary value */
extern uint32_t cdk_shell_symflag_name2type(const char *name);

extern int cdk_shell_option_filter(int argc, char *argv[],
                                   const char *fstr, uint32_t fval);

#endif /* __CDK_SHELL_H__ */
