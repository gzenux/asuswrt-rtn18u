/*
 * $Id: cdk_shell.c,v 1.20 Broadcom SDK $
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
 * CDK Shell Entry
 */

#include <cdk/cdk_shell.h>
#include <cdk/cdk_assert.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_stdlib.h>
#include <cdk/cdk_printf.h>
#include <cdk/shell/shcmd_quit.h>
#include <cdk/shell/shcmd_help.h>

#define SHCMD_OK                0
#define SHCMD_NOT_FOUND         -1
#define SHCMD_AMBIGUOUS         -2

/* List of installed shell commands */
static cdk_shell_command_t *command_root;

/*******************************************************************************
 *
 * Private functions
 *
 ******************************************************************************/

/*
 * Function:
 *	cdk_shell_prefix_print
 * Purpose:
 *	Print multi-line text with prefix.
 * Parameters:
 *	str - string to be prefix-printed 
 *      prefix - prefix string applied to each line of text
 * Returns:
 *      0 on success.
 */
static int
cdk_shell_prefix_print(char *str, char *prefix)
{
    char buf[128];
    char *ptr, *line;
    int max, len;

    if (str == NULL || prefix == NULL) {
        return -1;
    }
    line = ptr = str;
    max = sizeof(buf) - CDK_STRLEN(prefix) - 2;

    if (max < 0) {
        return -1;
    }

    while (*ptr) {
        len = ptr - line;
        if (len >= max) {
            /* Give up */
            CDK_PRINTF("%s", line);
            break;
        }
        if (*ptr++ == '\n') {
            CDK_STRLCPY(buf, line, len + 1);
            CDK_PRINTF("%s%s\n", prefix, buf);
            line = ptr;
        }
    }
    CDK_PRINTF("%s%s\n", prefix, line);

    return 0;
}

/*
 * Function:
 *	cdk_shell_show_cmds_avail
 * Purpose:
 *	Show avaiable shell commands in compact format.
 * Parameters:
 *	None
 * Returns:
 *      0 on success.
 */
static int
cdk_shell_show_cmds_avail(int unit, char *ref)
{
    cdk_shell_command_t *cmd;
    uint32_t flags;
    int cmds = 0;

    cdk_shell_unit_flags_get(unit, &flags);

    CDK_PRINTF("Available commands:");
    cmd = command_root;
    while (cmd) {
        if (cmd->flags && !(cmd->flags & flags)) {
            cmd = cmd->next;
            continue;
        }
        if (ref && CDK_STRNCMP(cmd->name, ref, CDK_STRLEN(ref)) != 0) {
            cmd = cmd->next;
            continue;
        }
        if (cmds++) {
            CDK_PRINTF(",");
        }
        CDK_PRINTF(" %s", cmd->name);
        cmd = cmd->next;
    }
    CDK_PRINTF("\n");

    return 0;
}

/*
 * Function:
 *	cdk_shell_normalize
 * Purpose:
 *	Normalize a string to simplify additional parsing.
 * Parameters:
 *	src - input string
 *	dst - output buffer
 *	max - size of output buffer
 * Returns:
 *      0 on success.
 */
static int
cdk_shell_normalize(const char *src, char *dst, int max)
{
    int count = 0; 

    /* Prevent buffer overflow */
    max -= 2;

    for(; *src && count < max; src++) {
	switch(*src) {

        case ' ':
            /* Remove extra whitespace */
            while (*src && *src == ' ') src++; 
            src--; 
            break; 		   
	    
        case ',':
        case '=':
            /* These characters may not have whitespace around them */
            /* It simplifies the rest of the commands parsing in the shell */
            if (count == 0) {
                /* Delete leading characters */
                while (*src) {
                    if (*src == '=') src++; 
                    else if (*src == ',') src++;
                    else break; 
                }
            }
            else if (dst[-1] == ' ') {
                /* Removing the whitespace leading to this character */
                dst--;
                count--; 
            }
            /* Write the actual character */
            *dst++ = *src++; 
            count++; 

            /* Remove any whitespace or duplicates after this character */
            while (*src) {
                if (*src == '=') src++;
                else if (*src == ',') src++; 
                else if (*src == ' ') src++; 
                else break;
            }
            break;

        default:
            break;
        }
	
	*dst++ = *src; 
	count++; 
    }

    *dst = 0; 

    return 0; 
}

/*
 * Function:
 *	cdk_shell_cmd_build
 * Purpose:
 *	Build tokens from command line string.
 * Parameters:
 *	str - raw command line string
 *	cmdln - command line structure to build
 *	delim - string of allowed token delimiters
 * Returns:
 *      0 on success.
 * Notes:
 *      If delim is NULL, default delimiters will be used.
 */
static int
cdk_shell_cmd_build(const char *str, cdk_shell_tokens_t *cmdln)
{	
    char nstr[CDK_CONFIG_SHELL_IO_MAX_LINE]; 

    CDK_ASSERT(str); 
    CDK_ASSERT(cmdln); 
    
    /* Clear the token structure */
    CDK_MEMSET(cmdln, 0, sizeof(*cmdln)); 
    cdk_shell_normalize(str, nstr, sizeof(nstr) - 1); 

    /* Create tokens */
    if (cdk_shell_tokenize(nstr, cmdln, NULL) < 0) {
        return -1;
    }

    return 0; 
}

/*
 * Function:
 *	cdk_shell_cmd_lookup
 * Purpose:
 *	Lookup command in list of installed commands.
 * Parameters:
 *      unit - current unit
 *	name - command
 *	shcmd - (OUT) pointer to matched command line structure
 * Returns:
 *      SHCMD_OK if unique match was found.
 *      SHCMD_AMBIGUOUS if two or more partial matches.
 *      SHCMD_NOT_FOUND if no matches.
 * Notes:
 *      SHCMD_OK will be returned on an exact match even if
 *      one or more partial matches exist.
 */
int
cdk_shell_cmd_lookup(int unit, const char *name, cdk_shell_command_t **shcmd)
{
    cdk_shell_command_t *cmd = command_root;
    size_t maxcmp;
    uint32_t flags;
    int rv = SHCMD_NOT_FOUND;

    if (cmd == NULL) {
        return SHCMD_NOT_FOUND;
    }

    maxcmp = CDK_STRLEN(name);
    *shcmd = NULL;
    cdk_shell_unit_flags_get(unit, &flags);

    while (cmd) {
        if (cmd->flags && !(cmd->flags & flags)) {
            cmd = cmd->next;
            continue;
        }
        if (CDK_STRNCMP(name, cmd->name, maxcmp) == 0) {
            if (CDK_STRLEN(cmd->name) == maxcmp) {
                /* Exact match */
                *shcmd = cmd;
                rv = SHCMD_OK;
                break;
            }
            rv = (*shcmd) ? SHCMD_AMBIGUOUS : SHCMD_OK;
            *shcmd = cmd;
        }
        cmd = cmd->next;
    }
    return rv;
}

/*
 * Function:
 *	cdk_shell_cmd_dispatch
 * Purpose:
 *	Parse and execute command line.
 * Parameters:
 *	str - raw command line
 * Returns:
 *      CDK_SHELL_CMD_OK if command completed successfully.
 *      CDK_SHELL_CMD_INVALID if command was not recognized/unique.
 *      CDK_SHELL_CMD_EXIT if command requested shell to terminate.
 *      CDK_SHELL_CMD_* if command returned an error.
 */
int
cdk_shell_cmd_dispatch(const char *str)
{
    cdk_shell_tokens_t cmdln; 
    cdk_shell_command_t *shcmd;
    char *cmd;
    int unit, cmd_unit;
    int rc = CDK_SHELL_CMD_INVALID; 
    
    /* Parse command line */
    if (cdk_shell_cmd_build(str, &cmdln) < 0) {
        return rc;
    }

    /* Empty command */
    if (cmdln.argc == 0) {
	return rc;
    }

    unit = cdk_shell_unit_get();
    cmd_unit = unit;

#if CDK_CONFIG_SHELL_UNIT_PREFIX == 1
    if ((cmd = CDK_STRCHR(cmdln.argv[0], ':')) != NULL) {
        *cmd++ = 0;
        if (cdk_shell_parse_int(cmdln.argv[0], &cmd_unit) < 0) {
            CDK_PRINTF("%sBad unit specification\n", 
                       CDK_CONFIG_SHELL_ERROR_STR);
            return rc;
        }
        if (cdk_shell_unit_set(cmd_unit) < 0) {
            /* Unit is invalid */
            CDK_PRINTF("%sUnit %d is not valid\n", 
                       CDK_CONFIG_SHELL_ERROR_STR, cmd_unit);
            return rc;
        }
        if (*cmd == 0) {
            /* Just switch default unit */
            return SHCMD_OK;
        }
    } else {
        cmd = cmdln.argv[0];
    }
#else
    cmd = cmdln.argv[0];
#endif

    /* Lookup command and execute if found */
    switch (cdk_shell_cmd_lookup(cmd_unit, cmd, &shcmd)) {
    case SHCMD_OK:
        cmdln.argv[0] = shcmd->name;
        /* Skip command name when passing arguments to command handlers */
        rc = shcmd->func(cmdln.argc-1, &cmdln.argv[1]);
        break;
    case SHCMD_AMBIGUOUS:
        CDK_PRINTF("%sAmbiguous command\n", CDK_CONFIG_SHELL_ERROR_STR); 
        cdk_shell_show_cmds_avail(cmd_unit, cmdln.argv[0]);
        break;
    default:
        CDK_PRINTF("%sInvalid command\n", CDK_CONFIG_SHELL_ERROR_STR); 
        cdk_shell_show_cmds_avail(cmd_unit, NULL);
        break;
    }

    /* Print out common error messages */
    switch (rc) {
    case CDK_SHELL_CMD_NO_SYM:
        CDK_PRINTF("%sChip symbol information not available\n", 
                   CDK_CONFIG_SHELL_ERROR_STR); 
        break;
    case CDK_SHELL_CMD_BAD_ARG:
        CDK_PRINTF("%sBad argument or wrong number of arguments\n", 
                   CDK_CONFIG_SHELL_ERROR_STR); 
    default:
        break;
    }

    if (unit >= 0 && cdk_shell_unit_set(unit) < 0) {
        CDK_PRINTF("%sInternal error\n", CDK_CONFIG_SHELL_ERROR_STR); 
    }

    return rc;     
}

/*******************************************************************************
 *
 * Built-in shell commands
 *
 ******************************************************************************/

/*
 * Function:
 *	cdk_shcmd_quit
 * Purpose:
 *	Shell command to quit shell.
 * Returns:
 *      CDK_SHELL_CMD_*.
 */
int
cdk_shcmd_quit(int argc, char *argv[])
{
    COMPILER_REFERENCE(argc);
    COMPILER_REFERENCE(argv);

    return CDK_SHELL_CMD_EXIT;
}

/*
 * Function:
 *	cdk_shcmd_help
 * Purpose:
 *	Shell command to display command help.
 * Returns:
 *      CDK_SHELL_CMD_*.
 */
int
cdk_shcmd_help(int argc, char *argv[])
{
    cdk_shell_command_t *cmd;
    int unit, idx;
    char prefix[32];
    uint32_t flags;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    if (argc == 0) {
        cdk_shell_unit_flags_get(unit, &flags);
        CDK_PRINTF("\nSummary of commands:\n\n");
        cmd = command_root;
        while (cmd) {
            if (cmd->flags && !(cmd->flags & flags)) {
                cmd = cmd->next;
                continue;
            }
            CDK_PRINTF("%-15s  %s\n", cmd->name, cmd->desc);
            cmd = cmd->next;
        }
        CDK_PRINTF("\nFor more information about a command, "
                   "enter 'help command-name'\n\n");
        return CDK_SHELL_CMD_OK;
    }

    switch (cdk_shell_cmd_lookup(unit, argv[0], &cmd)) {
    case SHCMD_OK:
        break;
    case SHCMD_AMBIGUOUS:
        CDK_PRINTF("%sCommand not unique\n", CDK_CONFIG_SHELL_ERROR_STR); 
        cdk_shell_show_cmds_avail(unit, argv[0]);
        return CDK_SHELL_CMD_ERROR;
    default:
        CDK_PRINTF("%sUnknown command\n", CDK_CONFIG_SHELL_ERROR_STR); 
        cdk_shell_show_cmds_avail(unit, NULL);
        return CDK_SHELL_CMD_ERROR;
    }

    CDK_PRINTF("\n  SUMMARY:\n\n     %s\n", cmd->desc);
    CDK_PRINTF("\n  USAGE:\n\n");
    CDK_SNPRINTF(prefix, sizeof(prefix)-1, "     %s ", cmd->name);
    cdk_shell_prefix_print(cmd->synop, prefix);
    CDK_PRINTF("\n");
    if (cmd->help[0]) {
        CDK_STRCPY(prefix, "     ");
        for (idx = 0; cmd->help[idx] && idx < COUNTOF(cmd->help); idx++) {
            cdk_shell_prefix_print(cmd->help[idx], prefix);
        }
        CDK_PRINTF("\n");
    }

    return CDK_SHELL_CMD_OK;
}

/*******************************************************************************
 *
 * Exported functions
 *
 ******************************************************************************/

/*
 * Function:
 *      cdk_shell_init
 * Purpose:
 *      Initialize the CDK shell module
 * Parameters:
 *      None
 * Returns:
 *      0 on success. 
 */
int
cdk_shell_init(void)
{
    /* Add basic shell commands */
    cdk_shell_add_core_cmds(); 

    /* Set default unit */
    cdk_shell_unit_set(0); 

    return 0; 
}


/*
 * Function:
 *	cdk_shell
 * Purpose:
 *	Main CDK Shell loop.
 * Parameters:
 *	sh_prompt - default shell prompt
 *	sh_gets - console input function to use
 * Returns:
 *      0 on success.
 */
int 
cdk_shell(const char *sh_prompt, cdk_shell_gets_t sh_gets)
{
    char line[CDK_CONFIG_SHELL_IO_MAX_LINE]; 
    char prompt[CDK_CONFIG_SHELL_IO_MAX_PROMPT]; 

    CDK_ASSERT(sh_prompt);
    CDK_ASSERT(sh_gets);

    while (TRUE) {
#if CDK_CONFIG_SHELL_UNIT_PREFIX == 1
        int unit;

	/* Generate the prompt with unit suffix */
        unit = cdk_shell_unit_get();
        if (unit < 0) {
            CDK_SNPRINTF(prompt, sizeof(prompt)-1, "%s> ", sh_prompt);
        } else {
            CDK_SNPRINTF(prompt, sizeof(prompt)-1, "%s.%d> ", sh_prompt, unit);
        }
#else
        /* Use raw prompt */
        CDK_SNPRINTF(prompt, sizeof(prompt)-1, "%s", sh_prompt);
#endif
	
	/* Read a command */
	if (sh_gets(prompt, line, CDK_CONFIG_SHELL_IO_MAX_LINE) == NULL) {
            break;
        }

        /* Execute the command */
        if (cdk_shell_cmd_dispatch(line) == CDK_SHELL_CMD_EXIT) {
            break;
        }
    }
    return 0; 
}

/*
 * Function:
 *	cdk_shell_add_command
 * Purpose:
 *	Add command to shell command table.
 * Parameters:
 *	shcmd - shell command structure to add
 *      flags - special command properties (if any)
 * Returns:
 *      0 on success.
 * Notes:
 *      If NULL is passed as shcmd, the command table is cleared.
 */
int
cdk_shell_add_command(cdk_shell_command_t *shcmd, uint32_t flags)
{
    cdk_shell_command_t* p; 

    if (shcmd == NULL) {
        command_root = NULL;
        return 0;
    }

    /* Do not reinstall the same command structure */
    for(p = command_root; p; p = p->next) {
        if(p == shcmd) {
            /* Already installed */
            return 0;
        }
    }

    if (shcmd->synop == NULL) {
        shcmd->synop = "";
    }
    shcmd->next = command_root;
    shcmd->flags = flags;
    command_root = shcmd;

    return 0;
}
