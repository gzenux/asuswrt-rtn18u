/*
 * $Id: xgsm_shell_parse_args.c,v 1.1 Broadcom SDK $
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
 */

/*******************************************************************************
 *
 * Main parsing function for XGSM shell commands
 *
 ******************************************************************************/

#include <cdk/arch/xgsm_shell.h>

int
cdk_xgsm_shell_parse_args(int argc, char *argv[], cdk_shell_tokens_t *csts, int max)
    
{		
    int idx; 
    cdk_shell_tokens_t *cst = csts;
    char tmpstr[CDK_CONFIG_SHELL_IO_MAX_LINE];

    CDK_MEMSET(csts, 0, max*sizeof(*csts)); 

    /* For all arguments */
    for (idx = 0; idx < argc && idx < max; idx++, cst++) {
	
	/* Parse each individual argument with '=' into cst */
	if (cdk_shell_tokenize(argv[idx], cst, "=") < 0) {
	    return idx;
	}
	if (cst->argc == 2) {
            /*
             * If two tokens are found, we parse a second time in 
             * order parse e.g. "flags=f1,f2,f3" into a single
             * token structure.
             */
	    CDK_SPRINTF(tmpstr, "%s,%s", cst->argv[0], cst->argv[1]); 

            /* Parse second argument with ',' into cst */
	    if (cdk_shell_tokenize(tmpstr, cst, ",") < 0) {
                return idx;
            }
	}		
	else if (cst->argc != 1) {
            /* Number of tokens must be 1 or 2 */
	    return idx;
	}	

    }
    return -1; 
}
