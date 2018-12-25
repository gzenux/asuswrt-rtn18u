/*
 * $Id: cdk_error.h,v 1.5 Broadcom SDK $
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
 * CDK error codes
 */

#ifndef __CDK_ERROR_H__
#define __CDK_ERROR_H__

typedef enum {
    CDK_E_NONE          = 0,
    CDK_E_INTERNAL      = -1,
    CDK_E_MEMORY        = -2,
    CDK_E_UNIT          = -3,
    CDK_E_PARAM         = -4,
    CDK_E_EMPTY         = -5,
    CDK_E_FULL          = -6,
    CDK_E_NOT_FOUND     = -7,
    CDK_E_EXISTS        = -8,
    CDK_E_TIMEOUT       = -9,
    CDK_E_BUSY          = -10,
    CDK_E_FAIL          = -11,
    CDK_E_DISABLED      = -12,
    CDK_E_BADID         = -13,
    CDK_E_RESOURCE      = -14,
    CDK_E_CONFIG        = -15,
    CDK_E_UNAVAIL       = -16,
    CDK_E_INIT          = -17,
    CDK_E_PORT          = -18,
    CDK_E_IO            = -19,

    CDK_E_LIMIT         = -20           /* Must come last */
} cdk_error_t;

#define CDK_ERRMSG_INIT { \
    "CDK_E_NONE", \
    "CDK_E_INTERNAL", \
    "CDK_E_MEMORY", \
    "CDK_E_UNIT", \
    "CDK_E_PARAM", \
    "CDK_E_EMPTY", \
    "CDK_E_FULL", \
    "CDK_E_NOT_FOUND", \
    "CDK_E_EXISTS", \
    "CDK_E_TIMEOUT", \
    "CDK_E_BUSY", \
    "CDK_E_FAIL", \
    "CDK_E_DISABLED", \
    "CDK_E_BADID", \
    "CDK_E_RESOURCE", \
    "CDK_E_CONFIG", \
    "CDK_E_UNAVAIL", \
    "CDK_E_INIT", \
    "CDK_E_PORT", \
    "CDK_E_IO", \
    "CDK_E_LIMIT" \
}

extern char *cdk_errmsg[];

#define	CDK_ERRMSG(r)		\
	cdk_errmsg[((r) <= 0 && (r) > CDK_E_LIMIT) ? -(r) : -CDK_E_LIMIT]

#define CDK_SUCCESS(rv)         ((rv) >= 0)
#define CDK_FAILURE(rv)         ((rv) < 0)


/*
 * Convenience macro to return an error if the given unit number is invalid. 
 */     
#define CDK_UNIT_CHECK(_u) do { if(!CDK_DEV_EXISTS(_u)) { return CDK_E_UNIT; } } while(0)

#endif /* __CDK_ERROR_H__ */
