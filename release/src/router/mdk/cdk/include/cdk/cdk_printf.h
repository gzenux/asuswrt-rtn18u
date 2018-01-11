/*
 * $Id: cdk_printf.h,v 1.8 Broadcom SDK $
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
 */

#ifndef __CDK_PRINTF_H__
#define __CDK_PRINTF_H__

#include <cdk_config.h>

#include <cdk/cdk_types.h>

/* System MUST supply stdarg.h */
#include <stdarg.h>

#ifdef CDK_CC_TYPE_CHECK
/* Allow compiler to check printf arguments */
#define cdk_vsnprintf vsnprintf
#define cdk_vsprintf vsprintf
#define cdk_vprintf vprintf
#define cdk_snprintf snprintf
#define cdk_sprintf sprintf
#define cdk_printf printf
#endif

#ifndef CDK_VSNPRINTF
#define CDK_VSNPRINTF cdk_vsnprintf
#endif

#ifndef CDK_VSPRINTF
#define CDK_VSPRINTF cdk_vsprintf
#endif

#ifndef CDK_VPRINTF
#define CDK_VPRINTF cdk_vprintf
#endif

#ifndef CDK_SNPRINTF
#define CDK_SNPRINTF cdk_snprintf
#endif

#ifndef CDK_SPRINTF
#define CDK_SPRINTF cdk_sprintf
#endif

#ifndef CDK_PRINTF
#define CDK_PRINTF cdk_printf
#endif

#ifndef CDK_PUTS
#define CDK_PUTS cdk_puts
#endif

#ifndef CDK_PUTCHAR
/* undefined by default */
#endif

/*
 * All printf functions that would normally print to stdout rely
 * on the CDK_PUTS macro which defaults to cdk_puts.
 * The cdk_puts function will attempt to output characters using
 * the CDK_PUTCHAR macro, which is undefined by default.
 */
extern int (*cdk_printhook)(const char *str);
extern int cdk_puts(const char *s);

extern int cdk_vsnprintf(char *buf, size_t bufsize, const char *fmt, va_list ap);
extern int cdk_vsprintf(char *buf, const char *fmt, va_list ap);
extern int cdk_vprintf(const char *fmt, va_list ap);
extern int cdk_snprintf(char *buf, size_t bufsize, const char *fmt, ...);
extern int cdk_sprintf(char *buf, const char *fmt, ...);
extern int cdk_printf(const char *fmt, ...);

/*
 * Internal use only
 */
#define CDK_VSNPRINTF_X_INF     0x7ff0

#endif /* __CDK_PRINTF_H__ */
