/*
 * $Id: cdk_string.h,v 1.6 Broadcom SDK $
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

#ifndef __CDK_STRING_H__
#define __CDK_STRING_H__

#include <cdk_config.h>

#include <cdk/cdk_types.h>

#ifndef CDK_MEMCMP
#define CDK_MEMCMP cdk_memcmp
#endif

#ifndef CDK_MEMSET
#define CDK_MEMSET cdk_memset
#endif

#ifndef CDK_MEMCPY
#define CDK_MEMCPY cdk_memcpy
#endif

#ifndef CDK_STRCPY
#define CDK_STRCPY cdk_strcpy
#endif

#ifndef CDK_STRNCPY
#define CDK_STRNCPY cdk_strncpy
#endif

#ifndef CDK_STRLEN
#define CDK_STRLEN cdk_strlen
#endif

#ifndef CDK_STRCMP
#define CDK_STRCMP cdk_strcmp
#endif

#ifndef CDK_STRNCMP
#define CDK_STRNCMP cdk_strncmp
#endif

#ifndef CDK_STRCHR
#define CDK_STRCHR cdk_strchr
#endif

#ifndef CDK_STRRCHR
#define CDK_STRRCHR cdk_strrchr
#endif

#ifndef CDK_STRSTR
#define CDK_STRSTR cdk_strstr
#endif

#ifndef CDK_STRCAT
#define CDK_STRCAT cdk_strcat
#endif

extern int cdk_memcmp(const void *dest,const void *src,size_t cnt);
extern void *cdk_memcpy(void *dest,const void *src,size_t cnt);
extern void *cdk_memset(void *dest,int c,size_t cnt);
extern char *cdk_strcpy(char *dest,const char *src);
extern char *cdk_strncpy(char *dest,const char *src,size_t cnt);
extern size_t cdk_strlen(const char *str);
extern int cdk_strcmp(const char *dest,const char *src);
extern int cdk_strncmp(const char *dest,const char *src,size_t cnt);
extern char *cdk_strchr(const char *dest,int c);
extern char *cdk_strrchr(const char *dest,int c);
extern char *cdk_strstr(const char *dest,const char *src);
extern char *cdk_strcat(char *dest,const char *src);

/* Non-standard ANSI/ISO functions */

#ifndef CDK_STRCASECMP
#define CDK_STRCASECMP cdk_strcasecmp
#endif

#ifndef CDK_STRNCASECMP
#define CDK_STRNCASECMP cdk_strncasecmp
#endif

#ifndef CDK_STRLCPY
#define CDK_STRLCPY cdk_strlcpy
#endif

#ifndef CDK_STRUPR
#define CDK_STRUPR cdk_strupr
#endif

#ifndef CDK_STRNCHR
#define CDK_STRNCHR cdk_strnchr
#endif

extern int cdk_strcasecmp(const char *dest,const char *src);
extern int cdk_strncasecmp(const char *dest,const char *src,size_t cnt);
extern size_t cdk_strlcpy(char *dest,const char *src,size_t cnt);
extern void cdk_strupr(char *s);
extern char *cdk_strnchr(const char *dest,int c,size_t cnt);

#endif /* __CDK_STRING_H__ */
