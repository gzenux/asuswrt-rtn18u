/*
 * @File: profile.h
 *
 * @Abstract: Load balancing daemon configuration/profile header file
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2011,2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#ifndef PROFILE_HEADER
#define PROFILE_HEADER

struct profileElement {
    const char *Element;
    const char *Default;
};

void profileInit(const char *File);
const char *profileGetOpts(u_int32_t ModuleID,
        const char *Element,
        struct profileElement *DefaultTable);
const char *profileElementDefault(const char *Element,
        struct profileElement *DefaultTable);
int profileGetOptsInt(u_int32_t ModuleID, 
        const char *Element, 
        struct profileElement *DefaultTable);
float profileGetOptsFloat(u_int32_t ModuleID,
        const char *Element,
        struct profileElement *DefaultTable);
#endif
