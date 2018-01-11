/*
 * @File: profile.h
 *
 * @Abstract: configuration/profile header file
 *
 * @Notes:
 *
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef PROFILE_HEADER
#define PROFILE_HEADER

struct profileElement {
    const char *Element;
    const char *Default;
};

void profileInit(const char *File);
const char *profileGetOpts(u_int32_t ModuleID, const char *Element,
	struct profileElement *DefaultTable);

#endif


