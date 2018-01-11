/*
 * Test harness utility.
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#ifndef _TEST_H_
#define _TEST_H_

/* --------------------------------------------------------------- */
typedef struct
{
	int count;		/* number of tests run */
	int passed;		/* number of tests passed */
	int failed;		/* number of tests failed */
} testLogT;

#define TEST_DECLARE() static testLogT gTestLog;

#define TEST_INITIALIZE()									\
{															\
	memset(&gTestLog, 0, sizeof(gTestLog));					\
}

#define TEST(condition, error)								\
	do {													\
		gTestLog.count++;									\
		if ((condition)) {									\
			gTestLog.passed++;								\
		}													\
		else {												\
			gTestLog.failed++;								\
			printf("\n*** FAIL *** - %s %s():%d - %s\n\n",	\
				__FILE__, __FUNCTION__, __LINE__, error);	\
		}													\
	} while (0)

#define TEST_FATAL(condition, error)						\
	do {													\
		gTestLog.count++;									\
		if ((condition)) {									\
			gTestLog.passed++;								\
		}													\
		else {												\
			gTestLog.failed++;								\
			printf("\n*** FAIL *** - %s():%d - %s\n\n",		\
				__FUNCTION__, __LINE__, error);				\
			exit(-1);										\
		}													\
	} while (0)

#define TEST_FINALIZE()										\
{															\
	int percent = gTestLog.count ?							\
		gTestLog.passed * 100 / gTestLog.count : 0; 		\
	printf("\n");											\
	printf("Test Results (%s):\n\n", __FILE__);				\
	printf("Tests    %d\n", gTestLog.count);				\
	printf("Pass     %d\n", gTestLog.passed);				\
	printf("Fail     %d\n\n", gTestLog.failed);				\
	printf("%d%%\n\n", percent);							\
}

#endif /* _TEST_H_ */
