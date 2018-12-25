/* @File: wsplcd.c
 * @Notes:  IEEE1905 AP Auto-Configuration Daemon
 *          AP Enrollee gets wifi configuration from AP Registrar via 
 *          authenticated IEEE1905 Interfaces
 *
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */

/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "wsplcd.h"
#include "eloop.h"
#include "ucpk_hyfi20.h"
#include "apac_priv.h"
#include "apac_hyfi20_mib.h"
#include <sys/time.h>

int debug_level = MSG_INFO;
apacLogFileMode_e logFileMode = APAC_LOG_FILE_INVALID;

FILE *pLogFile = NULL;

int dprintf(int level, const char *fmt, ...)
{
	va_list ap;
	struct timeval curTime;

	va_start(ap, fmt);
	if (level >= debug_level) {
		if (pLogFile) {
			gettimeofday(&curTime, NULL);
			fprintf(pLogFile, "[%lu.%lu] ", curTime.tv_sec, curTime.tv_usec);
			vfprintf(pLogFile, fmt, ap);
			fflush(pLogFile);
		} else {
			vprintf(fmt, ap);
		}
	}
	va_end(ap);
	return 0;
}


int main(int argc, char **argv)
{
    apacInfo_t apacInfo;
    memset(&apacInfo, 0, sizeof(apacInfo_t));

    apacHyfi20CmdLogFileMode(argc, argv);

    if (logFileMode == APAC_LOG_FILE_APPEND) {
        pLogFile = fopen(APAC_LOG_FILE_PATH, "a");
    } else if (logFileMode == APAC_LOG_FILE_TRUNCATE) {
        pLogFile = fopen(APAC_LOG_FILE_PATH, "w");
    }

    /* set up default configuration */
    wsplcd_hyfi10_init(&apacInfo.hyfi10);

    /* enable command line configuration or read config file */
    optind = 0;
    apacHyfi20CmdConfig(&apacInfo.hyfi20, argc, argv);

    apacHyfi20ConfigInit(&apacInfo.hyfi20);

    /* Start wsplcd daemon */	
    dprintf(MSG_INFO, "wsplcd daemon starting.\n");

    eloop_init(&apacInfo);

    if (apacHyfi20Init(&apacInfo.hyfi20) <0)
    {
        dprintf(MSG_INFO, "%s, Failed to initialize\n", __func__);
        return -1;
    }


    apacHyfi20ConfigDump(&apacInfo.hyfi20);

    apacHyfi20AtfConfigDump(&apacInfo.hyfi20);

    /* Restore QCA VAPIndependent flag*/
    if (apacInfo.hyfi20.config.manage_vap_ind)
    {
        apac_mib_set_vapind(&apacInfo.hyfi20, 0);
    }

    /* UCPK Init*/
    if (strlen(apacInfo.hyfi20.config.ucpk) > 0){
        char wpapsk[62+1];
        char plcnmk[32+1];
        if (ucpkHyfi20Init(apacInfo.hyfi20.config.ucpk, 
            apacInfo.hyfi20.config.salt,
            apacInfo.hyfi20.config.wpa_passphrase_type,
            wpapsk,
            plcnmk) < 0)
        {
            dprintf(MSG_INFO, "%s :Invalid 1905.1 UCPK\n", __func__);
        }
        else
        {
            apac_mib_set_ucpk(&apacInfo.hyfi20, wpapsk, plcnmk);
        }
    }
        
    apacHyfi20Startup(&apacInfo.hyfi20);

    /* check compatiblility with Hyfi-1.0 */
    if (apacInfo.hyfi20.config.hyfi10_compatible)
    {
        wsplcd_hyfi10_startup(&apacInfo.hyfi10);
    }

    eloop_run();
    eloop_destroy();

    if (apacInfo.hyfi20.config.hyfi10_compatible)
    {
        wsplcd_hyfi10_stop(&apacInfo.hyfi10);
    }

    apacHyfi20DeinitSock(&apacInfo.hyfi20);

    if (pLogFile) {
        fclose(pLogFile);
    }
    /* Probably won't get here... */
    printf("Leaving wsplcd executive program\n");

    return 0;
}


