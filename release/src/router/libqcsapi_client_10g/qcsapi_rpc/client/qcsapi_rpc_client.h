/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2011 Quantenna Communications Inc                   **
**                                                                           **
**  File        : call_qcsapi_sockrpcd.c                                     **
**  Description : Wrapper from rpc server daemon to call_qcsapi,             **
**                starting from an rpcgen generated server stub.             **
**                                                                           **
*******************************************************************************
**                                                                           **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/

#ifndef __QCSAPI_RPC_CLIENT_H__
#define __QCSAPI_RPC_CLIENT_H__

#include <rpc/rpc.h>

typedef void (*client_qcsapi_callback_pre_t)(const char *);
typedef void (*client_qcsapi_callback_post_t)(const char *, int was_error);
typedef void (*client_qcsapi_callback_reconnect_t)(const char *);

typedef int (*client_qcsapi_locker_t)(void);
typedef int (*client_qcsapi_unlocker_t)(int lock_fd);

extern void client_qcsapi_set_rpcclient(CLIENT * clnt);
extern void client_qcsapi_set_callbacks(client_qcsapi_callback_pre_t,
		client_qcsapi_callback_post_t,
		client_qcsapi_callback_reconnect_t);
extern void client_qcsapi_set_lock(client_qcsapi_locker_t,
		client_qcsapi_unlocker_t);

extern CLIENT *__clnt_pci;

#define QCSAPI_RPC_HOSTAPD_CMD_MIN_LEN 40

#ifdef PCIE_RPC_LOCK_ENABLE
#define PCIE_VIRTUAL_CLNT_ADDR  0x1234abc0
#undef CLNT_DESTROY
#undef clnt_destroy

#define CLNT_DESTROY(rh)    ((*(rh)->cl_ops->cl_destroy)(rh))
#define clnt_destroy(rh)    \
do{ \
		if((uintptr_t)rh == PCIE_VIRTUAL_CLNT_ADDR){ \
            if(__clnt_pci) \
			    rh = __clnt_pci;    \
		} else \
			((*(rh)->cl_ops->cl_destroy)(rh)); \
}while(0)
#endif

static inline int rpc_run_hostapd( char **argv )
{
	int len, ret;
	FILE *fp;
	char *buffer = NULL, *charp, *gctrl_iface = NULL;

	fp = popen("pidof hostapd", "r");
	if (fp == NULL)
		return -1;
	len = strlen(argv[2]) + strlen(argv[3]) + QCSAPI_RPC_HOSTAPD_CMD_MIN_LEN;
	buffer = malloc(len);
	if (buffer == NULL) {
		printf("Alloc memory failed\n");
		pclose(fp);
		return -1;
	}
	charp = fgets(buffer, len, fp);
	if (charp == NULL) {
		snprintf(buffer, len, "hostapd -B -g%s %s", argv[2], argv[3]);
		printf("%s\n", buffer);
		ret = system(buffer);
	} else {
		gctrl_iface = strrchr(argv[2], '/');
		if (gctrl_iface == NULL) {
			printf("global ctrl iface is incorrect!\n");
			pclose(fp);
			free(buffer);
			return -1;
		}
		gctrl_iface++;
		snprintf(buffer, len, "hostapd_cli -i%s add bss_config=%s:%s", gctrl_iface, argv[0], argv[3]);
		printf("%s\n", buffer);
		ret = system(buffer);
	}
	free(buffer);
	pclose(fp);

	return ret;
}

#endif	/* __QCSAPI_RPC_CLIENT_H__ */

