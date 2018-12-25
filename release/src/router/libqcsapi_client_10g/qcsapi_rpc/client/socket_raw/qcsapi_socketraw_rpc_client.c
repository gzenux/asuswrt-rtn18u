/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2014 Quantenna Communications Inc                   **
**                                                                           **
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "call_qcsapi.h"
#include "qcsapi_ver.h"
#include "qcsapi_output.h"
#include "qcsapi_rpc/client/qcsapi_rpc_client.h"
#include "qcsapi_rpc/generated/qcsapi_rpc.h"
#include "qcsapi_rpc_common/common/rpc_raw.h"
#include "qcsapi_rpc_common/client/qftc.h"
#include "qcsapi_rpc_api.h"

void print_usage(char *argv_0)
{
	printf("Usage:\n");
	printf("    %s <source ifname> <dest MAC addr>\n", argv_0);
	printf("    %s --version\n", argv_0);
}

int main(int argc, char **argv)
{
	CLIENT *clnt;
	struct qcsapi_output output;
	uint8_t dst_mac[ETH_HLEN];
	int ret, param_cut = 0;
	char *gctrl_iface;

	if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
		printf("%u.%u.%u.%u\n",
			(QCSAPI_BLD_VER >> 24) & 0xff,
			(QCSAPI_BLD_VER >> 16) & 0xff,
			(QCSAPI_BLD_VER >> 8) & 0xff,
			(QCSAPI_BLD_VER & 0xff));
		return 0;
	}

	if (geteuid()) {
		printf("%s: only root can do that\n", argv[0]);
		exit(1);
	}

	if (argc < 3) {
		print_usage(argv[0]);
		exit(1);
	}

	if (str_to_mac(argv[2], dst_mac) < 0) {
		printf("%s: Destination MAC must be in the format xx:xx:xx:xx:xx:xx\n\n", argv[0]);
		print_usage(argv[0]);
		exit(1);
	}

	/* When switch to ap, there are two more parameters(global_ctrl_iface and hostapd_conf_file)
	 * which only used in this function, so never pass these two parameters. */
	if (!strcmp(argv[3], "reload_in_mode")) {
		if (!strcmp(argv[5], "ap")) {
			if (argc != 6 && argc != 8) {
				printf("QRPC: <src_ifname> <dst_mac_addr> <reload_in_mode> <wifiY_X> <ap> [global_ctrl_iface] [hostapd_conf_file]\n");
				exit(1);
			}

			if (argc == 8) {
				gctrl_iface = strrchr(argv[6], '/');
				if (gctrl_iface == NULL) {
					printf("global ctrl iface is incorrect!\n");
					exit(1);
				}
				param_cut = 2;
			}
		}
	}

	output = qcsapi_output_stdio_adapter();

	clnt = qrpc_clnt_raw_create(QCSAPI_PROG, QCSAPI_VERS, argv[1], dst_mac, QRPC_QCSAPI_RPCD_SID);
	if (clnt == NULL) {
		clnt_pcreateerror("QRPC: ");
		exit(1);
	}

	client_qcsapi_set_rpcclient(clnt);
	argv[2] = argv[0];

	ret = qcsapi_main(&output, argc - 2 - param_cut, &argv[2]);

	/* When switch to ap, start hostapd daemon, or add a hostapd iface when hostapd daemon is already running. */
	if ((ret == 0) && (!strcmp(argv[3], "reload_in_mode"))) {
		if (!strcmp(argv[5], "ap")) {
			/* Run hostapd command on host for Host-based hostapd mode */
			if (argc == 8)
				rpc_run_hostapd(&argv[4]);
		}
	}

	clnt_destroy(clnt);

	return ret;
}

