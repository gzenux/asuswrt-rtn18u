#include <stdio.h>
#include <stdlib.h>

#include <bcmnvram.h>
#include <shutils.h>

#include "qcsapi_output.h"
#include "qcsapi_rpc_common/client/find_host_addr.h"

#include "qcsapi.h"
#include "qcsapi_rpc/client/qcsapi_rpc_client.h"
#include "qcsapi_rpc/generated/qcsapi_rpc.h"
#include "qcsapi_driver.h"
#include "call_qcsapi.h"

#define MAX_RETRY_TIMES 30
#define WIFINAME "wifi0"

static int s_c_rpc_use_udp = 0;

void inc_mac(char *mac, int plus);

int c_rpc_qcsapi_init()
{
	const char *host;
	CLIENT *clnt;
	int retry = 0;

	/* setup RPC based on udp protocol */
	do {
		// remove due to ATE command output format
		// fprintf(stderr, "#%d attempt to create RPC connection\n", retry + 1);

		host = client_qcsapi_find_host_addr(0, NULL);
		if (!host) {
			fprintf(stderr, "Cannot find the host\n");
			sleep(1);
			continue;
		}

		if (!s_c_rpc_use_udp) {
			clnt = clnt_create(host, QCSAPI_PROG, QCSAPI_VERS, "tcp");
		} else {
			clnt = clnt_create(host, QCSAPI_PROG, QCSAPI_VERS, "udp");
		}

		if (clnt == NULL) {
			clnt_pcreateerror(host);
			sleep(1);
			continue;
		} else {
			client_qcsapi_set_rpcclient(clnt);
			return 0;
		}
	} while (retry++ < MAX_RETRY_TIMES);

	return -1;
}

int setMAC_5G_qtn(const char *mac)
{
	int ret;
	char cmd_l[64];
	char value[20] = {0};

	if( mac==NULL || !isValidMacAddr(mac) )
		return 0;

	ret = c_rpc_qcsapi_init();
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_update_parameter("ethaddr", mac);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
#if 0
	inc_mac(mac, 1);
#endif
	ret = qcsapi_bootcfg_update_parameter("wifiaddr", mac);
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	ret = qcsapi_bootcfg_get_parameter("ethaddr", value, sizeof(value));
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}

	memset(cmd_l, 0, 64);
	sprintf(cmd_l, "asuscfe1:macaddr=%s", mac);
	eval("nvram", "set", cmd_l );
	// puts(nvram_safe_get("1:macaddr"));

	puts(value);
	return 1;
}

int getMAC_5G_qtn(void)
{
	int ret;
	char value[20] = {0};

	ret = c_rpc_qcsapi_init();
	ret = qcsapi_bootcfg_get_parameter("ethaddr", value, sizeof(value));
	if (ret < 0) {
		fprintf(stderr, "ATE command error\n");
		return -1;
	}
	puts(value);
	return 1;
}


int start_wireless_qtn(void)
{
	int ret;

	ret = c_rpc_qcsapi_init();

	ret = qcsapi_wifi_set_SSID(WIFINAME,nvram_safe_get("wl1_ssid"));
	if(!nvram_match("wl1_auth_mode_x", "open")){
		rpc_qcsapi_set_beacon_type(nvram_safe_get("wl1_auth_mode_x"));
		rpc_qcsapi_set_WPA_encryption_modes(nvram_safe_get("wl1_crypto"));
		rpc_qcsapi_set_key_passphrase(nvram_safe_get("wl1_wpa_psk"));
	}
	return 1;
}

int rpc_qcsapi_set_SSID(char *ssid)
{
	int ret;

	ret = qcsapi_wifi_set_SSID(WIFINAME, ssid);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_SSID error, return: %d\n", ret);
		return -1;
	}
	dbG("Set SSID as: %s\n", ssid);

	return 0;
}

int rpc_qcsapi_set_SSID_broadcast(char *option)
{
	int ret;
	int OPTION = 1 - atoi(option);

	ret = qcsapi_wifi_set_option(WIFINAME, qcsapi_SSID_broadcast, OPTION);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_option::SSID_broadcast error, return: %d\n", ret);
		return -1;
	}
	dbG("Set Broadcast SSID as: %s\n", OPTION ? "TRUE" : "FALSE");

	return 0;
}

int rpc_qcsapi_set_vht(char *mode)
{
	int ret;
	int VHT;

	switch (atoi(mode))
	{
		case 0:
			VHT = 1;
			break;
		default:
			VHT = 0;
			break;
	}

	ret = qcsapi_wifi_set_vht(WIFINAME, VHT);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_vht error, return: %d\n", ret);
		return -1;
	}
	dbG("Set wireless mode as: %s\n", VHT ? "11ac" : "11n");

	return 0;
}

int rpc_qcsapi_set_bw(char *bw)
{
	int ret;
	int BW = 20;

	switch (atoi(bw))
	{
		case 1:
			BW = 20;
			break;
		case 2:
			BW = 40;
			break;
		case 0:
		case 3:
			BW = 80;
			break;
	}

	ret = qcsapi_wifi_set_bw(WIFINAME, BW);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_bw error, return: %d\n", ret);
		return -1;
	}
	dbG("Set bw as: %d MHz\n", BW);

	return 0;
}

int rpc_qcsapi_set_channel(char *chspec_buf)
{
	int ret;
	int channel = 0;

	channel = wf_chspec_ctlchan(wf_chspec_aton(chspec_buf));

	ret = qcsapi_wifi_set_channel(WIFINAME, channel);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_channel error, return: %d\n", ret);
		return -1;
	}
	dbG("Set channel as: %d\n", channel);

	return 0;
}

int rpc_qcsapi_set_beacon_type(char *auth_mode)
{
	int ret;
	char *p_new_beacon = NULL;

	if (!strcmp(auth_mode, "open"))
		p_new_beacon = strdup("Basic");
        else if (!strcmp(auth_mode, "psk"))
		p_new_beacon = strdup("WPA");
        else if (!strcmp(auth_mode, "psk2"))
		p_new_beacon = strdup("11i");
        else if (!strcmp(auth_mode, "pskpsk2"))
		p_new_beacon = strdup("WPAand11i");
	else
		p_new_beacon = strdup("Basic");

	ret = qcsapi_wifi_set_beacon_type(WIFINAME, p_new_beacon);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_beacon_type error, return: %d\n", ret);
		return -1;
	}
	dbG("Set beacon type as: %s\n", p_new_beacon);

	if (p_new_beacon) free(p_new_beacon);

	return 0;
}

int rpc_qcsapi_set_WPA_encryption_modes(char *crypto)
{
	int ret;
	string_32 encryption_modes;

	if (!strcmp(crypto, "tkip"))
		strcpy(encryption_modes, "TKIPEncryption");
        else if (!strcmp(crypto, "aes"))
		strcpy(encryption_modes, "AESEncryption");
        else if (!strcmp(crypto, "tkip+aes"))
		strcpy(encryption_modes, "TKIPandAESEncryption");
	else
		strcpy(encryption_modes, "AESEncryption");

	ret = qcsapi_wifi_set_WPA_encryption_modes(WIFINAME, encryption_modes);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_WPA_encryption_modes error, return: %d\n", ret);
		return -1;
	}
	dbG("Set WPA encryption mode as: %s\n", encryption_modes);

	return 0;
}

int rpc_qcsapi_set_key_passphrase(char *wpa_psk)
{
	int ret;

	ret = qcsapi_wifi_set_key_passphrase(WIFINAME, 0, wpa_psk);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_key_passphrase error, return: %d\n", ret);
		return -1;
	}
	dbG("Set WPA preshared key as: %s\n", wpa_psk);

	return 0;
}

int rpc_qcsapi_set_dtim(char *dtim)
{
	int ret;
	int DTIM = atoi(dtim);

	ret = qcsapi_wifi_set_dtim(WIFINAME, DTIM);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_dtim error, return: %d\n", ret);
		return -1;
	}
	dbG("Set dtim as: %d\n", DTIM);

	return 0;
}

int rpc_qcsapi_set_beacon_interval(char *beacon_interval)
{
	int ret;
	int BCN = atoi(beacon_interval);

	ret = qcsapi_wifi_set_beacon_interval(WIFINAME, BCN);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_beacon_interval error, return: %d\n", ret);
		return -1;
	}
	dbG("Set beacon_interval as: %d\n", BCN);

	return 0;
}

int rpc_qcsapi_set_mac_address_filtering(char *mac_address_filtering)
{
	int ret;
	qcsapi_mac_address_filtering MAF;
	qcsapi_mac_address_filtering orig_mac_address_filtering;

	ret = rpc_qcsapi_get_mac_address_filtering(&orig_mac_address_filtering);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_mac_address_filtering error, return: %d\n", ret);
		return -1;
	}
	dbG("Original mac_address_filtering setting: %d\n", orig_mac_address_filtering);

	if (!strcmp(mac_address_filtering, "disabled"))
		MAF = qcsapi_disable_mac_address_filtering;
	else if (!strcmp(mac_address_filtering, "deny"))
		MAF = qcsapi_accept_mac_address_unless_denied;
	else if (!strcmp(mac_address_filtering, "allow"))
		MAF = qcsapi_deny_mac_address_unless_authorized;
	else
		MAF = qcsapi_disable_mac_address_filtering;

	ret = qcsapi_wifi_set_mac_address_filtering(WIFINAME, MAF);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_set_mac_address_filtering error, return: %d\n", ret);
		return -1;
	}
	dbG("Set mac_address_filtering as: %d (%s)\n", MAF, mac_address_filtering);

	if ((orig_mac_address_filtering == 0) && (mac_address_filtering != 0))
		update_wlmaclist();

	return 0;
}

int rpc_qcsapi_authorize_mac_address(const char *macaddr)
{
	int ret;
	qcsapi_mac_addr address_to_authorize;

	ether_atoe(macaddr, address_to_authorize);
	ret = qcsapi_wifi_authorize_mac_address(WIFINAME, address_to_authorize);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_authorize_mac_address error, return: %d\n", ret);
		return -1;
	}
//	dbG("authorize MAC addresss: %s\n", macaddr);

	return 0;
}

int rpc_qcsapi_deny_mac_address(const char *macaddr)
{
	int ret;
	qcsapi_mac_addr address_to_deny;

	ether_atoe(macaddr, address_to_deny);
	ret = qcsapi_wifi_deny_mac_address(WIFINAME, address_to_deny);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_deny_mac_address error, return: %d\n", ret);
		return -1;
	}
//	dbG("deny MAC addresss: %s\n", macaddr);

	return 0;
}

int rpc_qcsapi_get_SSID(qcsapi_SSID *ssid)
{
	int ret;

	ret = qcsapi_wifi_get_SSID(WIFINAME, (char *) ssid);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_bw error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_SSID_broadcast(int *p_current_option)
{
	int ret;

	ret = qcsapi_wifi_get_option(WIFINAME, qcsapi_SSID_broadcast, p_current_option);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_option::SSID_broadcast error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_vht(qcsapi_unsigned_int *vht)
{
	int ret;

	ret = qcsapi_wifi_get_vht(WIFINAME, vht);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_vht error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_bw(qcsapi_unsigned_int *p_bw)
{
	int ret;

	ret = qcsapi_wifi_get_bw(WIFINAME, p_bw);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_bw error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_channel(qcsapi_unsigned_int *p_channel)
{
	int ret;

	ret = qcsapi_wifi_get_channel(WIFINAME, p_channel);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_channel error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_channel_list(string_1024* list_of_channels)
{
	int ret;

	ret = qcsapi_wifi_get_list_channels(WIFINAME, *list_of_channels);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_list_channels error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_beacon_type(char *p_current_beacon)
{
	int ret;

	ret = qcsapi_wifi_get_beacon_type(WIFINAME, p_current_beacon);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_beacon_type error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_WPA_encryption_modes(char *p_current_encryption_mode)
{
	int ret;

	ret = qcsapi_wifi_get_WPA_encryption_modes(WIFINAME, p_current_encryption_mode);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_WPA_encryption_modes error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_key_passphrase(char *p_current_key_passphrase)
{
	int ret;

	ret = qcsapi_wifi_get_key_passphrase(WIFINAME, 0, p_current_key_passphrase);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_key_passphrase error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_dtim(qcsapi_unsigned_int *p_dtim)
{
	int ret;

	ret = qcsapi_wifi_get_dtim(WIFINAME, p_dtim);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_dtim error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_beacon_interval(qcsapi_unsigned_int *p_beacon_interval)
{
	int ret;

	ret = qcsapi_wifi_get_beacon_interval(WIFINAME, p_beacon_interval);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_beacon_interval error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_mac_address_filtering(qcsapi_mac_address_filtering *p_mac_address_filtering)
{
	int ret;

	ret = qcsapi_wifi_get_mac_address_filtering(WIFINAME, p_mac_address_filtering);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_mac_address_filtering error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_authorized_mac_addresses(char *list_mac_addresses, const unsigned int sizeof_list)
{
	int ret;

	ret = qcsapi_wifi_get_authorized_mac_addresses(WIFINAME, list_mac_addresses, sizeof_list);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_authorized_mac_addresses error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int rpc_qcsapi_get_denied_mac_addresses(char *list_mac_addresses, const unsigned int sizeof_list)
{
	int ret;

	ret = qcsapi_wifi_get_denied_mac_addresses(WIFINAME, list_mac_addresses, sizeof_list);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_denied_mac_addresses error, return: %d\n", ret);
		return -1;
	}

	return 0;
}

int
wl_channel_list_5g(void)
{
	int ret;
	int retval = 0;
	char tmp[256];
	string_1024 list_of_channels;
	char *p;
	int i = 0;;

	sprintf(tmp, "[\"%d\"]", 0);

	ret = qcsapi_wifi_get_list_channels(WIFINAME, (char *) &list_of_channels);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_list_channels error, return: %d\n", ret);
		goto ERROR;
	}

	p = strtok((char *) list_of_channels, ",");
	while (p)
	{
		if (i == 0)
			sprintf(tmp, "[\"%s\"", (char *)p);
		else
			sprintf(tmp,  "%s, \"%s\"", tmp, (char *)p);

		p = strtok(NULL, ",");
		i++;
	}

	if (i)
		sprintf(tmp,  "%s]", tmp);

ERROR:
	return retval;
}

int rpc_qcsapi_restore_default_config(int flag)
{
	int ret;

	ret = qcsapi_restore_default_config(flag);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_restore_default_config error, return: %d\n", ret);
		return -1;
	}
	dbG("QTN restore default config successfully\n");

	return 0;
}

void update_wlmaclist()
{
	int ret;
	qcsapi_mac_address_filtering mac_address_filtering;
	char list_mac_addresses[1024];
        char *m = NULL;
        char *p, *pp;

	ret = rpc_qcsapi_get_mac_address_filtering(&mac_address_filtering);
	if (ret < 0)
		dbG("rpc_qcsapi_get_mac_address_filtering error, return: %d\n", ret);
	else
	{
		if (mac_address_filtering == qcsapi_accept_mac_address_unless_denied)
		{
			ret = rpc_qcsapi_get_denied_mac_addresses(list_mac_addresses, sizeof(list_mac_addresses));
			if (ret < 0)
				dbG("rpc_qcsapi_get_denied_mac_addresses error, return: %d\n", ret);
			else
			{
//				dbG("current denied MAC addresses: %s\n", list_mac_addresses);
				if (strlen(list_mac_addresses))
				{
					pp = p = strdup(list_mac_addresses);
					while ((m = strsep(&p, ",")) != NULL) {
//						dbG("MAC address: %s\n", m);
						rpc_qcsapi_authorize_mac_address(m);
					}
					free(pp);
				}

				pp = p = strdup(nvram_safe_get("wl1_maclist_x"));
				if (pp) {
					while ((m = strsep(&p, "<")) != NULL) {
						if (!strlen(m)) continue;
						rpc_qcsapi_deny_mac_address(m);
					}
					free(pp);
				}

				ret = rpc_qcsapi_get_denied_mac_addresses(list_mac_addresses, sizeof(list_mac_addresses));
				if (ret < 0)
					dbG("rpc_qcsapi_get_denied_mac_addresses error, return: %d\n", ret);
				else
					dbG("current denied MAC addresses: %s\n", list_mac_addresses);
			}
		}
		else if (mac_address_filtering == qcsapi_deny_mac_address_unless_authorized)
		{
			ret = rpc_qcsapi_get_authorized_mac_addresses(list_mac_addresses, sizeof(list_mac_addresses));
			if (ret < 0)
				dbG("rpc_qcsapi_get_authorized_mac_addresses error, return: %d\n", ret);
			else
			{
//				dbG("current authorized MAC addresses: %s\n", list_mac_addresses);
				if (strlen(list_mac_addresses))
				{
					pp = p = strdup(list_mac_addresses);
					while ((m = strsep(&p, ",")) != NULL) {
//						dbG("MAC address: %s\n", m);
						rpc_qcsapi_deny_mac_address(m);
					}
					free(pp);
				}

				pp = p = strdup(nvram_safe_get("wl1_maclist_x"));
				if (pp) {
					while ((m = strsep(&p, "<")) != NULL) {
						if (!strlen(m)) continue;
						rpc_qcsapi_authorize_mac_address(m);
					}
					free(pp);
				}

				ret = rpc_qcsapi_get_authorized_mac_addresses(list_mac_addresses, sizeof(list_mac_addresses));
				if (ret < 0)
					dbG("rpc_qcsapi_get_authorized_mac_addresses error, return: %d\n", ret);
				else
					dbG("current authorized MAC addresses: %s\n", list_mac_addresses);
			}
		}
	}
}
