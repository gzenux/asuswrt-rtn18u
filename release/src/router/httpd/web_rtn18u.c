#include <stdio.h>

#include <httpd.h>
#include <json.h>
#include <bcmnvram.h>
#include <shared.h>

#ifdef RTCONFIG_CAPTCHA
extern const int gifsize;
extern void captcha(unsigned char im[70*200], unsigned char l[6]);
extern void makegif(unsigned char im[70*200], unsigned char gif[gifsize]);
unsigned char cur_captcha[6] = {0};
#endif

static struct stb_port stb_x_options[] = {
	{ .name = "none", .value = "0" },
	{ .name = "LAN1", .value = "1" },
	{ .name = "LAN2", .value = "2" },
	{ .name = "LAN3", .value = "3" },
	{ .name = "LAN4", .value = "4" },
	{ .name = "LAN1 & LAN2", .value = "5" },
	{ .name = "LAN3 & LAN4", .value = "6" },
#if 0 /* option disabled */
	{ .name = "", .value = "7" },
	{ .name = "", .value = "8" },
#endif /* option disabled */
};
static unsigned int num_stb_x_option = 7; //sizeof(stb_x_options)/sizeof(*stb_x_options);

static struct iptv_profile isp_profiles[] = {
	{
		.profile_name = "none",
		.iptv_port = "",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "none",
		.switch_stb_x = "0",
		.switch_wan0tagid = "", .switch_wan0prio = "0",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Unifi-Business",
		.iptv_port = "",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "unifi_biz",
		.switch_stb_x = "0",
		.switch_wan0tagid = "500", .switch_wan0prio = "0",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Unifi-Home",
		.iptv_port = "LAN4",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "unifi_home",
		.switch_stb_x = "4",
		.switch_wan0tagid = "500", .switch_wan0prio = "0",
		.switch_wan1tagid = "600", .switch_wan1prio = "0",
		.switch_wan2tagid = "", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Singtel-MIO",
		.iptv_port = "LAN4",
		.voip_port = "LAN3",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "singtel_mio",
		.switch_stb_x = "6",
		.switch_wan0tagid = "10", .switch_wan0prio = "0",
		.switch_wan1tagid = "20", .switch_wan1prio = "4",
		.switch_wan2tagid = "30", .switch_wan2prio = "4",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Singtel-Others",
		.iptv_port = "LAN4",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "singtel_others",
		.switch_stb_x = "4",
		.switch_wan0tagid = "10", .switch_wan0prio = "0",
		.switch_wan1tagid = "20", .switch_wan1prio = "4",
		.switch_wan2tagid = "", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "M1-Fiber",
		.iptv_port = "",
		.voip_port = "LAN3",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "m1_fiber",
		.switch_stb_x = "3",
		.switch_wan0tagid = "1103", .switch_wan0prio = "1",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "1107", .switch_wan2prio = "1",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Maxis-Fiber",
		.iptv_port = "",
		.voip_port = "LAN3",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "maxis_fiber",
		.switch_stb_x = "3",
		.switch_wan0tagid = "621", .switch_wan0prio = "0",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "821,822", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Maxis-Fiber-Special",
		.iptv_port = "",
		.voip_port = "LAN3",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "maxis_fiber_sp",
		.switch_stb_x = "3",
		.switch_wan0tagid = "11", .switch_wan0prio = "0",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "14", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Movistar Triple VLAN",
		.iptv_port = "",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "1",
		.voip_config = "1",
		.switch_wantag = "movistar",
		.switch_stb_x = "8",
		.switch_wan0tagid = "6", .switch_wan0prio = "0",
		.switch_wan1tagid = "2", .switch_wan1prio = "0",
		.switch_wan2tagid = "3", .switch_wan2prio = "0",
		.mr_enable_x = "1",
		.emf_enable = "1",
		.wan_vpndhcp = "0",
		.quagga_enable = "1",
		.mr_altnet_x = "172.0.0.0/8",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Meo",
		.iptv_port = "",
		.voip_port = "",
		.bridge_port = "LAN4",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "meo",
		.switch_stb_x = "4",
		.switch_wan0tagid = "12", .switch_wan0prio = "0",
		.switch_wan1tagid = "12", .switch_wan1prio = "0",
		.switch_wan2tagid = "", .switch_wan2prio = "0",
		.mr_enable_x = "1",
		.emf_enable = "1",
		.wan_vpndhcp = "0",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "1"
	},
	{
		.profile_name = "Vodafone(Portugal)",
		.iptv_port = "LAN3",
		.voip_port = "",
		.bridge_port = "LAN4",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "vodafone",
		.switch_stb_x = "3",
		.switch_wan0tagid = "100", .switch_wan0prio = "1",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "105", .switch_wan2prio = "1",
		.mr_enable_x = "1",
		.emf_enable = "1",
		.wan_vpndhcp = "0",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Hinet MOD",
		.iptv_port = "LAN4",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "hinet",
		.switch_stb_x = "4",
		.switch_wan0tagid = "", .switch_wan0prio = "0",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Stuff-Fibre",
		.iptv_port = "",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "stuff_fibre",
		.switch_stb_x = "0",
		.switch_wan0tagid = "10", .switch_wan0prio = "0",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
#if 0 /* profile disabled */
	{
		.profile_name = "Maxis-Fiber-IPTV",
		.iptv_port = "",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "maxis_fiber_iptv",
		.switch_stb_x = "7",
		.switch_wan0tagid = "621", .switch_wan0prio = "0",
		.switch_wan1tagid = "823", .switch_wan1prio = "0",
		.switch_wan2tagid = "821,822", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
	{
		.profile_name = "Maxis-Fiber-Special-IPTV",
		.iptv_port = "",
		.voip_port = "",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "maxis_fiber_sp_iptv",
		.switch_stb_x = "7",
		.switch_wan0tagid = "11", .switch_wan0prio = "0",
		.switch_wan1tagid = "15", .switch_wan1prio = "0",
		.switch_wan2tagid = "14", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
#endif /* profile disabled */
	{
		.profile_name = "manual",
		.iptv_port = "LAN4",
		.voip_port = "LAN3",
		.bridge_port = "",
		.iptv_config = "0",
		.voip_config = "0",
		.switch_wantag = "manual",
		.switch_stb_x = "0",
		.switch_wan0tagid = "", .switch_wan0prio = "0",
		.switch_wan1tagid = "", .switch_wan1prio = "0",
		.switch_wan2tagid = "", .switch_wan2prio = "0",
		.mr_enable_x = "",
		.emf_enable = "",
		.wan_vpndhcp = "",
		.quagga_enable = "0",
		.mr_altnet_x = "",
		.ttl_inc_enable = "0"
	},
};
static unsigned int num_isp_profile = sizeof(isp_profiles)/sizeof(*isp_profiles);


int ej_get_iptvSettings(int eid, webs_t wp, int argc, char_t **argv)
{
	int i;
	struct iptv_profile *isp_profile = NULL;
	struct json_object *item = NULL;
	struct json_object *array = NULL;
	struct json_object *root = json_object_new_object();

	/* stb_x options */
	for(array = json_object_new_array(), i = 0; i < num_stb_x_option; i++) {
		item = json_object_new_object();
		json_object_object_add(item, "name", json_object_new_string(stb_x_options[i].name));
		json_object_object_add(item, "value", json_object_new_string(stb_x_options[i].value));
		json_object_array_add(array, item);
	}
	json_object_object_add(root, "stb_x_options", array);

	/* isp profiles */
	for(array = json_object_new_array(), i = 0; i < num_isp_profile; i++) {
		isp_profile = &isp_profiles[i];
		item = json_object_new_object();
		json_object_object_add(item, "profile_name", json_object_new_string(isp_profile->profile_name));
		json_object_object_add(item, "iptv_port", json_object_new_string(isp_profile->iptv_port));
		json_object_object_add(item, "voip_port", json_object_new_string(isp_profile->voip_port));
		json_object_object_add(item, "bridge_port", json_object_new_string(isp_profile->bridge_port));
		json_object_object_add(item, "iptv_config", json_object_new_string(isp_profile->iptv_config));
		json_object_object_add(item, "voip_config", json_object_new_string(isp_profile->voip_config));
		json_object_object_add(item, "switch_wantag", json_object_new_string(isp_profile->switch_wantag));
		json_object_object_add(item, "switch_stb_x", json_object_new_string(isp_profile->switch_stb_x));
		json_object_object_add(item, "mr_enable_x", json_object_new_string(isp_profile->mr_enable_x));
		json_object_object_add(item, "emf_enable", json_object_new_string(isp_profile->emf_enable));
		json_object_object_add(item, "wan_vpndhcp", json_object_new_string(isp_profile->wan_vpndhcp));
		json_object_object_add(item, "quagga_enable", json_object_new_string(isp_profile->quagga_enable));
		json_object_object_add(item, "mr_altnet_x", json_object_new_string(isp_profile->mr_altnet_x));
		json_object_object_add(item, "ttl_inc_enable", json_object_new_string(isp_profile->ttl_inc_enable));
		json_object_array_add(array, item);
	}
	json_object_object_add(root, "isp_profiles", array);

	websWrite(wp, "%s", json_object_to_json_string(root));
	json_object_put(root);
	return 0;
}

int config_iptv_vlan(char *isp)
{
	int i;
	struct iptv_profile *isp_profile = NULL;

	for(i = 0; i < num_isp_profile && strcmp(isp_profiles[i].switch_wantag, isp); i++);
	if(i == num_isp_profile || !strcmp(isp, "manual"))
		return -1;
	else
		isp_profile = &isp_profiles[i];

	if(strcmp(isp, "none"))
		nvram_set("switch_stb_x", isp_profile->switch_stb_x);
	nvram_set("switch_wan0tagid", isp_profile->switch_wan0tagid); nvram_set("switch_wan0prio", isp_profile->switch_wan0prio);
	nvram_set("switch_wan1tagid", isp_profile->switch_wan1tagid); nvram_set("switch_wan1prio", isp_profile->switch_wan1prio);
	nvram_set("switch_wan2tagid", isp_profile->switch_wan2tagid); nvram_set("switch_wan2prio", isp_profile->switch_wan2prio);
	return 0;
}

int ej_get_txpwr(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp = NULL;
	int i, unit = 0;
	char cmd[64] = {0}, out[64] = {0};

	if (ejArgs(argc, argv, "%d", &unit) < 1)
		unit = 0;

	if (!nvram_match(wl_nvname("radio", unit, 0), "1"))
		return 0;

	sprintf(cmd, "wl -i %s txpwr_target_max | awk '{print $7}'", nvram_safe_get(wl_nvname("ifname", unit, 0)));
	if ((fp = popen(cmd, "r")) != NULL) {
		while (!feof(fp)) {
			if (fgets(out, sizeof(out), fp)) {
				if ((i = strlen(out)) > 0) {
					if (out[i-1] == '\n')
						out[i-1] = '\0';
					websWrite(wp, out);
				}
			}
		}
		pclose(fp);
	}

	return 0;
}

#ifdef RTCONFIG_CAPTCHA
int is_captcha_match(char *catpch)
{
	return !strncmp(catpch, (const char *)cur_captcha, sizeof(cur_captcha));
}

void do_captcha_file(char *url, FILE *stream)
{
	FILE *fp;
	const char *captcha_file = "/tmp/captcha.gif";
	unsigned char img[70*200] = {0};
	unsigned char gif[gifsize];

	memset(gif, 0, sizeof(gif));

	if ((fp = fopen(captcha_file, "w")) != NULL) {
		captcha(img, cur_captcha);
		makegif(img, gif);
		fwrite(gif, 1, gifsize, fp);
		fclose(fp);
	}

	do_file(captcha_file, stream);
	unlink(captcha_file);
}
#endif
