#include <rc.h>
#include <wlutils.h>

int LanWanLedCtrl(void)
{
#ifdef RTCONFIG_LANWAN_LED
	if(get_lanports_status() && !inhibit_led_on())
		return led_control(LED_LAN, LED_ON);
	else
		return led_control(LED_LAN, LED_OFF);
#endif
}

#if defined(RTCONFIG_LED_BTN) || defined(RTCONFIG_WPS_ALLLED_BTN) || defined(RTCONFIG_TURBO_BTN)
void setAllLedNormal(void)
{
	led_control(LED_POWER, LED_ON);

	/* Wireless LED */
	if (nvram_match("wl0_radio", "1")) {
		led_control(LED_2G, LED_ON);
	}

	/* LAN LED */
	LanWanLedCtrl();

	/* WAN LED */
	kill_pidfile_s("/var/run/wanduck.pid", SIGUSR2);

	/* USB LED */
	kill_pidfile_s("/var/run/usbled.pid", SIGTSTP);
}
#endif

/*
 * Note:
 *   The nominal target power (dBm) for CCK packets is –1.5 dBm from maxp2ga0 (converted in dBm units).
 *
 * RT-N18U maxp2ga0 setting:
 * [ASUS factory mode]
 * maxp2ga0: 58 ~ 106 qdbm
 * nominal target power: 13 ~ 25 dBm
 *
 * [Custom mode]
 * maxp2ga0: 58 ~ 106 qdbm (default)
 * nominal target power: 13 ~ 25 dBm (default)
 *
 * [Debug mode]
 * maxp2ga0: 30 ~ 120 qdbm
 * nominal target power: 6 ~ 28.5 dBm
 */
#define TXPWR_THRESHOLD_1	25
#define TXPWR_THRESHOLD_2	50
#define TXPWR_THRESHOLD_3	75
#define TXPWR_THRESHOLD_4	100

static int maxp2ga[3][5] = {
	/* [Asus] */
	{58, 70, 82, 94, 106},
	/* [Custom] */
	{58, 70, 82, 94, 106},
	/* [Debug] */
	{30, 52, 75, 98, 120}
};

void check_txpwr_nvram()
{
	char *value = NULL;
	char dbm[16] = {0};

	if (!strcmp(nvram_safe_get("txpwr_ccode"), ""))
		nvram_set("txpwr_ccode", strcmp((value = cfe_nvram_safe_get("0:ccode")), "0") ? value : "US");
	if (!strcmp(nvram_safe_get("txpwr_regrev"), ""))
		nvram_set("txpwr_regrev", cfe_nvram_safe_get("0:regrev"));
	if (!strcmp(nvram_safe_get("txpwr_min"), ""))
		nvram_set("txpwr_min", "6");	/* default to the minimal valid value */
	if (!strcmp(nvram_safe_get("txpwr_max"), "")) {
		sprintf(dbm, "%g", (atof(cfe_nvram_safe_get("0:maxp2ga0"))/4-1.5));
		nvram_set("txpwr_max", dbm);
	}
}

int set_wltxpower_rtn18u()
{
	char name[32], ifname[32], *next = NULL;
	int i, unit = -1;
	double dbm;
	char tmp[32], prefix[]="wlXXXXXXX_";
	char tmp2[32], prefix2[]="X:";
	int txpower = 100, txpwr_mod = nvram_get_int("txpwr_mod");
	int commit_needed = 0;

	if (!nvram_contains_word("rc_support", "pwrctrl")) {
		/* pwrctrl disabled */
		return -1;
	}

	if (get_model() != MODEL_RTN18U) {
		/* Invlid model */
		return -1;
	}

	if (txpwr_mod <= 0 || txpwr_mod > 2) {
		if (txpwr_mod) {
			/* Invlid txpwr_mod, restore to default value */
			nvram_set("txpwr_mod", nvram_default_get("txpwr_mod"));
			nvram_commit();
		}

		/* Fall back to Asus mode */
		check_wl_country();
		set_wltxpower();
		return 0;
	}

	/* Update custom parameters */
	if (txpwr_mod == 1) {
		check_txpwr_nvram();

		/* txpwr_min */
		dbm = atof(nvram_safe_get("txpwr_min"));
		if (dbm < 6) {
			dbm = 6;
			nvram_set("txpwr_min", "6");
			commit_needed++;
		} else if (dbm > 28.5) {
			dbm = 28.5;
			nvram_set("txpwr_min", "28.5");
			commit_needed++;
		}
		maxp2ga[txpwr_mod][0] = (int)(dbm * 4 + 6);

		/* txpwr_max */
		dbm = atof(nvram_safe_get("txpwr_max"));
		if (dbm < 6) {
			dbm = 6;
			nvram_set("txpwr_max", "6");
			commit_needed++;
		} else if (dbm > 28.5) {
			dbm = 28.5;
			nvram_set("txpwr_max", "28.5");
			commit_needed++;
		}
		maxp2ga[txpwr_mod][4] = (int)(dbm * 4 + 6);

		maxp2ga[txpwr_mod][2] = (maxp2ga[txpwr_mod][0] + maxp2ga[txpwr_mod][4]) / 2;
		maxp2ga[txpwr_mod][1] = (maxp2ga[txpwr_mod][0] + maxp2ga[txpwr_mod][2]) / 2;
		maxp2ga[txpwr_mod][3] = (maxp2ga[txpwr_mod][2] + maxp2ga[txpwr_mod][4]) / 2;
	}

	i = 0;
	foreach(name, nvram_safe_get("wl_ifnames"), next) {
		if (nvifname_to_osifname(name, ifname, sizeof(ifname)) != 0)
			continue;

		/* Convert eth name to wl name */
		if (osifname_to_nvifname(name, ifname, sizeof(ifname)) != 0)
			continue;

		/* Slave intefaces have a '.' in the name */
		if (strchr(ifname, '.'))
			continue;

		if (get_ifname_unit(ifname, &unit, NULL) < 0)
			continue;

		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		snprintf(prefix2, sizeof(prefix2), "%d:", unit);

		/* Overwrite the region */
		if (txpwr_mod == 1) {
			nvram_set(strcat_r(prefix2, "ccode", tmp2), nvram_safe_get("txpwr_ccode"));
			nvram_set(strcat_r(prefix2, "regrev", tmp2), nvram_safe_get("txpwr_regrev"));
		} else {
			nvram_set(strcat_r(prefix2, "ccode", tmp2), "#a");
			nvram_set(strcat_r(prefix2, "regrev", tmp2), "0");
		}
		nvram_set(strcat_r(prefix, "country_code", tmp), nvram_safe_get(strcat_r(prefix2, "ccode", tmp2)));
		nvram_set(strcat_r(prefix, "country_rev", tmp), nvram_safe_get(strcat_r(prefix2, "regrev", tmp2)));

		/* Apply TX power settings */
		txpower = nvram_get_int(wl_nvname("txpower", unit, 0));
		unit = 0;	/* txpower = 0% of UI slider */
		if (txpower >= TXPWR_THRESHOLD_1) {
			unit++;	/* txpower = 25% of UI slider */
			if (txpower >= TXPWR_THRESHOLD_2) {
				unit++;	/* txpower = 50% of UI slider */
				if (txpower >= TXPWR_THRESHOLD_3) {
					unit++;	/* txpower = 75% of UI slider */
					if (txpower >= TXPWR_THRESHOLD_4) {
						unit++;	/* txpower = 100% of UI slider */
					}
				}
			}
		}
		sprintf(tmp, "%d", maxp2ga[txpwr_mod][unit]);
		if (!nvram_match(strcat_r(prefix2, "maxp2ga0", tmp2), tmp)) {
			nvram_set(strcat_r(prefix2, "maxp2ga0", tmp2), tmp);
			nvram_set(strcat_r(prefix2, "maxp2ga1", tmp2), tmp);
			nvram_set(strcat_r(prefix2, "maxp2ga2", tmp2), tmp);
			if (unit) {
				nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0xA8642000");
				nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0xA8642000");
			} else {
				nvram_set(strcat_r(prefix2, "mcsbw202gpo", tmp2), "0x66642000");
				nvram_set(strcat_r(prefix2, "mcsbw402gpo", tmp2), "0x66642000");
			}
			nvram_set(strcat_r(prefix2, "dot11agofdmhrbw202gpo", tmp2), "0x6533");
			commit_needed++;
		}

		i++;
	}

	if (commit_needed)
		nvram_commit();

	return 0;
}
