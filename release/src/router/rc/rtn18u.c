#include <rc.h>

int LanWanLedCtrl(void)
{
#ifdef RTCONFIG_LANWAN_LED
	if(get_lanports_status() && !inhibit_led_on())
		return led_control(LED_LAN, LED_ON);
	else
		return led_control(LED_LAN, LED_OFF);
#endif
}

#if defined(RTCONFIG_WPS_ALLLED_BTN)
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

void config_mssid_isolate(char *ifname, int vif)
{
}

inline
void start_misc_services(void)
{
}
