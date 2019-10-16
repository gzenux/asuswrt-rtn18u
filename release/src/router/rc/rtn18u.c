#include <rc.h>

int LanWanLedCtrl(void)
{
#ifdef RTCONFIG_LANWAN_LED
	if(get_lanports_status()
		&& !nvram_get_int("led_disable")
#if defined(RTCONFIG_WPS_ALLLED_BTN) || defined(RTCONFIG_WPS_RST_BTN)
		&& nvram_match("AllLED", "1")
#endif
	)
		led_control(LED_LAN, LED_ON);
	else led_control(LED_LAN, LED_OFF);
#endif
}
