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
