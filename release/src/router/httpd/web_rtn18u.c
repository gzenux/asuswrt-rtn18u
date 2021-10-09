#include <stdio.h>

#include <httpd.h>
#include <json.h>
#include <bcmnvram.h>
#include <shared.h>

#include "sysinfo.h"

extern unsigned int get_phy_temperature(int radio);

#ifdef RTCONFIG_CAPTCHA
extern const int gifsize;
extern void captcha(unsigned char im[70*200], unsigned char l[6]);
extern void makegif(unsigned char im[70*200], unsigned char gif[gifsize]);
unsigned char cur_captcha[6] = {0};
#endif

int ej_temperature_status(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	int temperature;

	websWrite(wp, "{");
	/* CPU */
	if ((fp = fopen("/proc/dmu/temperature", "r")) != NULL) {
		if (fscanf(fp, "%*s %*s %*s %d%*s", &temperature) != 1)
			websWrite(wp, "\"cpu\":{\"enabled\":0,\"value\":0}");
		else
			websWrite(wp, "\"cpu\":{\"enabled\":1,\"value\":%d}", temperature);

		fclose(fp);
	}

	/* Wireless 2.4 GHz */
	temperature = get_phy_temperature(2);
	if (temperature == 0)
		websWrite(wp, ",\"w2g\":{\"enabled\":0,\"value\":0}");
	else
		websWrite(wp, ",\"w2g\":{\"enabled\":1,\"value\":%d}", temperature);

	websWrite(wp, "}");
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
