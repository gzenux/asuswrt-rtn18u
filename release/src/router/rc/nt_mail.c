/*
	NOTIFICATION_CENTER=y
*/

#include <rc.h>
#include <shared.h>
#include <libnt.h>
#include <nt_actMail_common.h>
#ifdef RTCONFIG_USB
#include <disk_io_tools.h>	//mkdir_if_none()
#endif

#ifdef RTCONFIG_BWDPI
#include <bwdpi_common.h>
#endif

#define TM_WRS_MAIL             0x01
#define TRAFFIC_LIMITER_MAIL    0x02

/* debug message */
#define AM_DEBUG                "/tmp/AM_DEBUG"
#define AM_DBG(fmt,args...) \
	if(f_exists(AM_DEBUG) > 0) { \
		dbg("[ALERT MAIL][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}

static int value = 0;

void am_setup_email_conf()
{
	FILE *fp;
	char smtp_auth_pass[256];
	memset(smtp_auth_pass, 0, sizeof(smtp_auth_pass));
	
	AM_DBG("start to write conf %s\n", MAIL_CONF);

	// email server conf setting
	mkdir_if_none("/etc/email");
	if((fp = fopen(MAIL_CONF, "w")) == NULL){
		_dprintf("fail to open %s\n", MAIL_CONF);
		return;
	}

#if defined(RTCONFIG_NVRAM_ENCRYPT)
	pw_dec(nvram_get("PM_SMTP_AUTH_PASS"), smtp_auth_pass);
#elif defined(RTCONFIG_HTTPS)
	pwdec(nvram_get("PM_SMTP_AUTH_PASS"), smtp_auth_pass);
#else
	strncpy(smtp_auth_pass,nvram_get("PM_SMTP_AUTH_PASS"),256);
#endif

	fprintf(fp,"SMTP_SERVER = '%s'\n", nvram_safe_get("PM_SMTP_SERVER"));
	fprintf(fp,"SMTP_PORT = '%s'\n", nvram_safe_get("PM_SMTP_PORT"));
	fprintf(fp,"MY_NAME = 'Administrator'\n");
	fprintf(fp,"MY_EMAIL = '%s'\n", nvram_safe_get("PM_MY_EMAIL"));
	fprintf(fp,"USE_TLS = 'true'\n");
	fprintf(fp,"SMTP_AUTH = 'LOGIN'\n");
	fprintf(fp,"SMTP_AUTH_USER = '%s'\n", nvram_safe_get("PM_SMTP_AUTH_USER"));
	fprintf(fp,"SMTP_AUTH_PASS = '%s'\n", smtp_auth_pass);
	fclose(fp);
}

static void am_setup_email_item(const char *f_name, const char *val)
{
	char buf[128];
	
	snprintf(buf, sizeof(buf), MAIL_ITEM_PATH"/%s", f_name);
	f_write_string(buf, val, 0, 0);
}

void am_setup_email_info()
{
	mkdir_if_none(MAIL_ITEM_PATH);
	am_setup_email_item(MODEL_NAME, get_productid()); // model name
	am_setup_email_item(SYSTEM_LANGUAGE, nvram_safe_get("preferred_lang")); // current language
	am_setup_email_item(MAIL_TO, nvram_safe_get("NOTIFY_MAIL_TO"));
}

#ifdef RTCONFIG_BWDPI
static
void am_tm_wrs_mail()
{
	if (f_exists(BWDPI_MON_VP)) {
		// copy the same file into another one to avoid trigger event loop issue
		eval("cp", BWDPI_MON_VP, NT_MON_VP, "-f");

		// remove the origin file to avoid trigger again
		eval("rm", BWDPI_MON_VP, "-f");

		char str[32];
		snprintf(str, 32, "0x%x", PROTECTION_VULNERABILITY_EVENT);
		eval("Notify_Event2NC", str, "");
	}

	if (f_exists(BWDPI_MON_CC)) {
		// copy the same file into another one to avoid trigger event loop issue
		eval("cp", BWDPI_MON_CC, NT_MON_CC, "-f");

		// remove the origin file to avoid trigger again
		eval("rm", BWDPI_MON_CC, "-f");

		char str[32];
		snprintf(str, 32, "0x%x", PROTECTION_CC_EVENT);
		eval("Notify_Event2NC", str, "");
	}

	if (f_exists(BWDPI_MON_MALS)) {
		// copy the same file into another one to avoid trigger event loop issue
		eval("cp", BWDPI_MON_MALS, NT_MON_MALS, "-f");

		// remove the origin file to avoid trigger again
		eval("rm", BWDPI_MON_MALS, "-f");

		char str[32];
		snprintf(str, 32, "0x%x", PROTECTION_MALICIOUS_SITE_EVENT);
		eval("Notify_Event2NC", str, "");
	}
}
#endif

#ifdef RTCONFIG_TRAFFIC_LIMITER
static
void am_traffic_limiter_mail()
{
	char str[32];
	unsigned int flag = traffic_limiter_read_bit("alert");
	unsigned int val = traffic_limiter_read_bit("count"); // have sent
	int send = 0;

	AM_DBG("flag=%u, val=%u\n", flag, val);

	if ((flag & 0x1) && !(val & 0x01)) {
		// send alert SMS
		//if(nvram_get_int("modem_sms_limit")) traffic_limiter_sendSMS("alert", 0);
		send = 1;
	}
	if ((flag & 0x2) && !(val & 0x02)) {
		// send alert SMS
		//if(nvram_get_int("modem_sms_limit")) traffic_limiter_sendSMS("alert", 1);
		send = 1;
	}

	// send alert mail
	if (send) {
		snprintf(str, 32, "0x%x", TRAFFICMETER_ALERT_EVENT);
		eval("Notify_Event2NC", str, "");
	}
}
#endif

static
int alert_mail_function_check()
{
	// intial global variable
	value = 0;

#ifdef RTCONFIG_BWDPI
	// TrendMicro wrs mail
	if (check_wrs_switch())
		value |= TM_WRS_MAIL;
#endif

#ifdef RTCONFIG_TRAFFIC_LIMITER
	// traffic limiter mail
	if (nvram_get_int("tl_enable") && (nvram_get_int("tl0_alert_enable") || nvram_get_int("tl1_alert_enable")))
		value |= TRAFFIC_LIMITER_MAIL;
#endif

	// TODO: add new here

	AM_DBG("value = %d(0x%x)\n", value, value);

	return value;
}

void alert_mail_service()
{
	// check function enable or not
	if (!alert_mail_function_check())
		return;

#ifdef RTCONFIG_BWDPI
	if (value & TM_WRS_MAIL)
		am_tm_wrs_mail();
#endif

#ifdef RTCONFIG_TRAFFIC_LIMITER
	if (value & TRAFFIC_LIMITER_MAIL)
		am_traffic_limiter_mail();
#endif
	
	// TODO: add new here
}
