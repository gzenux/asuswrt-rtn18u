/*
	for traffic limiter hook
	
	NOTE:
		traffic unit in database : KB (Kbytes)
*/

#include "traffic_limiter.h"

int sql_get_table(sqlite3 *db, const char *sql, char ***pazResult, int *pnRow, int *pnColumn)
{
	int ret;
	char *errMsg = NULL;
	
	ret = sqlite3_get_table(db, sql, pazResult, pnRow, pnColumn, &errMsg);
	if (ret != SQLITE_OK)
	{
		if (errMsg) sqlite3_free(errMsg);
	}

	return ret;
}

void sqlite_result_check(int ret, char *zErr, const char *msg)
{
	if(ret != SQLITE_OK){
		if(zErr != NULL){
			TL_DBG("%s - SQL error: %s\n", msg, zErr);
			sqlite3_free(zErr);
		}
	}
}

static
long long int traffic_limiter_realtime_traffic(char *interface, int unit)
{
	long long int result = 0;
	FILE *fp = NULL;
	unsigned long long tx = 0, rx = 0;	// current
	unsigned long long tx_t = 0, rx_t = 0;	// old
	unsigned long long tx_n = 0, rx_n = 0;	// diff
	char ifmap[IFNAME_MAX];	// ifname after mapping
	char wanif[IFNAME_MAX];
	char buf[256];
	char tx_buf[IFPATH_MAX], rx_buf[IFPATH_MAX];
	char tx_path[IFPATH_MAX], rx_path[IFPATH_MAX];
	char *p = NULL;
 	char *ifname = NULL;

	memset(buf, 0, sizeof(buf));
	memset(ifmap, 0, sizeof(ifmap));
	ifname_mapping(interface, ifmap); // database interface mapping
	TL_DBG("interface=%s, ifmap=%s\n", interface, ifmap);

	snprintf(tx_path, sizeof(tx_path), TL_PATH"%s/tx_t", ifmap);
	snprintf(rx_path, sizeof(rx_path), TL_PATH"%s/rx_t", ifmap);

 	if ((fp = fopen("/proc/net/dev", "r")) != NULL)
	{
		// skip first two rows
		fgets(buf, sizeof(buf), fp);
		fgets(buf, sizeof(buf), fp);

		while (fgets(buf, sizeof(buf), fp))
		{
			int match = 0;

			// search interface
			if ((p = strchr(buf, ':')) == NULL) continue;
			*p = 0;
			if ((ifname = strrchr(buf, ' ')) == NULL)
				ifname = buf;
			else
				++ifname;

			snprintf(wanif, sizeof(wanif), "wan%d_ifname", unit);
			if (strcmp(ifname, nvram_safe_get(wanif)))
				continue;
			else
				match = 1;

			// search traffic
			if (sscanf(p + 1, "%llu%*u%*u%*u%*u%*u%*u%*u%llu", &rx, &tx) != 2) continue;

			// tx / rx unit = KB
			tx = tx / 1024;
			rx = rx / 1024;
			
			if (f_read_string(tx_path, tx_buf, sizeof(tx_buf)) > 0)
				tx_t = strtoull(tx_buf, NULL, 10);
			else
				tx_t = 0;

			if (f_read_string(rx_path, rx_buf, sizeof(rx_buf)) > 0)
				rx_t = strtoull(rx_buf, NULL, 10);
			else
				rx_t = 0;

			// proc/net/dev max bytes is unsigned long (2^32)
			// diff traffic
			if(tx < tx_t)
				tx_n = (tx + LONGSIZE) - tx_t;
			else
				tx_n = tx - tx_t;
				
			if(rx < rx_t)
				rx_n = (rx + LONGSIZE) - rx_t;
			else
				rx_n = rx - rx_t;

			result = tx_n + rx_n;

			// debug message
			TL_DBG("tx/tx_t/tx_n = %16llu/%16lld/%16lld\n", tx, tx_t, tx_n);
			TL_DBG("rx/rx_t/rx_n = %16llu/%16lld/%16lld\n", rx, rx_t, rx_n);

			if(match) break;
		}
		fclose(fp);
	}

	return result;
}

void traffic_limiter_WanStat(char *buf, char *ifname, char *start, char *end, int unit)
{
	if (ifname == NULL || start == NULL || end == NULL ||
		(strcmp(ifname, "wan") && strcmp(ifname, "lan") && strcmp(ifname, "usb")))
	{
		sprintf(buf, "[0]");
		return;
	}

	int lock;	// file lock
	int ret;
	char path[IFPATH_MAX];
	char ifmap[IFNAME_MAX];	// ifname after mapping
	char sql[256];
	char cmd[256];
	char tmp[32];
	sqlite3 *db;
	int rows;
	int cols;
	char **result;
	time_t ts, te;
	long long int tx = 0, rx = 0, current = 0;
	time_t now;
	int divide = 1; // if BRCM && eth0 only, need to divide by 2

	lock = file_lock("traffic_limiter");

	// word and ifmap mapping
	ifname_mapping(ifname, ifmap); // database interface mapping
	TL_DBG("ifname=%s, ifmap=%s, start=%s, end=%s, unit=%d\n", ifname, ifmap, start, end, unit);

	snprintf(path, sizeof(path), TL_PATH"%s/traffic.db", ifmap);

#if !defined(RTCONFIG_QCA) && !defined(RTCONFIG_RALINK)
	// check eth0 only
	char *wan_if = nvram_safe_get("wans_dualwan");
	if ( ((strstr(wan_if, "none") && strstr(wan_if, "wan")) || (strstr(wan_if, "usb") && strstr(wan_if, "wan")))
		&& !strcmp(ifmap, "wan") )
		divide = 2;
	TL_DBG("wan_if=%s, ifmap=%s, divide=%d\n", wan_if, ifmap, divide);
#endif

	ret = sqlite3_open(path, &db);
	if (ret) {
		TL_DBG("CAN'T open database %s\n", sqlite3_errmsg(db));
		sprintf(buf, "[0]");
		sqlite3_close(db);
		file_unlock(lock);
		return;
	}
	
	ts = atoll(start);
	te = atoll(end);
	sprintf(sql, "SELECT ifname, SUM(tx), SUM(rx) FROM (SELECT timestamp, ifname, tx, rx FROM traffic WHERE timestamp BETWEEN %ld AND %ld) WHERE ifname = \"%s\"",
		(ts - 30), (te + 30), ifmap);

	// get current timestamp
	time(&now);
	
	// real-time traffic (not data in database)
	if ((te - now) < DAY && (te - now) > 0) {
		TL_DBG("Real-Time UPDATE /jffs/tld/%s/tmp\n", ifmap);
		current = traffic_limiter_realtime_traffic(ifname, unit);
		sprintf(cmd, TL_PATH"%s/tmp", ifmap);
		sprintf(tmp, "%lld", current);
		f_write_string(cmd, tmp, 0, 0);
	}

	if (sql_get_table(db, sql, &result, &rows, &cols) == SQLITE_OK)
	{
		int i = 0;
		int j = 0;
		int index = cols;
		for (i = 0; i < rows; i++) {
			for (j = 0; j < cols; j++) {
				if (j == 1) tx = (result[index] == NULL) ? 0 : atoll(result[index]);
				if (j == 2) rx = (result[index] == NULL) ? 0 : atoll(result[index]);
				sprintf(buf, "[%llu]", (tx + rx + current)/divide);
				++index;
			}
			// debug usage
			TL_LOG("ifname=%s, start=%s, end=%s, current=%lld, divide=%d, buf=%s", ifname, start, end, current, divide, buf); // /tmp/TLD.log
		}
		sqlite3_free_table(result);
	}

	TL_DBG("ifname=%s, start=%s, end=%s, current=%lld, divide=%d, buf=%s\n", ifname, start, end, current, divide, buf);
	if (!strcmp(buf, "")) {
		if(current != 0) 
			sprintf(buf, "[%lld]", current);
		else
			sprintf(buf, "[0]");
	}

	sqlite3_close(db);
	file_unlock(lock);
}

void traffic_limiter_hook(char *ifname, char *start, char *end, char *unit, int *retval, webs_t wp)
{
	char buf[64];
	int unit_t = atoi(unit);
	memset(buf, 0, sizeof(buf));

	traffic_limiter_WanStat(buf, ifname, start, end, unit_t);
	
	*retval += websWrite(wp, buf);
}

/*
	interface mapping rule
	ex.
	word = wan / lan / usb
	ifname = wan / lan / usb / imsi(number)
*/
void ifname_mapping(char *word, char *ifname)
{
	if (!strcmp(word, "usb") && nvram_get_int("usb_modem_act_imsi"))
		sprintf(ifname, nvram_safe_get("usb_modem_act_imsi"));
	else
		sprintf(ifname, word);
}
