uptimeStr = "<% uptime(); %>";
boottime = parseInt(uptimeStr.substring(32,42));
sync_status_update = "<% nvram_get("dsltmp_adslsyncsts"); %>";
adsl_timestamp_update = parseInt("<% nvram_get("adsl_timestamp"); %>");
log_Opmode="<% nvram_get("dsllog_opmode"); %>";
log_AdslType="<% nvram_get("dsllog_adsltype"); %>".replace("_", " ");
log_SNRMarginDown="<% nvram_get("dsllog_snrmargindown"); %>";
log_SNRMarginUp="<% nvram_get("dsllog_snrmarginup"); %>";
log_AttenDown="<% nvram_get("dsllog_attendown"); %>";
log_AttenUp="<% nvram_get("dsllog_attenup"); %>";
log_TCM="<% nvram_get("dsllog_tcm"); %>";
log_PathModeDown="<% nvram_get("dsllog_pathmodedown"); %>";
log_IntDepthDown="<% nvram_get("dsllog_interleavedepthdown"); %>";
log_PathModeUp="<% nvram_get("dsllog_pathmodeup"); %>";
log_IntDepthUp="<% nvram_get("dsllog_interleavedepthup"); %>";
log_WanListMode="<% nvram_get("dsllog_wanlistmode"); %>";
log_DataRateDown="<% nvram_get("dsllog_dataratedown"); %>";
log_DataRateUp="<% nvram_get("dsllog_datarateup"); %>";
log_AttainDown="<% nvram_get("dsllog_attaindown"); %>";
log_AttainUp="<% nvram_get("dsllog_attainup"); %>";
log_PowerDown="<% nvram_get("dsllog_powerdown"); %>";
log_PowerUp="<% nvram_get("dsllog_powerup"); %>";
log_CRCDown="<% nvram_get("dsllog_crcdown"); %>";
log_CRCUp="<% nvram_get("dsllog_crcup"); %>";


