<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#Web_Title#> - <#menu_dsl_log#></title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">

<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script language="JavaScript" type="text/javascript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/js/jquery.js"></script>
<script>

var adsl_timestamp = parseInt("<% nvram_get("adsl_timestamp"); %>");
var sync_status = "<% nvram_get("dsltmp_adslsyncsts"); %>";
var adsl_timestamp_update = parseInt("<% nvram_get("adsl_timestamp"); %>");
var sync_status_update = "<% nvram_get("dsltmp_adslsyncsts"); %>";
var adsl_boottime = boottime - adsl_timestamp;
var dsl_type = "<% nvram_get("dsllog_adsltype"); %>".replace("_", " ");

var log_Opmode;
var log_AdslType;
var log_SNRMarginDown;
var log_SNRMarginUp;
var log_AttenDown;
var log_AttenUp;
var log_TCM;
var log_PathModeDown;
var log_IntDepthDown;
var log_PathModeUp;
var log_IntDepthUp;
var log_WanListMode;
var log_DataRateDown;
var log_DataRateUp;
var log_AttainDown;
var log_AttainUp;
var log_PowerDown;
var log_PowerUp;
var log_CRCDown;
var log_CRCUp;
var log_VDSL_CurrentProfile;

function update_log(){
	$.ajax({
		url: 'ajax_AdslStatus.asp',
		dataType: 'script',
		error: function(xhr){
				setTimeout("update_log();", 1000);
			},
 	
		success: function(){
				if(adsl_timestamp_update != "" && sync_status != sync_status_update){
					adsl_boottime = boottime - adsl_timestamp_update;
					showadslbootTime();
				}
				
				sync_status = sync_status_update;
				document.getElementById("div_lineState").innerHTML = sync_status_update;
				document.getElementById("up_modul").innerHTML = log_Opmode;
				document.getElementById("up_annex").innerHTML = log_AdslType;
				document.getElementById("up_SNR_down").innerHTML = log_SNRMarginDown;
				document.getElementById("up_SNR_up").innerHTML = log_SNRMarginUp;
				document.getElementById("up_Line_down").innerHTML = log_AttenDown;
				document.getElementById("up_Line_up").innerHTML = log_AttenUp;
				document.getElementById("div_TCM").innerHTML = log_TCM;
				document.getElementById("div_PathModeDown").innerHTML = log_PathModeDown;
				document.getElementById("div_IntDepthDown").innerHTML = log_IntDepthDown;
				document.getElementById("div_PathModeUp").innerHTML = log_PathModeUp;
				document.getElementById("div_IntDepthUp").innerHTML = log_IntDepthUp;
				document.getElementById("up_rate_down").innerHTML = log_DataRateDown;
				document.getElementById("up_rate_up").innerHTML = log_DataRateUp;
				document.getElementById("up_maxrate_down").innerHTML = log_AttainDown;
				document.getElementById("up_maxrate_up").innerHTML = log_AttainUp;
				document.getElementById("up_power_down").innerHTML = log_PowerDown;
				document.getElementById("up_power_up").innerHTML = log_PowerUp;
				document.getElementById("up_CRC_down").innerHTML = log_CRCDown;
				document.getElementById("up_CRC_up").innerHTML = log_CRCUp;				
				document.getElementById("div_VDSL_CurrentProfile").innerHTML = log_VDSL_CurrentProfile;
				check_adsl_state_up();				
					
				setTimeout("update_log();", 5000);
			}	
	});		
}

function initial(){
	show_menu();
	showadslbootTime();
	check_adsl_state_up();
	document.getElementById("up_annex").innerHTML = dsl_type;
	setTimeout("update_log();", 5000);
}

function check_adsl_state_up(){
		if(sync_status == "up"){
				
				document.getElementById("up_modul").style.display = "";				
				document.getElementById("up_annex").style.display = "";
				document.getElementById("up_SNR_down").style.display = "";
				document.getElementById("up_SNR_up").style.display = "";
				document.getElementById("up_Line_down").style.display = "";
				document.getElementById("up_Line_up").style.display = "";
				document.getElementById("div_TCM").style.display = "";
				document.getElementById("div_PathModeDown").style.display = "";
				document.getElementById("div_IntDepthDown").style.display = "";
				document.getElementById("div_PathModeUp").style.display = "";
				document.getElementById("div_IntDepthUp").style.display = "";
				document.getElementById("up_rate_down").style.display = "";
				document.getElementById("up_rate_up").style.display = "";
				document.getElementById("up_maxrate_down").style.display = "";
				document.getElementById("up_maxrate_up").style.display = "";
				document.getElementById("up_power_down").style.display = "";
				document.getElementById("up_power_up").style.display = "";
				document.getElementById("up_CRC_down").style.display = "";
				document.getElementById("up_CRC_up").style.display = "";
		
		}
		else{
				
				document.getElementById("up_modul").style.display = "none";
				document.getElementById("up_annex").style.display = "none";
				document.getElementById("up_SNR_down").style.display = "none";
				document.getElementById("up_SNR_up").style.display = "none";
				document.getElementById("up_Line_down").style.display = "none";
				document.getElementById("up_Line_up").style.display = "none";
				document.getElementById("div_TCM").style.display = "none";
				document.getElementById("div_PathModeDown").style.display = "none";
				document.getElementById("div_IntDepthDown").style.display = "none";
				document.getElementById("div_PathModeUp").style.display = "none";
				document.getElementById("div_IntDepthUp").style.display = "none";
				document.getElementById("up_rate_down").style.display = "none";
				document.getElementById("up_rate_up").style.display = "none";
				document.getElementById("up_maxrate_down").style.display = "none";
				document.getElementById("up_maxrate_up").style.display = "none";
				document.getElementById("up_power_down").style.display = "none";
				document.getElementById("up_power_up").style.display = "none";
				document.getElementById("up_CRC_down").style.display = "none";
				document.getElementById("up_CRC_up").style.display = "none";
				
		}
}

function showadslbootTime(){
	
	if(adsl_timestamp_update != "" && sync_status_update == "up"){
		
		if(adsl_boottime < 0)
			adsl_boottime = boottime - adsl_timestamp_update;
		Days = Math.floor(adsl_boottime / (60*60*24));
		Hours = Math.floor((adsl_boottime / 3600) % 24);
		Minutes = Math.floor(adsl_boottime % 3600 / 60);
		Seconds = Math.floor(adsl_boottime % 60);

		document.getElementById("boot_days").innerHTML = Days;
		document.getElementById("boot_hours").innerHTML = Hours;
		document.getElementById("boot_minutes").innerHTML = Minutes;
		document.getElementById("boot_seconds").innerHTML = Seconds;
		adsl_boottime += 1;
		setTimeout("showadslbootTime()", 1000);
	}
	else
	{
		document.getElementById("boot_days").innerHTML = "0";
		document.getElementById("boot_hours").innerHTML = "0";
		document.getElementById("boot_minutes").innerHTML = "0";
		document.getElementById("boot_seconds").innerHTML = "0";
		
	}
}

</script>
</head>

<body onload="initial();" onunLoad="return unload_body();">
<div id="TopBanner"></div>

<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<form method="post" name="form" action="apply.cgi" target="hidden_frame">
<input type="hidden" name="current_page" value="Main_AdslStatus_Content.asp">
<input type="hidden" name="next_page" value="Main_AdslStatus_Content.asp">
<input type="hidden" name="group_id" value="">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="">
<input type="hidden" name="action_wait" value="">
<input type="hidden" name="first_time" value="">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
</form>
<table class="content" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td width="17">&nbsp;</td>
		<td valign="top" width="202">
			<div id="mainMenu"></div>
			<div id="subMenu"></div>
		</td>

		<td valign="top">
			<div id="tabMenu" class="submenuBlock"></div>

			<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
				<tr>
					<td align="left" valign="top">

			<table width="760px" border="0" cellpadding="5" cellspacing="0" bordercolor="#6b8fa3"  class="FormTitle" id="FormTitle">
			<tr>
		  		<td bgcolor="#4D595D" colspan="3" valign="top">
		  			<div>&nbsp;</div>
		  			<div class="formfonttitle"><#System_Log#> - <#menu_dsl_log#></div>
		  			<div style="margin-left:5px;margin-top:10px;margin-bottom:10px"><img src="/images/New_ui/export/line_export.png"></div>
		  			<div class="formfontdesc"><#GeneralLog_title#></div>
						<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
							<tr>
								<th width="20%">DSL <#FW_item2#></th>
								<td>
									<% nvram_get("dsllog_fwver"); %>
								</td>
							</tr>
							<tr>
								<th width="20%"><#adsl_fw_ver_itemname#></th>
								<td>
									<% nvram_get("dsllog_drvver"); %>
								</td>
							</tr>
							<tr>
								<th width="20%"><#adsl_link_sts_itemname#></th>
								<td>
									<div id="div_lineState"><% nvram_get("dsltmp_adslsyncsts"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">DSL <#General_x_SystemUpTime_itemname#></th>
								<td>
									<div id="up_uptime"><span id="boot_days"></span> <#Day#> <span id="boot_hours"></span> <#Hour#> <span id="boot_minutes"></span> <#Minute#> <span id="boot_seconds"></span> <#Second#></div>
								</td>
							</tr>
							
							<tr>
								<th width="20%"><#dslsetting_disc1#></th>
								<td>
									<div id="up_modul"><% nvram_get("dsllog_opmode"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%"><#dslsetting_disc2#></th>
								<td>
									<div id="up_annex"></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Current Profile</th>
								<td>
									<div id="div_VDSL_CurrentProfile"><% nvram_get("dsllog_vdslcurrentprofile"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">SNR Down</th>
								<td>
									<div id="up_SNR_down"><% nvram_get("dsllog_snrmargindown"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">SNR Up</th>
								<td>
									<div id="up_SNR_up"><% nvram_get("dsllog_snrmarginup"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Line Attenuation Down</th>
								<td>
									<div id="up_Line_down"><% nvram_get("dsllog_attendown"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Line Attenuation Up</th>
								<td>
									<div id="up_Line_up"><% nvram_get("dsllog_attenup"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">TCM(Trellis Coded Modulation)</th>
								<td>
									<div id="div_TCM"><% nvram_get("dsllog_tcm"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Path Mode Down</th>
								<td>
									<div id="div_PathModeDown"><% nvram_get("dsllog_pathmodedown"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Interleave Depth Down</th>
								<td>
									<div id="div_IntDepthDown"><% nvram_get("dsllog_interleavedepthdown"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Path Mode Up</th>
								<td>
									<div id="div_PathModeUp"><% nvram_get("dsllog_pathmodeup"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Interleave Depth Up</th>
								<td>
									<div id="div_IntDepthUp"><% nvram_get("dsllog_interleavedepthup"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Data Rate Down</th>
								<td>
									<div id="up_rate_down"><% nvram_get("dsllog_dataratedown"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">Data Rate Up</th>
								<td>
									<div id="up_rate_up"><% nvram_get("dsllog_datarateup"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">MAX Rate Down</th>
								<td>
									<div id="up_maxrate_down"><% nvram_get("dsllog_attaindown"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">MAX Rate Up</th>
								<td>
									<div id="up_maxrate_up"><% nvram_get("dsllog_attainup"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">POWER Down</th>
								<td>
									<div id="up_power_down"><% nvram_get("dsllog_powerdown"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">POWER Up</th>
								<td>
									<div id="up_power_up"><% nvram_get("dsllog_powerup"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">CRC Down</th>
								<td>
									<div id="up_CRC_down"><% nvram_get("dsllog_crcdown"); %></div>
								</td>
							</tr>
							<tr>
								<th width="20%">CRC Up</th>
								<td>
									<div id="up_CRC_up"><% nvram_get("dsllog_crcup"); %></div>
								</td>
							</tr>

						</table>
					</td>
			</tr>

			<tr class="apply_gen" valign="top">
				<!--td width="20%" align="center">
						<input type="submit" onClick="onSubmitCtrl(this, ' Save ')" value="<#CTL_onlysave#>" class="button_gen">
				</td-->
				<td width="40%" align="center">
					<form method="post" name="form3" action="apply.cgi">
						<input type="hidden" name="current_page" value="Main_AdslStatus_Content.asp">
						<input type="hidden" name="action_mode" value=" Refresh ">
						<input type="button" onClick="location.href=location.href" value="<#CTL_refresh#>" class="button_gen">
					</form>
				</td>
			</tr>
			</table>
		</td>

	</tr>
</table>
      <!--===================================Ending of Main Content===========================================-->
</td>
      <td width="10" align="center" valign="top"></td>
  </tr>
</table>
<div id="footer"></div>
		</form>
</body>
</html>
