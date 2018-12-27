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
<script language="JavaScript" type="text/javascript" src="/jquery.js"></script>
<script>
var $j = jQuery.noConflict();
var adsl_timestamp = parseInt("<% nvram_get("adsl_timestamp"); %>");
var adsl_boottime = boottime - adsl_timestamp;

var log_lineState = "<% nvram_get("dsltmp_adslsyncsts"); %>";
var log_Opmode;
var log_AdslType;
var log_SNRMarginDown;
var log_SNRMarginUp;
var log_AttenDown;
var log_AttenUp;
var log_WanListMode;
var log_DataRateDown;
var log_DataRateUp;
var log_AttainDown;
var log_AttainUp;
var log_PowerDown;
var log_PowerUp;
var log_CRCDown;
var log_CRCUp;

function update_log(){
	$j.ajax({
		url: 'ajax_AdslStatus.asp',
		dataType: 'script',
		error: function(xhr){
				setTimeout("update_log();", 1000);
			},
 	
		success: function(){
				document.getElementById("div_lineState").innerHTML = log_lineState;
				document.getElementById("up_modul").innerHTML = log_Opmode;
				document.getElementById("up_annex").innerHTML = log_AdslType;
				document.getElementById("up_SNR_down").innerHTML = log_SNRMarginDown;
				document.getElementById("up_SNR_up").innerHTML = log_SNRMarginUp;
				document.getElementById("up_Line_down").innerHTML = log_AttenDown;
				document.getElementById("up_Line_up").innerHTML = log_AttenUp;
				document.getElementById("up_wan_mode").innerHTML = log_WanListMode;
				document.getElementById("up_rate_down").innerHTML = log_DataRateDown;
				document.getElementById("up_rate_up").innerHTML = log_DataRateUp;
				document.getElementById("up_maxrate_down").innerHTML = log_AttainDown;
				document.getElementById("up_maxrate_up").innerHTML = log_AttainUp;
				document.getElementById("up_power_down").innerHTML = log_PowerDown;
				document.getElementById("up_power_up").innerHTML = log_PowerUp;
				document.getElementById("up_CRC_down").innerHTML = log_CRCDown;
				document.getElementById("up_CRC_up").innerHTML = log_CRCUp;				
				check_adsl_state_up();				
					
				setTimeout("update_log();", 5000);
			}	
	});		
}

function initial(){
	show_menu();
	showadslbootTime();
	check_adsl_state_up();	
	setTimeout("update_log();", 5000);
}

function check_adsl_state_up(){
		if(log_lineState == "up"){
				
				document.getElementById("up_modul").style.display = "";				
				document.getElementById("up_annex").style.display = "";
				document.getElementById("up_SNR_down").style.display = "";
				document.getElementById("up_SNR_up").style.display = "";
				document.getElementById("up_Line_down").style.display = "";
				document.getElementById("up_Line_up").style.display = "";
				document.getElementById("up_wan_mode").style.display = "";
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
				document.getElementById("up_wan_mode").style.display = "none";
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
	
	if(adsl_timestamp != "" && (log_lineState == "up"))
	{
		Days = Math.floor(adsl_boottime / (60*60*24));
		Hours = Math.floor((adsl_boottime / 3600) % 24);
		Minutes = Math.floor(adsl_boottime % 3600 / 60);
		Seconds = Math.floor(adsl_boottime % 60);

		$("boot_days").innerHTML = Days;
		$("boot_hours").innerHTML = Hours;
		$("boot_minutes").innerHTML = Minutes;
		$("boot_seconds").innerHTML = Seconds;
		adsl_boottime += 1;
		setTimeout("showadslbootTime()", 1000);
	}
	else
	{
		$("boot_days").innerHTML = "0";
		$("boot_hours").innerHTML = "0";
		$("boot_minutes").innerHTML = "0";
		$("boot_seconds").innerHTML = "0";
		
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
									<div id="up_annex"><% nvram_get("dsllog_adsltype"); %></div>
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
								<th width="20%">Path Mode</th>
								<td>
									<div id="up_wan_mode"><% nvram_get("dsllog_wanlistmode"); %></div>
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
