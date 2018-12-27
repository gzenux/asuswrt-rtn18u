<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<meta HTTP-EQUIV="refresh" CONTENT="10">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#Web_Title#> - <#menu_dsl_log#></title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">

<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script language="JavaScript" type="text/javascript" src="/help.js"></script>
<script>
wan_route_x = '<% nvram_get("wan_route_x"); %>';
wan_nat_x = '<% nvram_get("wan_nat_x"); %>';
wan_proto = '<% nvram_get("wan_proto"); %>';
var sync_status = "<% nvram_get("dsltmp_adslsyncsts"); %>";
var adsl_timestamp = "<% nvram_get("adsl_timestamp"); %>";
var adsl_boottime = boottime - parseInt(adsl_timestamp);

function initial(){
	show_menu();
	showadslbootTime();	
}

function showadslbootTime(){
	if((adsl_timestamp != "") && (sync_status == "up"))
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
									<% nvram_get("dsltmp_adslsyncsts"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">DSL <#General_x_SystemUpTime_itemname#></th>
								<td>
									<span id="boot_days"></span> <#Day#> <span id="boot_hours"></span> <#Hour#> <span id="boot_minutes"></span> <#Minute#> <span id="boot_seconds"></span> <#Second#>
								</td>
							</tr>
							
							<tr>
								<th width="20%"><#dslsetting_disc1#></th>
								<td>
									<% nvram_get("dsllog_opmode"); %>
								</td>
							</tr>
							<tr>
								<th width="20%"><#dslsetting_disc2#></th>
								<td>
									<% nvram_get("dsllog_adsltype"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">SNR Down</th>
								<td>
									<% nvram_get("dsllog_snrmargindown"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">SNR Up</th>
								<td>
									<% nvram_get("dsllog_snrmarginup"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">Line Attenuation Down</th>
								<td>
									<% nvram_get("dsllog_attendown"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">Line Attenuation Up</th>
								<td>
									<% nvram_get("dsllog_attenup"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">Path Mode</th>
								<td>
									<% nvram_get("dsllog_wanlistmode"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">Data Rate Down</th>
								<td>
									<% nvram_get("dsllog_dataratedown"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">Data Rate Up</th>
								<td>
									<% nvram_get("dsllog_datarateup"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">MAX Rate Down</th>
								<td>
									<% nvram_get("dsllog_attaindown"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">MAX Rate Up</th>
								<td>
									<% nvram_get("dsllog_attainup"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">POWER Down</th>
								<td>
									<% nvram_get("dsllog_powerdown"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">POWER Up</th>
								<td>
									<% nvram_get("dsllog_powerup"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">CRC Down</th>
								<td>
									<% nvram_get("dsllog_crcdown"); %>
								</td>
							</tr>
							<tr>
								<th width="20%">CRC Up</th>
								<td>
									<% nvram_get("dsllog_crcup"); %>
								</td>
							</tr>

						</table>
					</td>
			</tr>

			<tr class="apply_gen" valign="top">
				<!--td width="20%" align="center">
						<input type="submit" onClick="onSubmitCtrl(this, ' Save ')" value="<#CTL_onlysave#>" class="button_gen">
				</td-->
				<td width="40%" align="center" >
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
