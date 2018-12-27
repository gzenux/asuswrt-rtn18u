<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#Web_Title#> - <#menu5_4_4#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="other.css">
<style>
.contentM_qis{
	position:absolute;
	-webkit-border-radius: 5px;
	-moz-border-radius: 5px;
	border-radius: 5px;
	z-index:200;
	background-color:#2B373B;
	display:none;
	margin-left: 30%;
	margin-top: 10px;
	width:650px;
}
#ClientList_Block_PC{
	border:1px outset #999;
	background-color:#576D73;
	position:absolute;
	*margin-top:26px;	
	margin-left:2px;
	*margin-left:-189px;
	width:181px;
	text-align:left;	
	height:auto;
	overflow-y:auto;
	z-index:200;
	padding: 1px;
	display:none;
}
#ClientList_Block_PC div{
	background-color:#576D73;
	height:auto;
	*height:20px;
	line-height:20px;
	text-decoration:none;
	font-family: Lucida Console;
	padding-left:2px;
}

#ClientList_Block_PC a{
	background-color:#EFEFEF;
	color:#FFF;
	font-size:12px;
	font-family:Arial, Helvetica, sans-serif;
	text-decoration:none;	
}
#ClientList_Block_PC div:hover, #ClientList_Block a:hover{
	background-color:#3366FF;
	color:#FFFFFF;
	cursor:default;
}
.contentM_qis{
	position:absolute;
	-webkit-border-radius: 5px;
	-moz-border-radius: 5px;
	border-radius: 5px;
	z-index:200;
	background-color:#2B373B;
	display:none;
	margin-left: 30%;
	margin-top: 10px;
	width:650px;
}	
</style>	
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/validator.js"></script>
<script type="text/javascript" src="/wcdma_list.js"></script>
<script type="text/javaScript" src="/jquery.js"></script>
<script>

<% login_state_hook(); %>
var wireless = [<% wl_auth_list(); %>];	// [[MAC, associated, authorized], ...]
var country = '<% nvram_get("modem_country"); %>';
var isp = '<% nvram_get("modem_isp"); %>';
var apn = '<% nvram_get("modem_apn"); %>';
var dialnum = '<% nvram_get("modem_dialnum"); %>';
var user = '<% nvram_get("modem_user"); %>';
var pass = '<% nvram_get("modem_pass"); %>';
var modem_limit_unit = '<% nvram_get("modem_limit_unit"); %>';
var modem_warning_unit = '<% nvram_get("modem_warning_unit"); %>';

var modemlist = new Array();
var countrylist = new Array();
var protolist = new Array();
var isplist = new Array();
var apnlist = new Array();
var daillist = new Array();
var userlist = new Array();
var passlist = new Array();

var KBytes = 1024;
var MBytes = 1024*1024;
var GBytes = 1024*1024*1024;

var mobile_state = -1;
var mobile_sbstate = -1;
var mobile_auxstate = -1;
var usb_modem_act_auth = '<% nvram_get("usb_modem_act_auth"); %>';
var modem_pincode = '<% nvram_get("modem_pincode"); %>';
var modem_roaming_orig ='<% nvram_get("modem_roaming"); %>';

/* start of DualWAN */ 
var wans_dualwan = '<% nvram_get("wans_dualwan"); %>';
var sim_state = '<% nvram_get("usb_modem_act_sim"); %>';
<% wan_get_parameter(); %>
var wans_hotstandby = '<% nvram_get("wans_standby"); %>';

var $j = jQuery.noConflict();
if(dualWAN_support && wans_dualwan.search("usb") >= 0 ){
	var wan_type_name = wans_dualwan.split(" ")[<% nvram_get("wan_unit"); %>];
	wan_type_name = wan_type_name.toUpperCase();
	switch(wan_type_name){
		case "DSL":
			location.href = "Advanced_DSL_Content.asp";
			break;
		case "WAN":
			location.href = "Advanced_WAN_Content.asp";
			break;
		case "LAN":
			location.href = "Advanced_WAN_Content.asp";
			break;	
		default:
			break;	
	}
}

function genWANSoption(){
	for(i=0; i<wans_dualwan.split(" ").length; i++){
	var wans_dualwan_NAME = wans_dualwan.split(" ")[i].toUpperCase();
		//MODELDEP: DSL-N55U, DSL-N55U-B, DSL-AC68U, DSL-AC68R
		if(wans_dualwan_NAME == "LAN" && 
			(productid == "DSL-N55U" || productid == "DSL-N55U-B" || productid == "DSL-AC68U" || productid == "DSL-AC68R"))	
			wans_dualwan_NAME = "Ethernet WAN";
		else if(wans_dualwan_NAME == "LAN")
			wans_dualwan_NAME = "Ethernet LAN";
		if(wans_dualwan_NAME == "USB" && based_modelid == "4G-AC55U")
			wans_dualwan_NAME = "<#Mobile_title#>";
		document.form.wan_unit.options[i] = new Option(wans_dualwan_NAME, i);
	}
	document.form.wan_unit.selectedIndex = '<% nvram_get("wan_unit"); %>';
}
/* end of DualWAN */ 

function initial(){
	var data_usage = 0;
	var remaining_data = 0;
	var limit_val = parseFloat($("modem_bytes_data_limit").value);
	var warning_val = parseFloat($("modem_bytes_data_warning").value);

	show_menu();

	if( modem_limit_unit == '0' ) //GByes
		$("data_limit").value = parseFloat(Math.round(limit_val/GBytes*1000))/1000;
	else if( modem_limit_unit == '1' ) //MByes
		$("data_limit").value = parseFloat(Math.round(limit_val/MBytes*1000))/1000;		

	if( modem_warning_unit == '0' ) //GByes
		$("data_warning").value = parseFloat(Math.round(warning_val/GBytes*1000))/1000;		
	else if( modem_warning_unit == '1' ) //MByes
		$("data_warning").value = parseFloat(Math.round(warning_val/MBytes*1000))/1000;	

	data_usage = parseFloat('<% nvram_get("modem_bytes_tx_old"); %>')+parseFloat('<% nvram_get("modem_bytes_tx"); %>')+parseFloat('<% nvram_get("modem_bytes_rx_old"); %>')+parseFloat('<% nvram_get("modem_bytes_rx"); %>');

	if(!isNaN(data_usage)){
		if(data_usage < KBytes)
			$("data_usage").innerHTML = data_usage + "&nbsp;Bytes";
		else if(data_usage < MBytes)
			$("data_usage").innerHTML = parseFloat(Math.round(data_usage/KBytes*1000))/1000 + "&nbsp;KBytes";
		else if(data_usage < GBytes)
			$("data_usage").innerHTML = parseFloat(Math.round(data_usage/MBytes*1000))/1000 + "&nbsp;MBytes";
		else
			$("data_usage").innerHTML = parseFloat(Math.round(data_usage/GBytes*1000))/1000 + "&nbsp;GBytes";
	}

	remaining_data = parseFloat('<% nvram_get("modem_bytes_data_limit"); %>') - data_usage;
	if(remaining_data < 0)
		remaining_data = 0;	
	if(!isNaN(remaining_data)){
		if(Math.abs(remaining_data) < KBytes)
			$("remaining_data").innerHTML = remaining_data + "&nbsp;Bytes";
		else if(Math.abs(remaining_data) < MBytes)
			$("remaining_data").innerHTML = parseFloat(Math.round(remaining_data/KBytes*1000))/1000 + "&nbsp;KBytes";
		else if(Math.abs(remaining_data) < GBytes)
			$("remaining_data").innerHTML = parseFloat(Math.round(remaining_data/MBytes*1000))/1000 + "&nbsp;MBytes";
		else
			$("remaining_data").innerHTML = parseFloat(Math.round(remaining_data/GBytes*1000))/1000 + "&nbsp;GBytes";
	}

	if(dualWAN_support && '<% nvram_get("wans_dualwan"); %>'.search("none") < 0){
				genWANSoption();
	}
	else{
		document.form.wan_unit.disabled = true;
		$("WANscap").style.display = "none";	
	}

	switch_modem_mode('<% nvram_get("modem_enable"); %>');
	gen_country_list();
	reloadProfile();

	if(!dualWAN_support){		
		document.getElementById("_APP_Installation").innerHTML = '<table><tbody><tr><td><div class="AiProtection_HomeSecurity"></div></td><td><div style="width:120px;"><#Menu_usb_application#></div></td></tr></tbody></table>';
		document.getElementById("_APP_Installation").className = "menu_clicked";
	}

	if(usb_modem_act_auth == "1" || usb_modem_act_auth == "2"){
		document.form.pin_verify[0].selected = true;
	}
	else if(usb_modem_act_auth == "3"){
		document.form.pin_verify[1].selected = true;
	}
	else if(usb_modem_act_auth == ""){
		getSimAuth();
	}

	if(modem_pincode != "")
		document.form.pincode.value = modem_pincode;

	if(modem_pincode != "")
		document.form.save_pin_ckb.checked = true;
	else
		document.form.save_pin_ckb.checked = false;

	$("pin_remaining").innerHTML = '<#Mobile_remaining_num#>: ';
	$("pin_remaining").innerHTML += pin_remaining_count;

	if(sim_state == "1"){
		$("newtork_type_tr").style.display = "";
		$("connection_type_tr").style.display = "";
		$("modem_pdp_tr").style.display = "";
		$("modem_roaming_tr").style.display = "";
		ShowRoamingOpt(modem_roaming_orig);
	}
	else{
		$("newtork_type_tr").style.display = "none";
		$("connection_type_tr").style.display = "none";
		$("modem_pdp_tr").style.display = "none";
		$("modem_roaming_tr").style.display = "none";
	}

	show_dateList();
	check_sim_state();
	check_connect_status();	
}

function reloadProfile(){
	if(document.form.modem_enable.value == 0)
		return 0;
	gen_list();
	show_ISP_list();
	show_APN_list();
}

function switch_modem_mode(mode){
	document.form.modem_enable.value = mode;
	if(mode == "0"){
		$("connection_table").style.display = 'none';
		$("traffic_table").style.display = 'none';
		$("apn_table").style.display = 'none';
		$("sim_mgnt_table").style.display = 'none';		
		inputCtrl(document.form.connection_type, 0);
		inputCtrl(document.form.modem_pdp, 0);
		document.form.modem_bytes_data_limit.disabled = true;
		document.form.modem_bytes_data_warning.disabled = true;
		inputCtrl(document.form.modem_roaming, 0);
		inputCtrl(document.form.modem_roaming_isp, 0);
		inputCtrl(document.form.modem_enable_option, 0);
		inputCtrl(document.form.modem_country, 0);
		inputCtrl(document.form.modem_isp, 0);
		inputCtrl(document.form.modem_apn, 0);
		inputCtrl(document.form.modem_dialnum, 0);
		inputCtrl(document.form.modem_user, 0);
		inputCtrl(document.form.modem_pass, 0);
		inputCtrl(document.form.modem_idletime, 0);
	}
	else{
		$("connection_table").style.display = '';
		$("traffic_table").style.display = '';
		$("apn_table").style.display = '';
		$("sim_mgnt_table").style.display = '';
		inputCtrl(document.form.connection_type, 1);
		inputCtrl(document.form.modem_pdp, 1);
		document.form.modem_bytes_data_limit.disabled = false;
		document.form.modem_bytes_data_warning.disabled = false;
		inputCtrl(document.form.modem_roaming, 1);
		document.form.modem_roaming_isp.disabled = false;
		ShowRoamingOpt(modem_roaming_orig);
		inputCtrl(document.form.modem_country, 1);
		inputCtrl(document.form.modem_isp, 1);
		inputCtrl(document.form.modem_apn, 1);
		inputCtrl(document.form.modem_dialnum, 1);
		inputCtrl(document.form.modem_user, 1);
		inputCtrl(document.form.modem_pass, 1);
		inputCtrl(document.form.modem_idletime, 1);
	}
}

function modem_enable_act(enable){
	var confirm_str_off = "Hot-Standby will be disabled if Mobile Braodband is disabled. Are you sure you want to disable it?";

	if(enable == "1")
		switch_modem_mode(document.form.modem_enable_option.value);
	else{
		if(confirm(confirm_str_off)){
			document.form.wans_standby.value = "0";
			switch_modem_mode("0");
		}
	}

	reloadProfile();
}

function show_ISP_list(){
	var removeItem = 0;
	free_options(document.form.modem_isp);
	document.form.modem_isp.options.length = isplist.length;

	for(var i = 0; i < isplist.length; i++){
	  if(protolist[i] == 4 && !wimax_support){
			document.form.modem_isp.options.length = document.form.modem_isp.options.length - 1;

			if(document.form.modem_isp.options.length > 0)
				continue;
			else{
				alert('We currently do not support this location, please use "Manual"!');
				document.form.modem_country.focus();
				document.form.modem_country.selectedIndex = countrylist.length-1;
				break;
			}
		}
		else
			document.form.modem_isp.options[i] = new Option(isplist[i], isplist[i]);

		if(isplist[i] == isp)
			document.form.modem_isp.options[i].selected = 1;
	}
}

function show_APN_list(){
	var ISPlist = document.form.modem_isp.value;
	var Countrylist = document.form.modem_country.value;

	var isp_order = -1;
	for(isp_order = 0; isp_order < isplist.length; ++isp_order){
		if(isplist[isp_order] == ISPlist)
			break;
		else if(isp_order == isplist.length-1){
			isp_order = -1;
			break;
		}
	}

	if(isp_order == -1){
		alert("system error");
		return;
	}
	
	/* use manual or location */
	if(document.form.modem_country.value == ""){
		inputCtrl(document.form.modem_isp, 0);
		inputCtrl(document.form.modem_enable_option, 1);
	}
	else{
		inputHideCtrl(document.form.modem_isp, 1);
		inputHideCtrl(document.form.modem_enable_option, 0);
		if(protolist[isp_order] == "")
			protolist[isp_order] = 1;
	}

	if(Countrylist == ""){
		if('<% nvram_get("modem_enable"); %>' == $('modem_enable_option').value){
			$("modem_apn").value = apn;
			$("modem_dialnum").value = dialnum;
			$("modem_user").value = user;
			$("modem_pass").value = pass;
		}
		else{
			$("modem_apn").value = apnlist[isp_order];
			$("modem_dialnum").value = daillist[isp_order];
			$("modem_user").value = userlist[isp_order];
			$("modem_pass").value = passlist[isp_order];
		}
	}
	else if(protolist[isp_order] != "4"){
		if(ISPlist == isp && Countrylist == country && (apn != "" || dialnum != "" || user != "" || pass != "")){
			if(typeof(apnlist[isp_order]) == 'object' && apnlist[isp_order].constructor == Array){
				$("pull_arrow").style.display = '';
				showLANIPList(isp_order);
			}
			else{
				$("pull_arrow").style.display = 'none';
				$('ClientList_Block_PC').style.display = 'none';
			}

			$("modem_apn").value = apn;
			$("modem_dialnum").value = dialnum;
			$("modem_user").value = user;
			$("modem_pass").value = pass;
		}
		else{
			if(typeof(apnlist[isp_order]) == 'object' && apnlist[isp_order].constructor == Array){
				$("pull_arrow").style.display = '';
				showLANIPList(isp_order);
			}
			else{
				$("pull_arrow").style.display = 'none';
				$('ClientList_Block_PC').style.display = 'none';
				$("modem_apn").value = apnlist[isp_order];
			}

			$("modem_dialnum").value = daillist[isp_order];
			$("modem_user").value = userlist[isp_order];
			$("modem_pass").value = passlist[isp_order];
		}
	}
	else{
		$("modem_apn").value = "";
		$("modem_dialnum").value = "";

		if(ISPlist == isp	&& (user != "" || pass != "")){
			$("modem_user").value = user;
			$("modem_pass").value = pass;
		}
		else{
			$("modem_user").value = userlist[isp_order];
			$("modem_pass").value = passlist[isp_order];
		}
	}

	if(document.form.modem_country.value != ""){
		document.form.modem_enable.value = protolist[isp_order];
		switch_modem_mode(document.form.modem_enable.value);
	}
}

function applyRule(){
	if(document.form.modem_limit_unit.value == '0')//GBytes
		$("modem_bytes_data_limit").value = parseFloat($("data_limit").value)*GBytes;
	else if(document.form.modem_limit_unit.value == '1')
		$("modem_bytes_data_limit").value = parseFloat($("data_limit").value)*MBytes;

	if(document.form.modem_warning_unit.value == '0')//GBytes
		$("modem_bytes_data_warning").value = parseFloat($("data_warning").value)*GBytes;
	else if(document.form.modem_warning_unit.value == '1')
		$("modem_bytes_data_warning").value = parseFloat($("data_warning").value)*MBytes;

	if(document.form.modem_country.value == ""){
		var valueStr="";
		document.form.modem_isp.disabled = false;;
		document.form.modem_isp.options.length = 1;
		document.form.modem_isp.options[0] = new Option(valueStr, valueStr, false, true);
	}

	if(document.form.modem_roaming.selectedIndex == 0 && document.form.modem_roaming_isp.disabled == false && document.form.modem_roaming_isp.value == ""){
		alert("Please select the roaming ISP!");
		return;
	}
	showLoading(); 
	document.form.submit();
}

/*------------ Mouse event of fake LAN IP select menu {-----------------*/
function setClientIP(apnAddr){
	document.form.modem_apn.value = apnAddr;
	hideClients_Block();
	over_var = 0;
}

function showLANIPList(isp_order){
	var code = "";
	var show_name = "";

	for(var i = 0; i < apnlist[isp_order].length; i++){
		var apnlist_col = apnlist[isp_order][i].split('&&');
		code += '<a><div onmouseover="over_var=1;" onmouseout="over_var=0;" onclick="setClientIP(\''+apnlist_col[1]+'\');"><strong>'+apnlist_col[0]+'</strong></div></a>';

		if(i == 0)
			document.form.modem_apn.value = apnlist_col[1];
	}
	code +='<!--[if lte IE 6.5]><iframe class="hackiframe2"></iframe><![endif]-->';	
	$("ClientList_Block_PC").innerHTML = code;
}

function pullLANIPList(obj){
	
	if(isMenuopen == 0){		
		obj.src = "/images/arrow-top.gif"
		$("ClientList_Block_PC").style.display = 'block';		
		document.form.modem_apn.focus();		
		isMenuopen = 1;
	}
	else
		hideClients_Block();
}

var over_var = 0;
var isMenuopen = 0;
function hideClients_Block(){
	$("pull_arrow").src = "/images/arrow-down.gif";
	$('ClientList_Block_PC').style.display='none';
	isMenuopen = 0;
}
/*----------} Mouse event of fake LAN IP select menu-----------------*/

var dsltmp_transmode = "<% nvram_get("dsltmp_transmode"); %>";
function change_wan_unit(obj){
	if(!dualWAN_support) return;
	
	if(obj.options[obj.selectedIndex].text == "DSL"){
		if(dsltmp_transmode == "atm")
			document.form.current_page.value = "Advanced_DSL_Content.asp";
		else //ptm
			document.form.current_page.value = "Advanced_VDSL_Content.asp";	
	}else if(document.form.dsltmp_transmode){
		document.form.dsltmp_transmode.style.display = "none";
	}

	if(obj.options[obj.selectedIndex].text == "WAN" ||	obj.options[obj.selectedIndex].text == "Ethernet LAN"){
		document.form.current_page.value = "Advanced_WAN_Content.asp";
	}else	if(obj.options[obj.selectedIndex].text == "USB") {
		return false;
	}

	FormActions("apply.cgi", "change_wan_unit", "", "");
	document.form.target = "";
	document.form.submit();
}

function done_validating(action){
	refreshpage();
}

function check_connect_status(){
	 $j.ajax({
    	url: '/ajax_simconnect.asp',
    	dataType: 'script', 

    	error: function(xhr){
      		check_connect_status();
    	},
    	success: function(response){
    		if( usb_index == 0 ){
				mobile_state = first_wanstate;
				mobile_sbstate = first_wansbstate;
				mobile_auxstate = first_wanauxstate;
			}
			else if(usb_index == 1){
				mobile_state = second_wanstate;
				mobile_sbstate = second_wansbstate;
				mobile_auxstate = second_wanauxstate;
			}

			if(mobile_state == 2 && mobile_sbstate == 0 && mobile_auxstate == 0){
				$("connection_status").innerHTML = "<#Connected#>";
				$("mconnect_status").innerHTML = "<#Connected#>";
			}
			else{
				$("connection_status").innerHTML = "<#Disconnected#>.";
				$("mconnect_status").innerHTML = "<#Disconnected#>.";
				var sim_status = parseInt(sim_state);
				if(sim_status == 2){
					$("connection_status").innerHTML = "<#Mobile_need_pin#>";
					$("mconnect_status").innerHTML = " <#Mobile_need_pin#>";
				}
				else if(sim_status == 3){
					$("connection_status").innerHTML = "<#Mobile_sim_lock#> <#Mobile_need_puk#>";
					$("mconnect_status").innerHTML = "<#Mobile_sim_lock#> <#Mobile_need_puk#>";
				}
				else if(sim_status == 4){
					$("connection_status").innerHTML = "<#Mobile_need_pin2#>";
					$("mconnect_status").innerHTML = "<#Mobile_need_pin2#>";
				}
				else if(sim_status == 5){
					$("connection_status").innerHTML = "<#Mobile_sim_lock#> <#Mobile_need_puk2#>";
					$("mconnect_status").innerHTML = "<#Mobile_sim_lock#> <#Mobile_need_puk2#>";	
				}
				else if(sim_status == 6){
					$("connection_status").innerHTML = "<#Mobile_wait_sim#>";
					$("mconnect_status").innerHTML = "<#Mobile_wait_sim#>";
				}
				else if(sim_status == -1){
					$("connection_status").innerHTML = "<#Mobile_sim_miss#>";
					$("mconnect_status").innerHTML = "<#Mobile_sim_miss#>";					
				}
				else if(mobile_state == 1){
					$("connection_status").innerHTML = "<#Connecting_str#>";
					$("mconnect_status").innerHTML = "<#Connecting_str#>";					
				}
				else{
					$("connection_status").innerHTML = "<#Mobile_fail_connect#>";
					$("mconnect_status").innerHTML = "<#Mobile_fail_connect#>";					
				}
			}		
			setTimeout("check_connect_status();",3000);
       }
   });
}

function showUpDownRate(){
	var Kbits = 1024;
	var Mbits = 1024*1024;
	var Gbits = 1024*1024*1024;	

	if(!isNaN(tx_rate)){
		if(tx_rate < Kbits)
			$("upRate").innerHTML = tx_rate + "&nbsp;bps";
		else if(tx_rate < Mbits)
			$("upRate").innerHTML = parseFloat(Math.round(tx_rate/Kbits*1000))/1000 + "&nbsp;Kbps";
		else if(tx_rate < Gbits)
			$("upRate").innerHTML = parseFloat(Math.round(tx_rate/Mbits*1000))/1000 + "&nbsp;Mbps";
		else
			$("upRate").innerHTML = parseFloat(Math.round(tx_rate/Gbits*1000))/1000 + "&nbsp;Gbps";
	}

	if(!isNaN(rx_rate)){
		if(rx_rate < Kbits)
			$("downRate").innerHTML = rx_rate + "&nbsp;bps";
		else if(rx_rate < Mbits)
			$("downRate").innerHTML = parseFloat(Math.round(rx_rate/Kbits*1000))/1000 + "&nbsp;Kbps";
		else if(rx_rate < Gbits)
			$("downRate").innerHTML = parseFloat(Math.round(rx_rate/Mbits*1000))/1000 + "&nbsp;Mbps";
		else
			$("downRate").innerHTML = parseFloat(Math.round(rx_rate/Gbits*1000))/1000 + "&nbsp;Gbps";
	}
}

var stopCheck = 0;
var modem_act_hwver = '<% nvram_get("usb_modem_act_hwver"); %>';
var modem_act_imei = '<% nvram_get("usb_modem_act_imei"); %>';
var modem_act_imsi = '<% nvram_get("usb_modem_act_imsi"); %>';
var modem_act_iccid = '<% nvram_get("usb_modem_act_iccid"); %>';
var modem_operation ='<% nvram_get("usb_modem_act_operation"); %>';
var modem_isp = '<% nvram_get("modem_isp"); %>';
var g3err_pin = '<% nvram_get("g3err_pin"); %>';
var pin_remaining_count = '<% nvram_get("usb_modem_act_auth_pin"); %>';
var puk_remaining_count = '<% nvram_get("usb_modem_act_auth_puk"); %>';
var rx_bytes = parseFloat('<% nvram_get("modem_bytes_rx"); %>');
var tx_bytes = parseFloat('<% nvram_get("modem_bytes_tx"); %>');
var tx_rate = parseFloat('<% nvram_get("usb_modem_act_tx"); %>');
var rx_rate = parseFloat('<% nvram_get("usb_modem_act_rx"); %>');
var total_bytes = 0;
var simact_result = "";
var modemuptime = parseInt('<% get_modemuptime(); %>');

function check_simact_result(flag){ // 1: Unblock PIN  2: configure PIN  3: modify PIN
	$j.ajax({
		url: '/simact_result.asp',
		dataType: 'script',
		error: function(xhr){
			check_simact_result();		
		},
		success: function(response){
			if(simact_result.indexOf("done") >= 0){
				if(flag == 1)
					setTimeout("check_sim_state(1);", 2000);
				else if(flag == 2)
					setTimeout("check_sim_state(2);", 2000);
				else if(flag == 3){
					show_sim_table(0);
					$("pin_modify_result").innerHTML = "Succeed to change the PIN!";
					$("pin_modify_result").style.display="";
				}
			}
			else{
				if(flag == 1 || flag == 2)
					check_sim_state(flag);
				else if(flag == 3){//Modify PIN
					show_sim_table(0);
					$("pin_modify_result").innerHTML = simact_result;
					$("pin_modify_result").style.display="";
				}
			}
		}
	});	
}

function check_sim_state(flag){
	$j.ajax({
    	url: '/ajax_simstate.asp',
    	dataType: 'script', 

    	error: function(xhr){
      		setTimeout("check_sim_state();", 1000);
    	},
    	success: function(response){						
			switch(sim_state){
				case '1':	
					if(flag == 1 && $j("#sim_input").css("display") == "block")
						show_sim_table(0);
					$("usim_status").innerHTML = "<#Mobile_sim_ready#>";
					break;
				case '2':
					if(g3err_pin == '1' && pin_remaining_count < 3){
						$("usim_status").innerHTML = "Wrong PIN code. Please input the correct PIN code.";	
						if( pin_remaining_count == 0)
							check_sim_state(2);									
					}
					else{
						$("usim_status").innerHTML = "<#Mobile_need_pin#>";
					}
					$("pin_remaining").innerHTML = '<#Mobile_remaining_num#>: ';
					$("pin_remaining").innerHTML += pin_remaining_count;							
					break;	
				case '3':
					$("usim_status").innerHTML = "<#Mobile_need_puk#>";	
					if(flag == 1 && $j("#sim_input").css("display") == "block")
						$("puk_remaining").innerHTML = puk_remaining_count;		
					break;
				case '4':
					$("usim_status").innerHTML = "<#Mobile_need_pin2#>";
					break;
				case '5':
					$("usim_status").innerHTML = "<#Mobile_need_puk2#>";					
					break;
				case '6':
					$("usim_status").innerHTML = "<#Mobile_wait_sim#>";				
					break;					
				case '-1':
					$("usim_status").innerHTML = "<#Mobile_sim_miss#>";
					break;	
				case '-2':
				case '-10':
					$("usim_status").innerHTML = "<#Mobile_sim_fail#>";
					break;
				default:
					break;	
			}

			if(sim_state == '1'){
				$("pin_verify_tr").style.display = "";
				$("pin_modify_tr").style.display = "";
				$("unblock_btn").style.display = "none";
				document.form.pincode.value="";
				$("pin_code_tr").style.display="none";		
			}
			else if(sim_state == '3' || sim_state == '5'){
				$("pin_verify_tr").style.display = "none";
				$("pin_modify_tr").style.display = "none";
				document.form.pincode.value="";
				$("pin_code_tr").style.display="none";
				$("unblock_btn").style.display = "";				
			}
			else{
				if(sim_state == '2'){
					$("pin_code_tr").style.display="";
				}
				$("pin_verify_tr").style.display = "none";
				$("pin_modify_tr").style.display = "none";
				$("unblock_btn").style.display = "none";					
			}

			if(document.form.pin_verify[0].selected != true && document.form.pin_verify[1].selected != true){
				if(usb_modem_act_auth == "1" || usb_modem_act_auth == "2")
					document.form.pin_verify[0].selected = true;
				else if(usb_modem_act_auth == "3")
					document.form.pin_verify[1].selected = true;
			}

			if(flag == 1){
				if($j("#sim_input").css("display") == "block"){
					$("loadingIcon_sim").style.display="none";
					$("sim_ok_button").style.display = "";
					$("sim_cancel_btn").style.display = "";	
				}
			}	
			else if(flag == 2){			
				$("loadingIcon_pin").style.display = "none";
				$("save_pin_btn").style.display = "";
				$("save_pin_ckb_span").style.display="";	
			}
			else
				setTimeout("check_sim_state();", 3000);

			if(sim_state == "1"){
				$("newtork_type_tr").style.display = "";
				$("connection_type_tr").style.display = "";
				$("modem_pdp_tr").style.display = "";
				$("modem_roaming_tr").style.display = "";
			}
			else{
				$("newtork_type_tr").style.display = "none";
				$("connection_type_tr").style.display = "none";
				$("modem_pdp_tr").style.display = "none";
				$("modem_roaming_tr").style.display = "none";
			}
       }
   });
}	

function check_sim_details(){
	if( stopCheck == 1 )
		return;

	$j.ajax({
    	url: '/ajax_simstatus.asp',
    	dataType: 'script', 

    	error: function(xhr){
      		setTimeout("check_sim_details();", 1000);
    	},
    	success: function(response){

			$("modem_act_hwver").innerHTML = modem_act_hwver;	
			$("modem_act_imei").innerHTML = modem_act_imei;
			$("modem_act_imsi").innerHTML = modem_act_imsi;
			$("modem_act_iccid").innerHTML = modem_act_iccid;

			if(sim_state == '1'){
				$("misp").innerHTML = '&nbsp;'+ modem_spn;
				switch(modem_operation)
				{
					case 'Edge':
						$("msignalsys").innerHTML  = '<img src="/images/mobile/E.png">';
						break;
					case 'GPRS':
						$("msignalsys").innerHTML = '<img src="/images/mobile/G.png">';	
						break;
					case 'WCDMA':
					case 'CDMA':
					case 'EV-DO REV 0':	
					case 'EV-DO REV A':		
					case 'EV-DO REV B':
						$("msignalsys").innerHTML = '<img src="/images/mobile/3G.png">';	
						break;	
					case 'HSDPA':										
					case 'HSUPA':
						$("msignalsys").innerHTML = '<img src="/images/mobile/H.png">';	
						break;	
					case 'HSDPA+':										
					case 'DC-HSDPA+':
						$("msignalsys").innerHTML = '<img src="/images/mobile/H+.png">';	
						break;		
					case 'LTE':
						$("msignalsys").innerHTML = '<img src="/images/mobile/LTE.png">';	
						break;		
					case 'GSM':	
					default:
						$("msignalsys").innerHTML = '';
						break;
				}	

				total_bytes = rx_bytes + tx_bytes;
				if(!isNaN(total_bytes)){
					if(total_bytes < KBytes)
						$("totalTraffic").innerHTML = total_bytes + "&nbsp;Bytes";
					else if(total_bytes < MBytes)
						$("totalTraffic").innerHTML = parseFloat(Math.round(total_bytes/KBytes*1000))/1000 + "&nbsp;KBytes";
					else if(total_bytes < GBytes)
						$("totalTraffic").innerHTML = parseFloat(Math.round(total_bytes/MBytes*1000))/1000 + "&nbsp;MBytes";
					else
						$("totalTraffic").innerHTML = parseFloat(Math.round(total_bytes/GBytes*1000))/1000 + "&nbsp;GBytes";
				}

				if(!isNaN(tx_bytes)){
					if(tx_bytes < KBytes)
						$("upTraffic").innerHTML = tx_bytes + "&nbsp;Bytes";
					else if(tx_bytes < MBytes)
						$("upTraffic").innerHTML = parseFloat(Math.round(tx_bytes/KBytes*1000))/1000 + "&nbsp;KBytes";
					else if(tx_bytes < GBytes)
						$("upTraffic").innerHTML = parseFloat(Math.round(tx_bytes/MBytes*1000))/1000 + "&nbsp;MBytes";
					else
						$("upTraffic").innerHTML = parseFloat(Math.round(tx_bytes/GBytes*1000))/1000 + "&nbsp;GBytes";
				}

				if(!isNaN(rx_bytes)){			
					if(rx_bytes < KBytes)
						$("downTraffic").innerHTML = rx_bytes + "&nbsp;Bytes";
					else if(rx_bytes < MBytes)
						$("downTraffic").innerHTML = parseFloat(Math.round(rx_bytes/KBytes*1000))/1000 + "&nbsp;KBytes";
					else if(rx_bytes < GBytes)
						$("downTraffic").innerHTML = parseFloat(Math.round(rx_bytes/MBytes*1000))/1000 + "&nbsp;MBytes";
					else
						$("downTraffic").innerHTML = parseFloat(Math.round(rx_bytes/GBytes*1000))/1000 + "&nbsp;GBytes";
				}		
			}
			else{
				$("msignalsys").innerHTML = '';
				$("misp").innerHTML = '';
			}		

			if(!isNaN(modemuptime)){
				$("connect_days").innerHTML = Math.floor(modemuptime / (60*60*24));	
				$("connect_hours").innerHTML = Math.floor((modemuptime / 3600) % 24);
				$("connect_minutes").innerHTML = Math.floor(modemuptime % 3600 / 60);
				$("connect_seconds").innerHTML = Math.floor(modemuptime % 60);
			}

			showUpDownRate();

			setTimeout("check_sim_details();", 1000);
       }
   });
}	

function update_remaining_data()
{
	var remaining_data = 0;
	var data_limit_bytes = 0;
	var data_usage = parseFloat('<% nvram_get("modem_bytes_tx_old"); %>')+parseFloat('<% nvram_get("modem_bytes_tx"); %>')+parseFloat('<% nvram_get("modem_bytes_rx_old"); %>')+parseFloat('<% nvram_get("modem_bytes_rx"); %>');

	if(document.form.modem_limit_unit.value == '0')//GBytes
		data_limit_bytes = parseFloat($("data_limit").value)*GBytes;
	else if(document.form.modem_limit_unit.value == '1')
		data_limit_bytes = parseFloat($("data_limit").value)*MBytes;

	remaining_data = data_limit_bytes-data_usage;

	if(remaining_data < 0)
		remaining_data = 0;	
	
	if(Math.abs(remaining_data) < KBytes)
		$("remaining_data").innerHTML = remaining_data + "&nbsp;Bytes";
	else if(Math.abs(remaining_data) < MBytes)
		$("remaining_data").innerHTML = parseFloat(Math.round(remaining_data/KBytes*1000))/1000 + "&nbsp;KBytes";
	else if(Math.abs(remaining_data) < GBytes)
		$("remaining_data").innerHTML = parseFloat(Math.round(remaining_data/MBytes*1000))/1000 + "&nbsp;MBytes";
	else
		$("remaining_data").innerHTML = parseFloat(Math.round(remaining_data/GBytes*1000))/1000 + "&nbsp;GBytes";	
}

function Show_status(){
	$j("#mobile_status").fadeIn(300);
	stopCheck = 0;
	check_sim_details();
}

function hide_status(){
	$j("#mobile_status").fadeOut(300);
	stopCheck = 1;
}

var scan_end = '<% nvram_get("usb_modem_act_scanning"); %>';
var ispstr = '<% get_isp_scan_results(); %>';
var ispList = "";
var orig_modem_isp = '<% nvram_get("modem_isp"); %>';
var orig_operation = '<% nvram_get("usb_modem_act_operation"); %>';
switch(orig_operation)
{
	case 'GSM':
	case 'Edge':
	case 'GPRS':
		orig_operation  = '2G';
		break;
	case 'WCDMA':
	case 'CDMA':
	case 'EV-DO REV 0':	
	case 'EV-DO REV A':		
	case 'EV-DO REV B':
		orig_operation  = '3G';
		break;	
	case 'HSDPA+':										
	case 'DC-HSDPA+':
		orig_operation  = 'H+';
		break;		
	case 'LTE':
		orig_operation  = '4G';	
		break;			
	default:
		break;
}

function ShowRoamingOpt(modem_roaming){
	var show = parseInt(modem_roaming);

	if(show){
		$("roaming_isp").style.display = "";
		show_roaming_isp_list(ispstr);		
	}
	else{
		$("roaming_isp").style.display = "none";
	}
}

function change_limit_unit(traffic_unit){
	var limit_val = parseFloat($("data_limit").value);

	if( traffic_unit == '0' ) //MBytes => GBytes
		$("data_limit").value = parseFloat(Math.round(limit_val/1024*1000))/1000;
	else if( traffic_unit == '1' ) //Gbytes => MBytes
		$("data_limit").value = Math.round(limit_val*1024);		

	update_remaining_data();
}

function change_warning_unit(traffic_unit){
	var warning_val = parseFloat($("data_warning").value);

	if( traffic_unit == '0' ) //MBytes => GBytes
		$("data_warning").value = parseFloat(Math.round(warning_val/1024*1000))/1000;
	else if( traffic_unit == '1' ) //Gbytes => MBytes
		$("data_warning").value = Math.round(warning_val*1024);		
}

function show_dateList(){
	var now_value = '<% nvram_get("data_usage_cycle"); %>';
	var valuestr = "";

	free_options(document.form.data_usage_cycle);
	document.form.data_usage_cycle.options.length = 31;	
	for(var i = 0; i < 31; i++){
		valuestr = (i+1).toString();
		document.form.data_usage_cycle.options[i] = new Option(valuestr, valuestr);
		if(now_value == valuestr)
			document.form.data_usage_cycle.options[i].selected = "1";	
	}
}

function show_roaming_isp_list(ispStr){
	var optionText;
	ispList = ispStr.toArray();
	ispList.sort();
	if(ispList.length > 0){
		if(document.form.modem_roaming_isp.options.length > 0)
			free_options(document.form.modem_roaming_isp);
		document.form.modem_roaming_isp.options.length = ispList.length;				
		for(var i = 0; i < ispList.length; i++){
			optionText = ispList[i][0]+' ('+ispList[i][2]+')';
			document.form.modem_roaming_isp.options[i] = new Option(optionText, ispList[i][0]);
			if(orig_modem_isp == ispList[i][0] && orig_operation == ispList[i][2])
				document.form.modem_roaming_isp.options[i].selected = "1";
		}
		$("modem_roaming_isp").style.display = "";	
		$("isp_scan_button").value = "<#QIS_rescan#>";	
	}
	else
		$("modem_roaming_isp").style.display = "none";
}

function detect_scan_result(){
	$j.ajax({
		url: '/ajax_scanIsp.asp',
		dataType: 'script',
		
		error: function(xhr){
			detect_scan_result();		
		},
		success: function(response){
			if( scan_end == '0'){
				if(ispstr.length > 0){
					show_roaming_isp_list(ispstr);
					$("loadingIcon").style.display = "none";
					$("isp_scan_button").style.display = "";
					$("warning_states").style.display = "";
				}
				else
					setTimeout("detect_scan_result();", 5000);
			}
			else if( scan_end == '2' || scan_end == '1' ){
				setTimeout("detect_scan_result();", 5000);	
			}
			else{ //Never scan
				$("loadingIcon").style.display = "none";
				$("isp_scan_button").value = "<#CTL_scan#>";
				$("isp_scan_button").style.display = "";
				$("warning_states").style.display = "";
			}
		}	
	});	
}

function scan_isp(){
	$("loadingIcon").style.display = "";
	$("isp_scan_button").style.display = "none";
	$("modem_roaming_isp").style.display = "none";
	$("warning_states").style.display = "none";
	setTimeout("detect_scan_result();", 10000);
	document.simact_form.action_mode.value = "scan_isp";
	document.simact_form.submit();
}

function cancel_action(){
	if(usb_modem_act_auth == "1" || usb_modem_act_auth == "2")
		document.form.pin_verify[0].selected = true;
	else if(usb_modem_act_auth == "3")
		document.form.pin_verify[1].selected = true;
	show_sim_table(0);
}

function set_verify_pin(){	
	if(document.form.sim_pincode.value !=""){
		if(document.form.sim_pincode.value.search(/^\d{4,8}$/)==-1){
			$("verify_pincode_status").innerHTML='<#JS_InvalidPIN#>';
			$("verify_pincode_status").style.display="";
			document.form.sim_pincode.select();
			document.form.sim_pincode.focus();
		}
		else{
			document.simact_form.sim_pincode.value = document.form.sim_pincode.value;
			if(document.form.pin_verify[0].selected == true)
				document.simact_form.action_mode.value = "start_lockpin";
			else if(document.form.pin_verify[1].selected == true)
				document.simact_form.action_mode.value = "stop_lockpin";
			document.simact_form.submit();
			show_sim_table(0);
		}
	}
	else{
		$("verify_pincode_status").innerHTML='Please Input SIM PIN! ';
		$("verify_pincode_status").style.display="";
	}

	showLoading(4);
	setTimeout("location.reload();", 3000);
}

function change_sim_pin(){
	var pin_check = 0;
	var newPin_check = 0;

	if(document.form.sim_pincode.value !=""){
		if(document.form.sim_pincode.value.search(/^\d{4,8}$/)==-1){
			$("verify_pincode_status").innerHTML='<#JS_InvalidPIN#>';
			$("verify_pincode_status").style.display="";
		}
		else{
			document.simact_form.sim_pincode.value = document.form.sim_pincode.value;
			pin_check = 1;
		}
	}	
	else{
		$("verify_pincode_status").innerHTML='Please input the SIM PIN!';
		$("verify_pincode_status").style.display="";
	}	

	if(document.form.sim_newpin.value !=""){
		if(document.form.sim_newpin.value.search(/^\d{4,8}$/)==-1){
				$("new_pincode_status").innerHTML='<#JS_InvalidPIN#>';
				$("new_pincode_status").style.display="";
		}
		else{
			document.simact_form.sim_newpin.value = document.form.sim_newpin.value;
			newPin_check = 1;
		}
	}	
	else{
		$("new_pincode_status").innerHTML='Please input the new SIM PIN!';
		$("new_pincode_status").style.display="";
	}

	if(pin_check && newPin_check){
		document.simact_form.action_mode.value = "start_pwdpin";
		document.simact_form.submit();
		showLoading(3);
		setTimeout("check_simact_result(3);", 3000);	
	}
}

function unblock_pin(){
	var puk_check = 0;
	var newPin_check = 0;

	if(document.form.sim_puk.value != ""){
		document.simact_form.sim_puk.value = document.form.sim_puk.value;
		puk_check = 1;
	}	
	else{
		$("puk_status").innerHTML='Please input the SIM PUK!';
		$("puk_status").style.display="";
	}	

	if(document.form.sim_newpin.value !=""){
		if(document.form.sim_newpin.value.search(/^\d{4,8}$/)==-1){
				$("new_pincode_status").innerHTML='<#JS_InvalidPIN#>';
				$("new_pincode_status").style.display="";
		}
		else{
			document.simact_form.sim_newpin.value = document.form.sim_newpin.value;
			newPin_check = 1;
		}
	}	
	else{
		$("new_pincode_status").innerHTML='Please input the new SIM PIN!';
		$("new_pincode_status").style.display="";
	}

	if(puk_check && newPin_check){
		$("loadingIcon_sim").style.display="";
		$("sim_ok_button").style.display = "none";
		$("sim_cancel_btn").style.display = "none";		
		document.simact_form.action_mode.value = "start_simpuk";
		document.simact_form.submit();
		setTimeout("check_simact_result(1);", 3000);	
	}
}

function show_sim_table(show, action){ //show: 1-show  0-hide   action: 1-pin verification  2:pin modification 3: unlock sim
	if(show == 1){
		$j("#sim_input").fadeIn(300);
		if(action == 1){
			$("sim_formtitle").innerHTML = "SIM <#Mobile_pin_management#> - <#Mobile_pin_verify#>";
			$("sim_title_desc").innerHTML = "Please input the PIN code obtained from the internet services providers.";
			document.form.sim_pincode.value = "";
			$("sim_pincode_tr").style.display = "";
			$("sim_pincode_hd").innerHTML = "<#PIN_code#>";
			$("sim_newpin_tr").style.display = "none";
			$("sim_puk_tr").style.display = "none";
			$("puk_remaining_tr").style.display = "none";
			document.form.sim_pincode.focus();
			document.getElementById('sim_ok_button').onclick = function(){ 
				set_verify_pin(); 
			}; 
		}
		else if(action == 2){
			$("sim_formtitle").innerHTML = "SIM <#Mobile_pin_management#> - PIN Modification";
			$("sim_title_desc").innerHTML = "";
			document.form.sim_pincode.value = "";
			$("sim_pincode_tr").style.display = "";
			$("sim_pincode_hd").innerHTML = "Old PIN";
			document.form.sim_newpin.value = "";
			$("sim_newpin_tr").style.display = "";
			$("sim_puk_tr").style.display = "none";
			$("puk_remaining_tr").style.display = "none";
			document.getElementById('sim_ok_button').onclick = function(){ 
				change_sim_pin(); 
			}; 
		}
		else if(action == 3){
			$("sim_formtitle").innerHTML = "SIM <#Mobile_pin_management#> - Unblock SIM";
			$("sim_title_desc").innerHTML = "Please contact the internet services providers to obtain the PIN unblocking code(PUK).";
			document.form.sim_puk.value = "";			
			$("sim_puk_tr").style.display = "";
			document.form.sim_newpin.value = "";			
			$("sim_newpin_tr").style.display = "";
			$("sim_pincode_tr").style.display = "none";	
			$("puk_remaining").innerHTML = puk_remaining_count;	
			$("puk_remaining_tr").style.display = "";		
			document.getElementById('sim_ok_button').onclick = function(){ 
				unblock_pin(); 
			}; 
		}
	}
	else if(show == 0){
		$j("#sim_input").fadeOut(300);
	}
}

function configure_pin(){
	if(document.form.pincode.value !=""){
		if(document.form.pincode.value.search(/^\d{4,8}$/)==-1){
			$("pincode_status").innerHTML='<#JS_InvalidPIN#> ';
			$("pincode_status").style.display="";
		}
		else{
			$("save_pin_btn").style.display="none";
			$("save_pin_ckb_span").style.display="none";
			$("loadingIcon_pin").style.display="";			
			document.simact_form.sim_pincode.value = document.form.pincode.value;
			if(document.form.save_pin_ckb.checked == true)
				document.simact_form.save_pin.value = "1";
			else
				document.simact_form.save_pin.value = "0";
			document.simact_form.action_mode.value = "start_simpin";
			document.simact_form.submit();
			setTimeout("check_simact_result(2);", 3000);	
		}
	}
	else{
		$("pincode_status").innerHTML='Please input the SIM PIN! ';
		$("pincode_status").style.display="";
	}		
}

function getSimAuth(){
	document.simact_form.action_mode.value = "restart_simauth";
	document.simact_form.submit();
}

function change_autoAPN(autoAPN){
	if(autoAPN == "0")
		inputCtrl(document.form.modem_enable_option, 1);
	else
		inputCtrl(document.form.modem_enable_option, 0);
}

function reset_usage(){
	cookie.unset(keystr);
	document.simact_form.action_mode.value = "restart_resetcount";
	document.getElementById("reset_usage_btn").style.display = "none";
	document.getElementById("loadingIcon_reset").style.display = "";
	document.simact_form.submit();
	setTimeout("finish_reset_usage();", 4000);
}

function finish_reset_usage(){
	document.getElementById("loadingIcon_reset").style.display = "none";
	update_usage_data();
}

function show_change_hint(){
	document.getElementById("change_day_hint").style.display="";
}

</script>
</head>

<body onload="initial();" onunLoad="return unload_body();">
<div id="TopBanner"></div>
<div id="hiddenMask" class="popup_bg">
	<table cellpadding="5" cellspacing="0" id="dr_sweet_advise" class="dr_sweet_advise" align="center">
		<tr>
		<td>
			<div class="drword" id="drword" style="height:110px;"><#Main_alert_proceeding_desc4#> <#Main_alert_proceeding_desc1#>...
				<br/>
				<br/>
	    </div>
		  <div class="drImg"><img src="images/alertImg.png"></div>
			<div style="height:70px;"></div>
		</td>
		</tr>
	</table>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>

<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame" autocomplete="off">
<input type="hidden" name="productid" value="<% nvram_get("productid"); %>">
<input type="hidden" name="current_page" value="Advanced_MobileBroadband_Content.asp">
<input type="hidden" name="next_page" value="Advanced_MobileBroadband_Content.asp">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="restart_net">
<input type="hidden" name="action_wait" value="10">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="modem_enable" value="<% nvram_get("modem_enable"); %>">
<input type="hidden" name="modem_bytes_data_limit" id="modem_bytes_data_limit" value="<% nvram_get("modem_bytes_data_limit"); %>">
<input type="hidden" name="modem_bytes_data_warning" id="modem_bytes_data_warning" value="<% nvram_get("modem_bytes_data_warning"); %>">
<input type="hidden" name="g3err_pin" value="<% nvram_get("g3err_pin"); %>">
<input type="hidden" name="wans_standby" value="<% nvram_get("wans_standby"); %>">

<!---- connect status start  ---->
<div id="mobile_status"  class="contentM_qis" style="box-shadow: 3px 3px 10px #000;">
	<table class="QISform_wireless" border=0 align="center" cellpadding="5" cellspacing="5">
		<tr>
			<td align="left">
			<span class="formfonttitle"><#menu5_3#> - <#Mobile_status_title#></span>
			<div style="width:600px; height:15px;overflow:hidden;position:relative;left:0px;top:5px;"><img src="/images/New_ui/export/line_export.png"></div>
			<div><#Mobile_status_desc1#></div>
			</td>
		</tr>
		<tr>
			<td>
				<div id="product_info">
				<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
					<thead>
					<tr>
						<td colspan="2"><#Product_information#></td>
					</tr>
					</thead>
			 		<tr><th><#Modelname#></th><td><% nvram_get("productid"); %></td></tr>  
		  			<tr><th><#Hardware_version#></th><td><div id="modem_act_hwver"><% nvram_get("usb_modem_act_hwver"); %></div></td></tr>
		  			<tr><th>LTE Modem Version</th><td><div id="usb_modem_act_swver"><% nvram_get("usb_modem_act_swver"); %></div></td></tr>
		  			<tr><th>IMEI</th><td><div id="modem_act_imei"><% nvram_get("usb_modem_act_imei"); %></div></td></tr>
					<tr><th>IMSI</th><td><div id="modem_act_imsi"><% nvram_get("usb_modem_act_imsi"); %></div></td></tr>
					<tr><th>ICCID</th><td><div id="modem_act_iccid"><% nvram_get("usb_modem_act_iccid"); %></div></td></tr>
		 		</table>
		 		</div> 			 	
	  		</td>
		</tr>
		<tr>
			<td>
				<div id="internet_usage">
				<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
					<thead>
					<tr>
						<td colspan="2"><#Mobile_internet_usage#></td>
					</tr>
					</thead>
		  			<tr>
		  				<th><#PPPConnection_x_WANLink_itemname#></th>
		  				<td>
		  					<div id="mconnect_status" style="cursor:auto;"></div>
		  				</td>
		  			</tr>
		  			<th><#Mobile_network_op#></th>
			 		<td><div id="msignalsys" style="cursor:auto;float:left;" class="img_wrap2"></div><div id="misp" style="float:left;margin-top:10px;"></div></td>
		  			<tr><th><#Total_traffic#></th><td><span id="totalTraffic" style="color:#FFF;"></span></td></tr>
					<tr><th><#Uplink_traffic#></th><td><span id="upTraffic" style="color:#FFF;"></span></td></tr>
					<tr><th><#Downlink_traffic#></th><td><span id="downTraffic" style="color:#FFF;"></span></td></tr>
					<tr><th><#Uplink_rate#></th><td><span id="upRate" style="color:#FFF;"></span></td></tr>					
					<tr><th><#Downlink_rate#></th><td><span id="downRate" style="color:#FFF;"></span></td></tr>
					<tr><th><#Connection_time#></th><td><span id="connect_days"></span> <#Day#> <span id="connect_hours"></span> <#Hour#> <span id="connect_minutes"></span> <#Minute#> <span id="connect_seconds"></span> <#Second#></td></span></td></tr>
		 		</table>
		 		</div>	 			 	
	  		</td>		
		</tr>
	</table>		

	<div style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
		<input class="button_gen" type="button" onclick="hide_status();" value="<#CTL_close#>">	
	</div>				
</div>
<!--===================================Ending of connect status ===========================================-->

<table class="content" align="center" cellpadding="0" cellspacing="0">
  <tr>
	<td width="17">&nbsp;</td>
	
	<!--=====Beginning of Main Menu=====-->
	<td valign="top" width="202">
	  <div id="mainMenu"></div>
	  <div id="subMenu"></div>
	</td>
	
	<td valign="top">
	<div id="tabMenu" class="submenuBlock"></div>
		<!--===================================Beginning of Main Content===========================================-->
	<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
	<tr>
		<td align="left" valign="top">
	  <table width="760px" border="0" cellpadding="5" cellspacing="0" class="FormTitle" id="FormTitle" style="-webkit-border-radius: 3px;-moz-border-radius: 3px;border-radius:3px;">
		<tbody>
		<tr>
			<td bgcolor="#4D595D" valign="top" height="680px">
				<div>&nbsp;</div>
				<div style="width:730px">
					<table width="730px">
						<tr>
							<td align="left">
								<span class="formfonttitle"><#menu5_3#> - <#Mobile_title#></span>
							</td>
							<td align="right">
								<img onclick="go_setting('/APP_Installation.asp')" align="right" style="cursor:pointer;position:absolute;margin-left:-20px;margin-top:-30px;" title="<#Menu_usb_application#>" src="/images/backprev.png" onMouseOver="this.src='/images/backprevclick.png'" onMouseOut="this.src='/images/backprev.png'">
							</td>
						</tr>
					</table>
				</div>
				<div style="margin:5px;"><img src="/images/New_ui/export/line_export.png"></div>
	      		<div class="formfontdesc"><#Mobile_desc1#></div>			  

						<table  width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" id="WANscap">
							<thead>
							<tr>
								<td colspan="2"><#wan_index#></td>
							</tr>
							</thead>							
							<tr>
								<th><#wan_type#></th>
								<td align="left">
									<select class="input_option" name="wan_unit" onchange="change_wan_unit(this);">
									</select>
								</td>
							</tr>

							<tr>
								<th><#Mobile_enable#></th>
								<td>
									<select name="modem_enable_select" id="modem_enable_select" class="input_option" onchange="modem_enable_act(this.value);">
										<option value="1"><#WLANConfig11b_WirelessCtrl_button1name#></option>
										<option value="0" <% nvram_match("modem_enable", "0","selected"); %>><#WLANConfig11b_WirelessCtrl_buttonname#></option>
									</select>
								</td>
							</tr>							
						</table>

				<table id="connection_table" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable" style="margin-top:8px">
				  	<thead>
				  	<tr>
						<td colspan="2"><#menu5_3_1#></td>
				  	</tr>
				  	</thead>		
				  
				  	<tr>
						<th width="200"><#ConnectionStatus#></th>
						<td>
							<span id="connection_status"></span>
							<div><img onclick="Show_status()" style="cursor:pointer;position:absolute;margin-left:450px;margin-top:-19px;" title="<#Mobile_inf#>" src="/images/New_ui/helpicon.png"></div>
						</td>		
				  	</tr>

					<tr id="newtork_type_tr" style="display:none">
						<th width="40%"><#Network_type#></th>
						<td>
							<select name="modem_mode" id="modem_mode" class="input_option">
								<option value="0" <% nvram_match("modem_mode", "0", "selected"); %>>Auto</option>
								<option value="43" <% nvram_match("modem_mode", "43", "selected"); %>>4G/3G</option>
								<option value="4" <% nvram_match("modem_mode", "4", "selected"); %>>4G only</option>
								<option value="3" <% nvram_match("modem_mode", "3", "selected"); %>>3G only</option>
								<option value="2" <% nvram_match("modem_mode", "2", "selected"); %>>2G only</option>
							</select>
						</td>
					</tr>

					<tr id="connection_type_tr" style="display:none">
						<th width="40%"><#Connectiontype#></th>
						<td>
							<select name="connection_type" id="connection_type" class="input_option">
								<option value="0" <% nvram_match("connection_type", "0", "selected"); %>>Always Connected</option>
								<option value="43" <% nvram_match("connection_type", "1", "selected"); %>>Auto Triggered by Traffic</option>
							</select>
						</td>
					</tr>

					<tr id="modem_pdp_tr" style="display:none">
						<th width="40%"><#Mobile_pdp_type#></th>
						<td>
							<select name="modem_pdp" id="modem_pdp" class="input_option">
								<option value="0" <% nvram_match("modem_pdp", "0", "selected"); %>>IPv4</option>
								<option value="1" <% nvram_match("modem_pdp", "1", "selected"); %>>PPP</option>
								<option value="2" <% nvram_match("modem_pdp", "2", "selected"); %>>IPv6</option>
								<option value="3" <% nvram_match("modem_pdp", "3", "selected"); %>>IPv4tov6</option>
							</select>
						</td>
					</tr>

					<tr id="modem_roaming_tr" style="display:none">
						<th width="40%"><#Mobile_roaming#></th>
						<td>
							<select name="modem_roaming" id="modem_roaming" class="input_option" onchange="ShowRoamingOpt(this.value);">
								<option value="1" <% nvram_match("modem_roaming", "1","selected"); %>><#WLANConfig11b_WirelessCtrl_button1name#></option>
								<option value="0" <% nvram_match("modem_roaming", "0","selected"); %>><#WLANConfig11b_WirelessCtrl_buttonname#></option>
							</select>
						</td>
					</tr>	
					<tr id="modem_roaming_mode" style="display:none">
						<th width="40%"><#Mobile_select_op#></th>
						<td>
							<input type="radio" value="1" name="modem_roaming_mode" class="input" <% nvram_match("modem_roaming_mode", "1", "checked"); %>><#Auto#>
							<input type="radio" value="0" name="modem_roaming_mode" class="input" <% nvram_match("modem_roaming_mode", "0", "checked"); %>><#Manual#>
						</td>
					</tr>

					<tr id="roaming_isp" style="display:none">
						<th width="40%"><#Mobile_roaming_isp#></th>
						<td>
							<select id="modem_roaming_isp" name="modem_roaming_isp" class="input_option" style="display:none;"></select>					
							<input type="button" id = "isp_scan_button" name = "isp_scan_button" class="button_gen" onclick="scan_isp();" value="<#CTL_scan#>"/>
							<img id="loadingIcon" style="display:none;" src="/images/InternetScan.gif">
							<div id = "warning_states"><span>*Roaming ISP scanning will make current mobile connection be disconnected.</span></div>
						</td>
					</tr>

				  <tr style="display:none">
					<th><#PPPConnection_x_PPPoEMTU_itemname#></th>
					<td>
					  <input type="text" maxlength="15" class="input_15_table" name="mobile_mtu" value="<% nvram_get("sim_mtu"); %>" onkeypress="return validator.isNumber(this,event)"/>
					</td>
				  </tr>					  		  				  
				</table>

				<table id="traffic_table" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable" style="margin-top:8px">
				  <thead>
				  <tr>
					<td colspan="2"><#Mobile_traffic_limit#></td>
				  </tr>
				  </thead>		
				  
				  <tr>
					<th width="200"><#Mobile_data_usage#></th>
					<td>
						<span id="data_usage" style="color:#FFF;"></span>	
					</td>
				  </tr>
				  
				  <tr>
					<th><#Mobile_remaining_data#></th>
					<td>
					  	<span id="remaining_data" style="color:#FFF;"></span>
					</td>
				  </tr>

				  <tr>
					<th>Reset Usage Date</th>
					<td><select id="data_usage_cycle" name="data_usage_cycle" class="input_option"></select></td>
				  </tr>

				  <tr>
					<th><#Mobile_usage_limit#></th>
					<td>
					  <input type="text" maxlength="15" class="input_15_table" id="data_limit" name="data_limit" value="" onkeypress="return validator.isNumberFloat(this,event)" onchange="update_remaining_data();"/>
					  	<span>
					  		<select name="modem_limit_unit" class="input_option" onchange="change_limit_unit(document.form.modem_limit_unit.value);">
					  			<option value="0" <% nvram_match("modem_limit_unit", "0", "selected"); %>>GBytes</option>
								<option value="1" <% nvram_match("modem_limit_unit", "1", "selected"); %>>MBytes</option>
							</select>
						</span>
					</td>
				  </tr>		

				  <tr>
					<th><#Mobile_usage_warning#></th>
					<td>
					  <input type="text" maxlength="15" class="input_15_table" id="data_warning" name="data_warning" value="" onkeypress="return validator.isNumberFloat(this,event)"/>
					  	<span>
					  		<select name="modem_warning_unit" class="input_option" onchange="change_warning_unit(document.form.modem_warning_unit.value);">
					  			<option value="0" <% nvram_match("modem_warning_unit", "0", "selected"); %>>GBytes</option>
								<option value="1" <% nvram_match("modem_warning_unit", "1", "selected"); %>>MBytes</option>
							</select>
						</span>
					</td>
				  </tr>					  		  				  
				</table>

			  	<table id="apn_table" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable" style="margin-top:8px">
					<thead>
					<tr>
						<td colspan="2"><#Mobile_apn_profile#></td>
					</tr>
					</thead>							

					<tr>
          				<th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(21,9);"><#HSDPAConfig_Country_itemname#></a></th>
            			<td>
            				<select name="modem_country" class="input_option" onchange="switch_modem_mode(document.form.modem_enable_option.value);reloadProfile();"></select>
						</td>
					</tr>
                                
			    	<tr>
			     		<th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(21,8);"><#HSDPAConfig_ISP_itemname#></a></th>
			    		<td><select name="modem_isp" class="input_option" onchange="show_APN_list();"></select></td>
			    	</tr>

					<tr>
						<th width="40%">
							<a class="hintstyle" href="javascript:void(0);" onclick="openHint(21,1);"><#menu5_4_4#></a>
						</th>
						<td>
							<select name="modem_enable_option" id="modem_enable_option" class="input_option" onchange="switch_modem_mode(this.value);reloadProfile();">
								<option value="1" <% nvram_match("modem_enable", "1", "selected"); %>>WCDMA (UMTS)</option>
								<option value="2" <% nvram_match("modem_enable", "2", "selected"); %>>CDMA2000 (EVDO)</option>
								<option value="3" <% nvram_match("modem_enable", "3", "selected"); %>>TD-SCDMA</option>
							</select>
						</td>
					</tr>

          			<tr>
						<th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(21,3);"><#HSDPAConfig_private_apn_itemname#></a></th>
            		<td>
            			<input id="modem_apn" name="modem_apn" class="input_20_table" type="text" value=""/>
           				<img id="pull_arrow" height="14px;" src="/images/arrow-down.gif" style="position:absolute;*margin-left:-3px;*margin-top:1px;" onclick="pullLANIPList(this);" title="<#select_APN_service#>" onmouseover="over_var=1;" onmouseout="over_var=0;">
							<div id="ClientList_Block_PC" class="ClientList_Block_PC"></div>
					</td>
					</tr>

					<tr>
						<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(21,10);"><#HSDPAConfig_DialNum_itemname#></a></th>
						<td>
							<input id="modem_dialnum" name="modem_dialnum" class="input_20_table" type="text" value=""/>
						</td>
					</tr>
                                
					<tr>
						<th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(21,11);"><#HSDPAConfig_Username_itemname#></a></th>
						<td>
						<input id="modem_user" name="modem_user" class="input_20_table" type="text" value="<% nvram_get("modem_user"); %>"/>
						</td>
					</tr>
                                
					<tr>
						<th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(21,12);"><#PPPConnection_Password_itemname#></a></th>
						<td>
							<input id="modem_pass" name="modem_pass" class="input_20_table" type="password" value="<% nvram_get("modem_pass"); %>"/>
						</td>
					</tr>

					<tr>
						<th><#Mobile_idle_time#></th>
						<td>
							<input id="modem_idletime" name="modem_idletime" class="input_20_table" value="<% nvram_get("modem_idletime"); %>"/> <#Second#>
						</td>
					</tr>
				</table>	

				<!--===================================Beginning of SIM Table ===========================================-->
				<div id="sim_input" style="box-shadow: 3px 3px 10px #000; position:absolute; background-color: #2B373B; margin-left:100px; margin-top: -50px; -webkit-border-radius: 5px;	-moz-border-radius: 5px; border-radius: 5px;display:none;"/>
					<table class="QISform_wireless" border=0 align="center" cellpadding="5" cellspacing="5">
						<tr>
							<td align="left">
							<span id="sim_formtitle" class="formfonttitle"></span>
							<div style="width:500px; height:15px;overflow:hidden;position:relative;left:0px;top:5px;"><img src="/images/New_ui/export/line_export.png"></div>
							<div id="sim_title_desc"></div>
							</td>
						</tr>
						<tr>
							<td>
								<div>
								<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
								  	<tr id="sim_puk_tr" style="display:none;">
										<th><#Mobile_puk#></th>
										<td>
					  						<input type="text" maxlength="8" class="input_20_table" name="sim_puk" autocapitalization="off" value="" onkeypress="return validator.isNumber(this,event)"/>
					  						<br><span id="puk_status" style="display:none;"></span>
										</td>
				  					</tr>

							 		<tr id="sim_pincode_tr" style="display:none;">
							 			<th id="sim_pincode_hd"></th>
							 			<td>
							 				<input id="sim_pincode" name="sim_pincode" class="input_20_table" type="text" autocapitalization="off" maxLength="8" value="<% nvram_get("modem_pincode"); %>" onkeypress="return validator.isNumber(this,event)"/>
							 				<br><span id="verify_pincode_status" style="display:none;"></span>
							 			</td>
							 		</tr>
				  					<tr id="sim_newpin_tr" style="display:none;">
										<th><#Mobile_new_pin#></th>
											<td><input type="text" maxlength="8" class="input_20_table" name="sim_newpin" value=""  onkeypress="return validator.isNumber(this,event)"/>
											<br><span id="new_pincode_status" style="display:none;"></span>
											</td>
				  					</tr>

				  					<tr id="puk_remaining_tr">
										<th><#Mobile_remaining_num#></th>
										<td><span id="puk_remaining"></span></td>
				  					</tr>					  											 		
						 		</table>
						 		</div> 			 	
					  		</td>
						</tr>	
					</table>		

					<div style="margin-top:5px;padding-bottom:10px;width:100%;text-align:center;">
						<input id="sim_cancel_btn" class="button_gen" type="button" onclick="cancel_action();" value="<#CTL_Cancel#>">						
						<input id="sim_ok_button" class="button_gen" type="button" onclick="" value="<#CTL_ok#>">	
						<img id="loadingIcon_sim" style="margin-left:10px; display:none;" src="/images/InternetScan.gif">
					</div>				
				</div>	 
				<!--===================================End of SIM Table ===========================================-->		

				<table id="sim_mgnt_table" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable" style="margin-top:8px">
				  <thead>
				  	<tr>
						<td colspan="2">SIM <#Mobile_pin_management#></td>
				  	</tr>
				  </thead>		
				  
				  	<tr>
						<th width="200"><#Mobile_usim_status#></th>
						<td><span id="usim_status"></span><span ><input class="button_gen" id="unblock_btn" type="button" onclick="show_sim_table(1, 3);" style="margin-left:10px; display:none;" value="Unblock" ></span></td>
				  	</tr>
				  
				  	<tr id="pin_verify_tr" style="display:none;">
						<th width="40%"><#Mobile_pin_verify#></th>
						<td>
							<select name="pin_verify" id="pin_verify" class="input_option" onchange="show_sim_table(1, 1);">
								<option value="1"><#WLANConfig11b_WirelessCtrl_button1name#></option>
								<option value="0"><#WLANConfig11b_WirelessCtrl_buttonname#></option>
							</select>						
						</td>
				  	</tr>	

				  	<tr id="pin_modify_tr" style="display:none;">
						<th width="40%">PIN Modification</th>
						<td>
							<input class="button_gen" type="button" onclick="show_sim_table(1, 2);" value="<#CTL_modify#>">	
							<span id="pin_modify_result" style="display: none"></span>
						</td>
				  	</tr>					  	

					<tr id="pin_code_tr" style="display:none;">
						<th><a class="hintstyle"  href="javascript:void(0);" onClick="openHint(21,2);"><#PIN_code#></a></th>
						<td>
							<input id="pincode" name="pincode" class="input_20_table" type="text" autocapitalization="off" maxLength="8" value="" onkeypress="return validator.isNumber(this,event)"/>
							<span id="save_pin_ckb_span"><input type="checkbox" name="save_pin_ckb" id="save_pin_ckb" value="" onclick=""><#Mobile_save_pin#></input></span>
							<img id="loadingIcon_pin" style="margin-left:10px; display:none;" src="/images/InternetScan.gif">
							<span><input  id="save_pin_btn" class="button_gen" type="button" onclick="configure_pin();" style="margin-left:10px;" value="<#CTL_ok#>"></span>
							<br><span id="pincode_status" style="display:none;"></span><span id="pin_remaining"></span>
	
						</td>
					</tr>				  		  				  
				</table>	
				<div class="apply_gen">
					<input class="button_gen" onclick="applyRule()" type="button" value="<#CTL_apply#>"/>
				</div>
			</td>
		</tr>
		</tbody>	
	  </table> 
		</td>
	</tr>
	</table>				
			<!--===================================End of Main Content===========================================-->
	</td>
  <td width="10" align="center" valign="top">&nbsp;</td>
	</tr>
</table>
</form>					

<div id="footer"></div>

<form method="post" name="simact_form" action="/apply.cgi" target="hidden_frame">
<input type="hidden" name="action_mode" value="">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="action_wait" value="">
<input type="hidden" name="sim_pincode" value="">
<input type="hidden" name="sim_newpin" value="">
<input type="hidden" name="sim_puk" value="">
<input type="hidden" name="save_pin" value="">
<input type="hidden" name="g3err_pin" value="0">
<input type="hidden" name="wan_unit" value="">
</form>
</body>
</html>
