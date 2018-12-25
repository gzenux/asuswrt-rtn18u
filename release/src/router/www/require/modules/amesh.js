function updateAMeshCount() {
	if(lastName != "iconAMesh") {
		$.ajax({
			url: '/ajax_onboarding.asp',
			dataType: 'script', 
			success: function(response) {
				var get_cfg_clientlist_num = 0;
				if(get_cfg_clientlist.length > 1) {
					for (var idx in get_cfg_clientlist) {
						if(get_cfg_clientlist.hasOwnProperty(idx)) {
							if(idx != 0) {
								get_cfg_clientlist_num++;
							}
						}
					}
					show_AMesh_status(get_cfg_clientlist_num, 1);
				}
				else 
					show_AMesh_status(0, 1);
			}
		});
	}
}
function show_AMesh_status(num, flag) {
	document.getElementById("ameshNumber").innerHTML = "AiMesh Node: <span>" + num + "</span>";/* untranslated */
}
function initial_amesh_obj() {
	//initial amesh obj
	if($('link[rel=stylesheet][href~="/device-map/amesh.css"]').length == 1) {
		$('link[rel=stylesheet][href~="/device-map/amesh.css"]').remove();
	}
	if($('.amesh_popup_bg').length > 0) {
		$('.amesh_popup_bg').remove();
	}
	if($('#edit_amesh_client_block_form').length == 1) {
		$('#edit_amesh_client_block_form').remove();
	}
}
function check_wl_auth_support(_wl_auth_mode_x, _obj) {
	var support_flag = false;
	var support_auth = ["psk2", "pskpsk2"];
	for (var idx in support_auth) {
		if (support_auth.hasOwnProperty(idx)) {
			if(_wl_auth_mode_x == support_auth[idx]) {
				support_flag = true;
				break;
			}
		}
	}
	if(!support_flag) {
		var auth_text = _obj.text();
		var confirm_msg = "If the <#WLANConfig11b_AuthenticationMethod_itemname#> used the " + auth_text + ", it will affect the AiMesh wifi connectivity.\nAre you sure to process?";/*untranslated*/
		support_flag = confirm(confirm_msg);
	}
	return support_flag;
}
function check_dhcp_disable(_disable_dhcp) {
	var flag = true;
	if(_disable_dhcp) {
		var confirm_msg = "If you turn off the DHCP Server, AiMesh system will be abnormal.\nAre you sure to process?";/*untranslated*/
		flag = confirm(confirm_msg);
	}
	return flag;
}
