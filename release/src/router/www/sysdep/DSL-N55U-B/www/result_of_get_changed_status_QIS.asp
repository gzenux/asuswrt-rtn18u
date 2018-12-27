<% wanlink(); %>
<% wanstate(); %>
parent.allUsbStatusArray = <% show_usb_path(); %>;
var link_wan_status = "<% nvram_get("link_wan"); %>";
var link_wan1_status = "<% nvram_get("link_wan1"); %>";
var dsl_autodet_state = "<% nvram_get("dsltmp_autodet_state"); %>";
var wan_type = "<% nvram_get("dsltmp_autodet_wan_type"); %>";
