function merlin_url_show(event) {
	var url = document.getElementById("merlin_url");

	if(url.style.display != "") {
		url.style.left = event.offsetX + "px";
		url.style.top = (event.offsetY-52) + "px";
		url.style.display = "";
	} else
		url.style.display = "none";
}

function merlin_url_hide() {
	document.getElementById("merlin_url").style.display = "none";
}

function merlin_logo() {
	var i, banner_code = "";
	var siteurl = [
		["The official website" , "https://www.asuswrt-merlin.net/"],
		["Asuswrt-Merlin for RT-N18U" , "https://gzenux.github.io/asuswrt-rtn18u/"]
	];

	banner_code +='<div id="merlin_logo"><img src="images/merlin-logo.png" onclick="merlin_url_show(event);"><ul id="merlin_url" style="display:none;" onmouseleave="merlin_url_hide();">';
	for(i = 0; i < siteurl.length; i++)
		banner_code +='<li><a href="'+siteurl[i][1]+'" target="_blank" rel="noreferrer" onclick="merlin_url_hide();"><span>'+siteurl[i][0]+'</span></a></li>';
	banner_code +='</ul></div>';

	return banner_code;
};
