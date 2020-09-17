var manifest = "";
var base_url = "";
var manifest_url = base_url + "manifest.txt";
var gFwObj = { model: "RT-N18U", stable: null, beta: null };

$(function()
{
	$("#release_list").DataTable({
		data: fw_data_set(),
		columns: [
			{ title: "ID", visible: false },
			{ title: "Version", className: "dt-head-center dt-body-left" },
			{
				title: "Downloads",
				render: function(data, type, row, meta) {
					var fw = fw_info_gen(row[0]);
					var row_html = "";

					row_html += "<a target=\"_blank\" href=\"" + fw.url + "\">firmware</a>&nbsp;&nbsp;&nbsp;&nbsp;";
					row_html += "<a target=\"_blank\" href=\"" + fw.url_checksum + "\">checksum</a>&nbsp;&nbsp;&nbsp;&nbsp;";
					row_html += "<a target=\"_blank\" href=\"" + fw.fnote + "\">release note</a>";

					return row_html;
				},
				className: "dt-center"
			}
		],
		dom: "lpi",
		ordering: false
	});
	$("#manifest_txt").load(manifest_url , manifest_get);
	$("#release_stable_nonote_warning").attr('style', 'display:none');
	$("#release_beta_nonote_warning").attr('style', 'display:none');
	$("#install_note_accordion").accordion({collapsible: true, active: false});
	$("#release_history_accordion").accordion({collapsible: true, active: false});
});

function manifest_get(response, status, xhr)
{
	if (status == "success") {
		manifest=$("#manifest_txt").html();
		if(manifest_parse()) {
			var str;
			if(gFwObj.stable != null) {
				str = gFwObj.stable.firmver;
				if(gFwObj.stable.buildno != "0")
					str += "_" + gFwObj.stable.buildno;
				gFwObj.stable.trx_name = str;
				gFwObj.stable.trx_url = (base_url != "") ? base_url + "/" : "";
				gFwObj.stable.trx_url += gFwObj.model + "/" + gFwObj.model + "_" + gFwObj.stable.firmver + "_" + gFwObj.stable.buildno + ".trx";
				gFwObj.stable.note_url = (base_url != "") ? base_url + "/" : "";
				gFwObj.stable.note_url += gFwObj.stable.firmver.replace(".", "_") + "_" + gFwObj.stable.buildno + "_note.txt";

				$("#release_note_stable_txt").html("Loading...");
				$("#release_note_stable_txt").load(gFwObj.stable.note_url , function (response, status, xhr) {
					if (status == "success") {
						$("#release_note_stable").accordion({collapsible: true, active: false});
					} else {
						$("#release_note_stable_txt").attr('style', 'display:none');
						$("#release_stable_nonote_warning").attr('style', 'display:inline');
						$("#release_note_stable").accordion({collapsible: true, active: 0});
					}
				});
				$("#release_note_stable_version").html(gFwObj.stable.trx_name);

				$("#txt_stable_version").html(gFwObj.stable.trx_name);
				$("#txt_stable_checksum").attr({target: "_blank", href: gFwObj.stable.trx_url + ".sha256"});
				$(".cta > .stable_hidden").attr("href", gFwObj.stable.trx_url);
				$(".stable_hidden").removeClass("stable_hidden");
			} else {
				// stable release not available
				$("#txt_stable_version").html("N/A");
				$("#txt_stable_checksum").hide();
			}
			if(gFwObj.beta != null) {
				str = gFwObj.beta.firmver;
				str += "-" + gFwObj.beta.buildno;
				gFwObj.beta.trx_name = str
				gFwObj.beta.trx_url = (base_url != "") ? base_url + "/" : "";
				gFwObj.beta.trx_url += gFwObj.model + "/beta/" + gFwObj.model + "_" + gFwObj.beta.firmver + "_" + gFwObj.beta.buildno + ".trx";
				gFwObj.beta.note_url = (base_url != "") ? base_url + "/" : "";
				gFwObj.beta.note_url += gFwObj.beta.firmver.replace(".", "_") + "_" + gFwObj.beta.buildno + "_note.txt";

				$("#release_note_beta_txt").html("Loading...");
				$("#release_note_beta_txt").load(gFwObj.beta.note_url , function (response, status, xhr) {
					if (status == "success") {
						$("#release_note_beta").accordion({collapsible: true, active: false});
					} else {
						$("#release_note_beta_txt").attr('style', 'display:none');
						$("#release_beta_nonote_warning").attr('style', 'display:inline');
						$("#release_note_beta").accordion({collapsible: true, active: 0});
					}
				});
				$("#release_note_beta_version").html(gFwObj.beta.trx_name);

				$("#txt_beta_version").html(gFwObj.beta.trx_name);
				$("#txt_beta_checksum").attr({target: "_blank", href: gFwObj.beta.trx_url + ".sha256"});
				$(".cta > .beta_hidden").attr("href", gFwObj.beta.trx_url);
				$(".beta_hidden").removeClass("beta_hidden");
			} else {
				// beta release not available
				$("#txt_beta_version").html("N/A");
				$("#txt_beta_checksum").hide();
			}
		}
	}

	// no any available firmware release
	if(gFwObj.stable == null && gFwObj.beta == null)
		$(".nofw_hidden").removeClass("nofw_hidden");
}

function manifest_parse()
{
	var i, lines, stable, beta;

	// git the model-specific manifest info
	if(manifest == "") return false;
	lines = manifest.split('\n');
	for(manifest = "", i = 0; i < lines.length; i++) {
		if(lines[i].search(gFwObj.model) == 0) {
			manifest = lines[i];
			break;
		}
	}
	if(manifest == "") return false; // model not matched

	// search for stable/beta release info
	manifest = manifest.split('#');
	for(gFwObj.stable = {}, gFwObj.beta = {}, i = 0; i < manifest.length; i++) {
		if(manifest[i].indexOf("FW") == 0) {
			gFwObj.stable.firmver = manifest[i].substr(2);
		} else if(manifest[i].indexOf("EXT") == 0) {
			gFwObj.stable.buildno = manifest[i].substr(3);
		} else if(manifest[i].indexOf("BETAFW") == 0) {
			gFwObj.beta.firmver = manifest[i].substr(6);
		} else if(manifest[i].indexOf("BETAEXT") == 0) {
			gFwObj.beta.buildno = manifest[i].substr(7);
		}
	}

	// version checking
	if(gFwObj.stable.firmver == null || gFwObj.stable.buildno == null || gFwObj.stable.firmver == "0.0")
		gFwObj.stable = null; // reset invalid stable release
	if(gFwObj.beta.firmver == null || gFwObj.beta.buildno == null || gFwObj.beta.firmver == "0.0")
		gFwObj.beta = null; // reset invalid beta release

	if(gFwObj.stable != null && gFwObj.beta != null) {
		var stable_firmver = gFwObj.stable.firmver.split('.');
		var beta_firmver = gFwObj.beta.firmver.split('.');
		if(typeof stable_firmver[0] !== "undefined" && typeof stable_firmver[1] !== "undefined" &&
		   typeof beta_firmver[0] !== "undefined" && typeof beta_firmver[1] !== "undefined") {
			if(parseInt(beta_firmver[0]) <= parseInt(stable_firmver[0]) && parseInt(beta_firmver[1]) <= parseInt(stable_firmver[1]))
				gFwObj.beta = null;
		}
	}

	return (gFwObj.stable != null || gFwObj.beta != null);
}
