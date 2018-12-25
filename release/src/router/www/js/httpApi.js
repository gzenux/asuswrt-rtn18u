var cachedData = {
	"get": {},
	"clear": function(dataArray){$.each(dataArray, function(idx, val){delete cachedData.get[val];})}
}

var asyncData = {
	"get": {},
	"clear": function(dataArray){$.each(dataArray, function(idx, val){delete asyncData.get[val];})}
}

var httpApi ={
	"nvramGet": function(objItems, forceUpdate){
		var queryArray = [];
		var retData = {};

		var __nvramget = function(_nvrams){
			return _nvrams.map(function(elem){return "nvram_get(" + elem + ")";}).join("%3B");
		};

		if(forceUpdate) cachedData.clear(objItems);

		objItems.forEach(function(key){
			if(cachedData.get.hasOwnProperty(key)){
				retData[key] = cachedData.get[key];
			}
			else if(asyncData.get.hasOwnProperty(key)){
				retData[key] = cachedData.get[key] = asyncData.get[key];
				if(forceUpdate) delete asyncData.get[key];
			}
			else{
				queryArray.push(key);
			}
		});

		if(queryArray.length != 0){
			$.ajax({
				url: '/appGet.cgi?hook=' + __nvramget(queryArray),
				dataType: 'json',
				async: false,
				error: function(){
					for(var i=0; i<queryArray.length; i++){retData[queryArray[i]] = "";}
					retData.isError = true;

					$.ajax({
						url: '/appGet.cgi?hook=' + __nvramget(queryArray),
						dataType: 'json',
						error: function(){
							for(var i=0; i<queryArray.length; i++){asyncData.get[queryArray[i]] = "";}
						},
						success: function(response){
							Object.keys(response).forEach(function(key){asyncData.get[key] = response[key];})
						}
					});
				},
				success: function(response){
					Object.keys(response).forEach(function(key){retData[key] = cachedData.get[key] = response[key];})
					retData.isError = false;
				}
			});
		}
		else{
			retData.isError = false;		
		}
		
		return retData;
	},

	"nvramDefaultGet": function(objItems, forceUpdate){
		var queryArray = [];
		var retData = {};

		var __nvramget = function(_nvrams){
			return _nvrams.map(function(elem){return "nvram_default_get(" + elem + ")";}).join("%3B");
		};

		if(forceUpdate) cachedData.clear(objItems);

		objItems.forEach(function(key){
			if(cachedData.get.hasOwnProperty(key + "_default")){
				retData[key] = cachedData.get[key + "_default"];
			}
			else if(asyncData.get.hasOwnProperty(key + "_default")){
				retData[key] = cachedData.get[key + "_default"] = asyncData.get[key + "_default"];
				if(forceUpdate) delete asyncData.get[key + "_default"];
			}
			else{
				queryArray.push(key);
			}
		});

		if(queryArray.length != 0){
			$.ajax({
				url: '/appGet.cgi?hook=' + __nvramget(queryArray),
				dataType: 'json',
				async: false,
				error: function(){
					for(var i=0; i<queryArray.length; i++){retData[queryArray[i]] = "";}
					retData.isError = true;

					$.ajax({
						url: '/appGet.cgi?hook=' + __nvramget(queryArray),
						dataType: 'json',
						error: function(){
							for(var i=0; i<queryArray.length; i++){asyncData.get[queryArray[i] + "_default"] = "";}
						},
						success: function(response){
							Object.keys(response).forEach(function(key){asyncData.get[key + "_default"] = response[key];})
						}
					});
				},
				success: function(response){
					Object.keys(response).forEach(function(key){retData[key] = cachedData.get[key + "_default"] = response[key];})
					retData.isError = false;
				}
			});
		}
		else{
			retData.isError = false;		
		}
		
		return retData;
	},

	"nvramSet": function(postData, handler){
		delete postData.isError;

		$.ajax({
			url: '/applyapp.cgi',
			dataType: 'json',
			data: postData,
			error: function(response){
				if(handler) handler.call(response);
			},
			success: function(response){
				if(handler) handler.call(response);
			}
		})
	},

	"uploadFile": function(postData, handler){
		delete postData.isError;

		var formData = new FormData();
		formData.append('file', postData);

		$.ajax({
			url: 'upload.cgi',
			dataType: 'multipart/form-data',
			data: formData,
			contentType: false,
			processData: false,
			type: 'POST',
			error: function(response){
				if(handler) handler.call(response);
			},
			success: function(response){
				if(handler) handler.call(response);
			}
		 });
	},

	"nvramFormSet": function(postData, handler){
		if(!postData.hasOwnProperty("action")) return false;
		
		$("<iframe>")
			.attr({
				"id": "hiddenFrame",
				"name": "hiddenFrame",
				"width": "0",
				"height": "0",
				"frameborder": "0"
			})
			.appendTo("body")

		var $form = $("<form>", {
			action: postData.action,
			name: "hiddenForm",
			target: "hiddenFrame"
		});

		delete postData.action;	
		Object.keys(postData).forEach(function(key){
			$form.append($("<input>", {
				type: "hidden",
				name: key,
				value: postData[key]
			}));			
		})

		$form.appendTo("body").submit().remove();
		$("#hiddenFrame").remove();
	},

	"hookGet": function(hookName, forceUpdate){
		var queryString = hookName.split("-")[0] + "(" + (hookName.split("-")[1] || "") + ")";
		var retData = {};

		if(cachedData.get.hasOwnProperty(hookName) && !forceUpdate){
			retData[hookName] = cachedData.get[hookName];
		}
		else if(asyncData.get.hasOwnProperty(hookName)){
			retData[hookName] = asyncData.get[hookName];
			if(forceUpdate) delete asyncData.get[hookName];
		}
		else{
			$.ajax({
				url: '/appGet.cgi?hook=' + queryString,
				dataType: 'json',
				async: false,
				error: function(){
					retData[hookName] = "";
					retData.isError = true;
			
					$.ajax({
						url: '/appGet.cgi?hook=' + queryString,
						dataType: 'json',
						error: function(){
							asyncData.get[hookName] = "";
						},
						success: function(response){
							asyncData.get[hookName] = response[hookName];
						}
					});
				},
				success: function(response){
					retData = response;
					cachedData.get[hookName] = response[hookName]
					retData.isError = false;
				}
			});
		}

		return retData;
	},

	"startAutoDet": function(){
		$.get("/appGet.cgi?hook=start_force_autodet()");
	},

	"detwanGetRet": function(){
		var retData = {
			"wanType": "CHECKING",
			"isIPConflict": false,
			"isError": false
		};

		var getDetWanStatus = function(state){
			switch(parseInt(state)){
				case 0:
					if(hadPlugged("modem"))
						retData.wanType = "MODEM";
					else
						retData.wanType = "NOWAN";
					break;
				case 2:
				case 5:
					retData.wanType = "DHCP";
					break;
				case 3:
				case 6:
					retData.wanType = "PPPoE";
					break;
				case 4:
				case "":
					retData.wanType = "CHECKING";
					break;
				case 7:
					retData.wanType = "DHCP";
					retData.isIPConflict = true;
					break;
				default:
					if(hadPlugged("modem")){
						retData.wanType = "MODEM";
					}
					else{
						retData.wanType = "RESETMODEM";
					}
					break;
			}
		}

		$.ajax({
			url: '/detwan.cgi?action_mode=GetWanStatus',
			dataType: 'json',
			async: false,
			error: function(xhr){
				if(asyncData.get.hasOwnProperty("detwanState")){
					getDetWanStatus(asyncData.get["detwanState"]);
					retData.isError = false;

					delete asyncData.get["detwanState"];
				}
				else{
					retData = {
						"wanType": "CHECKING",
						"isIPConflict": false,
						"isError": true
					}

					$.ajax({
						url: '/detwan.cgi?action_mode=GetWanStatus',
						dataType: 'json',
						error: function(xhr){
							asyncData.get["detwanState"] = "UNKNOWN";
						},
						success: function(response){
							asyncData.get["detwanState"] = response.state;
						}
					});
				}
			},
			success: function(response){
				getDetWanStatus(response.state)
			}
		});

		return retData;
	},

	"isAlive": function(hostOrigin, token, callback){
		window.chdom = callback;
		$.getJSON(hostOrigin + "/chdom.json?hostname=" + token + "&callback=?");
	},

	"checkCap": function(targetOrigin, targetId){
		window.chcap = function(){
			setTimeout(function(){
				if(isPage("conncap_page")) window.location.href = targetOrigin + "/cfg_onboarding.cgi?id=" + targetId;
			}, 3000);

			// $("#connCapAlert").hide();
			$("#loginCapAlert").fadeIn(500);
		}

		$.getJSON(targetOrigin + "/chcap.json?callback=?");
	},

	"checkWhatsNews": function(modelName){
		window.whatsnews = function(content){
			var newsString = "";
			var newsId = httpApi.nvramGet(["extendno", "preferred_lang"]);

			try{
				newsString = (content[newsId.extendno].hasOwnProperty(newsId.preferred_lang)) ? content[newsId.extendno][newsId.preferred_lang] : content[newsId.extendno]["EN"];
			}
			catch(e){
				newsString = "";
			}

			// show what's news here
		}

		$.getJSON("https://dlcdnets.asus.com/pub/ASUS/LiveUpdate/Release/Wireless_SQ/News/" + modelName + "_NEWS.zip?callback=?");
	},

	"cleanLog": function(path, callback) {
		if(path != "") {
			var confirm_flag = confirm("Data will not be able to recover once deleted, are you sure you want to clean?");/*untranslated*/
			if(confirm_flag) {
				$.ajax({
					url: '/cleanlog.cgi?path=' + path,
					dataType: 'script',	
					error: function(xhr) {
						alert("Clean error!");/*untranslated*/
					},
					success: function(response) {
						if(typeof callback == "function")
							callback();
					}
				});
			}
		}
		else {
			alert("Clean error, no path!");/*untranslated*/
		}
	}
}
