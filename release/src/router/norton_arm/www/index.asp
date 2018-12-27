<!DOCTYPE html>
<!--
  Copyright (c) 2012 Symantec Corporation. All rights reserved.
 
 THIS SOFTWARE CONTAINS CONFIDENTIAL INFORMATION AND TRADE SECRETS OF SYMANTEC
 CORPORATION.  USE, DISCLOSURE OR REPRODUCTION IS PROHIBITED WITHOUT THE PRIOR
 EXPRESS WRITTEN PERMISSION OF SYMANTEC CORPORATION.
 
 The Licensed Software and Documentation are deemed to be commercial computer
 software as defined in FAR 12.212 and subject to restricted rights as defined in
 FAR Section 52.227-19 "Commercial Computer Software - Restricted Rights" and
 DFARS 227.7202, "Rights in Commercial Computer Software or Commercial Computer
 Software Documentation", as applicable, and any successor regulations.  Any use,
 modification, reproduction release, performance, display or disclosure of the
 Licensed Software and Documentation by the U.S. Government shall be solely in
 accordance with the terms of this Agreement. 
-->
<html>
<head>
    <script src="jquery-1.8.2.min.js" type="text/javascript"></script>
    <style type="text/css">body{padding:0;margin:0;font-family:Arial;background-color:#fff}</style>
    <title>Please wait...</title></head>
<body>

<noscript>
    <!-- for non-JS browsers, we'll refresh every 5 seconds -->
    <meta http-equiv="refresh" content="5;URL=http://www.google.com">
</noscript>

<div style="width:960px;margin:0 auto;">
    <div style="background:url(loading_page_sprite.jpg) no-repeat -18px -8px; width:72px;height:28px;"></div>
    <div style="text-align:center;color:#666;">
        <h2>Initializing Norton <em>&quot;Apollo&quot;</em></h2>
        <h4>Please wait<span id="redirect-loader">&nbsp;...</span></h4>
        <img src="apolloLoader.gif"  width="214" height="233" alt="loading" style="margin:20px 0 0px 0"/>
        <h4 id="state"></h4>
    </div>
    <div style="border-top: solid 1px #efefef;margin:80px 0 4px 0;"></div>
</div>

    <script type="text/javascript">
        var resources = {
            stateNet: "Waiting for an active Internet connection.",
            stateDownload: "Downloading the Norton Apollo components.",
            stateInstall: "Installing Norton Apollo.",
            stateReady: "Norton Apollo is ready!",
            stateWait: "Waiting.",
            stateError: "Error."
        };
        var info = {
                       state: '<% nvram_get("nga_state"); %>',
                       progress: '<% nvram_get("nga_progress"); %>'
                   };
        updateState();

        function withProgress(t) {
            if(info.progress && info.progress.length > 0)
                return t + " (" + info.progress + ")";
            return t;
        }

        function updateState() {
            switch(parseInt(info.state)) {
                case 0:
                    $("#state").text(resources.stateNet);
                    break;
                case 1:
                    $("#state").text(withProgress(resources.stateDownload));
                    break;
                case 2:
                    $("#state").text(withProgress(resources.stateInstall));
                    break;
                case 3:
                    $("#state").text(resources.stateReady);
                    setTimeout(function() { window.location.reload(); }, 1000);
                    return;
                default:
                    $("#state").text(resources.stateWait);
                    setTimeout(function() { window.location.reload(); }, 5000);
                    return;
            }

            setTimeout(function() {
                $.ajax({
                    url: '/status.asp',
                    type: 'GET',
                    dataType: 'json',
                    success: function (response) {
                        info = response;
                        updateState();
                    },
                    error: function (request, status, error) {
                        $("#state").text(resources.stateError);
                        setTimeout(function() { window.location.reload(); }, 1000);
                    }
                });
            }, 2500);

        }

    </script>

</body>
</html>
