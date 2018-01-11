<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html">
<title>Save/Reload Setting</title>
<script type="text/javascript" src="common.js"> </script>
<script>

function includeSpace(str)
{
  for (var i=0; i<str.length; i++) {
  	if ( str.charAt(i) == ' ' ) {
	  return true;
	}
  }
  return false;
}

function selectcaClick(object)
{
	document.selectca.rootSelect.value = object.value ;

}
function selectprClick(object)
{
	document.selectca.userSelect.value = object.value ;

}

function saveClick(form)
{
	if(form.name.value.length == 0 ){
		alert("Name  can't be empty !");
		form.name.focus();
		return false;
	}
	if(form.pass != null &&  form.pass.value.length ==0 ){
		alert("pass phrase can't be empty !");
		form.pass.focus();
		return false;
	}
	if(includeSpace(form.name.value)){
		alert('Cannot accept space character in name. Please try it again.');
		form.name.focus();
		return false;
	}
	return true;
}
function deleteClick()
{
  if ( !confirm('Do you really want to delete the selected entry?') ) {
	return false;
  }
  else
	return true;
}

function deleteAllClick()
{
   if ( !confirm('Do you really want to delete the all entries?') ) {
	return false;
  }
  else
	return true;
}
</script>

</head>
<body>
<blockquote>
<h2><font color="#0000FF">Certificate Import </font></h2>
  <table border="0" cellspacing="4" width="500">
  <tr><font size=2>
 This page allows you  import certificate or select certificate suits for TLS client mode.
  </tr>
  <tr><hr size=1 noshade align=top></tr>
  <form method="post" action="goform/formCertUpload" enctype="multipart/form-data" name="rootimport">
  <tr>
    <td width="32%"><font size=2><b>Root CA Name:</b></td>
    <td width="30%"><font size=2><input type="text" name="name" size=24></td>
  </tr>

  <tr>
    <td width="32%"><font size=2><b>Root CA File: (*.cer)</b></td>
    <td width="30%"><font size=2><input type="file" name="binary" size=24></td>
    <td width="20%"><font size=2><input type="submit" value="Upload" name="loadroot" onClick="return saveClick(document.rootimport);"></td>
  </tr>
     <input type="hidden" value="/cert.asp" name="url">
  </form>
  <tr><td colspan=3><hr size=1 noshade ></td></tr>
  <form method="post" action="goform/formCertUpload" enctype="multipart/form-data" name="userimport">
  <tr>
    <td width="32%"><font size=2><b>User CA Name:</b></td>
    <td width="30%"><font size=2><input type="text" name="name" size=24></td>
  </tr>
  <tr>
    <td width="32%"><font size=2><b>Root CA Pass Phrase:</b></td>
    <td width="30%"><font size=2><input type="text" name="pass" size=24></td>
  </tr>
  <tr>
    <td width="32%"><font size=2><b>User CA File: (*.pfx)</b></td>
    <td width="30%"><font size=2><input type="file" name="binary" size=24></td>
    <td width="20%"><font size=2><input type="submit" value="Upload" name="loaduser" onClick="return saveClick(document.userimport);"></td>
  </tr>
     <input type="hidden" value="/cert.asp" name="url">
  </form>
  <tr height=30> <td> </td></tr>
  <tr>
    <td colspan=3><font size=2><b>Root CA Table : </b></td>
  </tr>
  <form method="post" action="goform/formCertUpload" enctype="multipart/form-data" name="rootTable">
  <% certRootList(); %>
  <tr ><td colspan=3>
  <input type="submit" value="Delete Selected" name="deleteSelRoot" onClick="return deleteClick()">&nbsp;&nbsp;
  <input type="submit" value="Delete All" name="deleteAllRoot" onClick="return deleteAllClick()">&nbsp;&nbsp;&nbsp;
  </td>
  </tr>
  <input type="hidden" value="/cert.asp" name="url">
  </form>
  <tr height=30> <td> </td></tr>
  <form method="post" action="goform/formCertUpload" enctype="multipart/form-data" name="userTable">
  <tr>
    <td colspan=3><font size=2><b>User CA Table : </b></td>    
  </tr>
  <% certUserList(); %>
  <tr ><td colspan=3>
  
  <input type="submit" value="Delete Selected" name="deleteSelUser" onClick="return deleteClick()">&nbsp;&nbsp;
  <input type="submit" value="Delete All" name="deleteAllUser" onClick="return deleteAllClick()">&nbsp;&nbsp;&nbsp;
  <input type="hidden" value="/cert.asp" name="url">
  </td>
  </tr>  
  <tr>
  </form>
  <td colspan=3 halign=left>
  <form method="post" action="goform/formCertUpload" enctype="multipart/form-data" name="selectca">
  <input type="hidden" value="0" name="rootSelect">
  <input type="hidden" value="0" name="userSelect"><p align="right">
  <input type="submit" value="Apply Select Change" name="selectca"></p>
  <input type="hidden" value="/cert.asp" name="url">
  </form>
  </td>
  </tr>
  <script>
  	form = document.rootTable ;      
  	
  	i= <% write(getIndex("rootIdx")); %>;
  	j = <% write(getIndex("rootNum")); %>;
  	document.selectca.rootSelect.value = i ;
  	if(i==1 && j ==1)
  		form.selectcert.checked = true;  
  	if(i<=j && form.selectcert[i-1] != null && i != 0)
  		form.selectcert[i-1].checked = true;
			
  	form = document.userTable ;
  	i= <% write(getIndex("userIdx")); %>;
  	j = <% write(getIndex("userNum")); %>;
  	if(i==1 && j ==1)
  		form.selectcert.checked = true;  
  	if(i<=j && form.selectcert[i-1] != null && i != 0)
  		form.selectcert[i-1].checked = true;
  	document.selectca.userSelect.value = i ;
	  		
  </script>
</table>
</blockquote>
</body>
</html>
