///////////////////////////////////////////////////////////////////////////
//  Comments for this code can be found in source control
//////////////////////////////////////////////////////////////////////////
function get_videoid() {
		if (GetCaseInSensitive('videoid') != null)
			return GetCaseInSensitive('videoid');
		else
			return 0;
}

function get_videoChannelId() {
        if(typeof(ad_Video_CID)!="undefined")if(ad_Video_CID != 0)return ad_Video_CID;
        else
		if (GetCaseInSensitive('channelid') != null)
			return GetCaseInSensitive('channelid');
		else 
			return 0;
}

function get_videoUserCategoryId() {
		if(typeof(ad_Video_RID)!="undefined")if(ad_Video_RID != 0)return ad_Video_RID;
        else
		if (GetCaseInSensitive('rid') != null)
			return GetCaseInSensitive('rid');
		else
			return 0;
}

function get_groupCategoryId() {
		if(typeof(ad_Group_CID)!="undefined")if(ad_Group_CID != 0)return ad_Group_CID;
		else
			return 0;
}

function get_adTopicId() {
		if(typeof(ad_Topic_ID)!="undefined")if(ad_Topic_ID != 0)return ad_Topic_ID;
		else
			return 0;
}

function GetCaseInSensitive(key)
{ 
QueryString_Parse();
for (var i = 0; i < QueryString.keys.length; i++)
 {
 if(QueryString.keys[i].toLowerCase() == key.toLowerCase())return escape(QueryString.values[i].toLowerCase());
 }
return null;
}

function get_DownloadCategory() {
		var dcat = "";
		if (GetCaseInSensitive('cat') != null)
			dcat =  GetCaseInSensitive('cat');
			
			if(dcat=="audiovideo")return 1;
			if(dcat=="business")return 2;
			if(dcat=="camera")return 3;
			if(dcat=="desktopenhancements")return 4;
			if(dcat=="devtools")return 5;
			if(dcat=="homeanded")return 6;
			if(dcat=="internet")return 7;
			if(dcat=="isit")return 8;
			if(dcat=="utilities")return 9;
			if(dcat=="spywarecenter")return 10;
			if(dcat=="powerdownloader")return 11;
			if(dcat=="mobile")return 12;
			if(dcat=="mac")return 13;
			return 0;		
}

function full(vid)
{
  var fs = window.open( "http://vids.myspace.com/index.cfm?fuseaction=vids.fullscreen&videoid=" + vid,
		   "fsv", "toolbar=no,width=" + screen.availWidth  + ",height=" + screen.availHeight 
		 + ",status=no,resizable=yes,fullscreen=yes,scrollbars=no");
  fs.focus();
}
function deleteUser(friendid, name, url){
	if ( confirm('Are you sure you want to delete ' + name + ' from your list of friends?') ) {
		location.href = url;
	}
}
var checkflag = "false";
function checkUncheckAll(f){
	if (checkflag == "false") {
		for (i=0; i < f.length; i++) {
			f[i].checked = true;
		}
		f.checked = true;
		checkflag = "true";
	}else {
		for (i=0; i < f.length; i++) {
			f[i].checked = false;
		}
		f.checked = false;
		checkflag = "false";
	}
}

function checkCountry(form){
	if(form.f_country.value != 'US'){
		form.f_region.disabled = true;
		form.f_region_other.disabled = false;
		form.f_region_other.value = '';
		form.f_region_other.focus();
	}else{
		form.f_region.disabled = false;
		form.f_postal_code.disabled = false;
		form.f_region_other.disabled = true;
		form.f_region_other.value = '(NA)';
	}
}

function registerEvent(object, event, cmd, append)
{
	if(arguments.length < 3) { return alert("Invalid arguments. Please use the format \nregisterEvent(object, event, command, [append])."); }
	if (typeof append != "boolean") {append = true; }

	event = object + "." + event.toLowerCase();
	var objEvent = eval(event);

	var strEvent = (objEvent) ? objEvent.toString() : "";
	strEvent = strEvent.substring(strEvent.indexOf("{")+1, strEvent.lastIndexOf("}"));
	strEvent = (append) ? (strEvent + cmd) : (cmd + strEvent);
	strEvent += "\n";
	eval(event + " = new Function(strEvent)");
	return true;
}

function countCharacters(formName, elementName)
{
	var formElementString = "document." + formName + "." + elementName;
	var ID = formElementString + ".CharacterCount";

	if (!document.getElementById(ID)) {document.write("<INPUT ID='" + ID + "' TYPE='TEXT' SIZE='4' onfocus='blur();'>");}
	
	var functionString = "updateCountCharacters('" + formElementString + "');";
	
	registerEvent("window", "onload", "registerEvent(\"" + formElementString + "\", \"onkeydown\", \"" + functionString + "\", false);", false);
	registerEvent("window", "onload", "registerEvent(\"" + formElementString + "\", \"onkeyup\", \"" + functionString + "\", false);", false);
	registerEvent("window", "onload", functionString, false);
	setInterval(functionString, 1000);
}

function updateCountCharacters(formElementString)
{
	var formElement = eval(formElementString);
	var ID = formElementString + ".CharacterCount";
	var formElementValue = formElement.value.replace(/\n/g, '\r\n').replace(/\r\r/g, '\r');
	document.getElementById(ID).value = parseInt(formElementValue.length, 10);
}

function generalizeDomain()
{
	var domainArray = document.domain.split(".");
	var domainArrayLength = domainArray.length;
	if (domainArrayLength >= 2) {document.domain = domainArray[domainArrayLength - 2] + "." + domainArray[domainArrayLength - 1];}
}

if ( (QueryString('fuseaction') != 'blog.create') && 
	 (QueryString('fuseaction') != 'blog.edit') && 
	 (QueryString('fuseaction') != 'blog.commentreply') && 
	 (QueryString('fuseaction') != 'blog.comment') &&
	 (QueryString('fuseaction') != 'forums.post') ) {
	generalizeDomain();
}

function openWin( windowURL, windowName, windowFeatures ) { 
	return window.open( windowURL, windowName, windowFeatures ) ;
}

function QueryString_Parse() {
	QueryString.keys = [];
	QueryString.values = [];
	var query = window.location.search.substring(1);
	var pairs = query.split("&");
	for (var i = 0; i < pairs.length; i++) {
		var pos = pairs[i].indexOf('=');
		if (pos >= 0) {
			var argname = pairs[i].substring(0,pos);
			var value = pairs[i].substring(pos+1);
			QueryString.keys[QueryString.keys.length] = argname;
			QueryString.values[QueryString.values.length] = value;
		}
	}
}

function QueryString(key) {
	QueryString_Parse();
	var value = null;
	for (var i = 0; i < QueryString.keys.length; i++) {
		if (QueryString.keys[i] == key) {
			value = escape(QueryString.values[i].toLowerCase());
			break;
		}
	}
	return value;
}

function wrapFF(which, atlen) {
	if (navigator.userAgent.toLowerCase().indexOf("firefox") != -1) {
		var start = which.innerHTML;
		var finish = start.substr(0,1);
		var mini = "";
		var inTag = 0;
		var current = 0;
		var next = "";
		while (start.length) {
			mini = start.substr(1,1);
			finish = finish + mini;
			start = start.substring(1, start.length);
			switch (mini) {
				case " ":
					current = 0;
				break;
				case "<":
					inTag = 1;
					current = 0;
				break;
				case ">":
					inTag = 0;
					current = 0;
				break;
				default:
					if (!inTag) {
						current = current + 1;
						next = start.substring(0,Math.min(3,start.length));
						if (current == atlen && (next.indexOf("<") == -1) && (next.indexOf(">") == -1) && (next.indexOf(" ") == -1) ) {
							finish = finish + " ";
							current = 0;
						}
					}
				}
		}
		which.innerHTML = finish;
	}
}

function stripTicks(str)
{
	var s = str;
	while(s.indexOf("'") != -1) {
	s = s.replace("'",""); }
	return s;
}

function random()
{
	randomseed = (randomseed * randoma + randomc) % randomm;
	return randomseed / randomm;
}

var randomm = 714025;
var randoma = 4096;
var randomc = 150889;
var acnt	= 1;


randomseed = Date.parse(new Date()); 
randomNumber = random() + "";
if (typeof OASHost == "undefined") {OASHost = "www";}


function get_url() { //el=str, case_sensitive=bool
	var rs="i";
	var urls = document.URL;
	urls = stripTicks(urls);

	var el = "friendID";
	var re = new RegExp( "\\?[\\w\\W]*"+ el +"=([^\\&\\?#]*)", rs);
	var arr = re.exec(urls);
if (!arr) {
	elg = "groupID";
	var red = new RegExp( "\\?[\\w\\W]*"+ elg +"=([^\\&\\?#]*)", rs);
	arr = red.exec(urls);
	}
	if(arr && arr.length>1){	
	return arr[1];
	}else{ 
	var expr = /\/([\w]*)$/i;
	arr = expr.exec(urls);
		if(arr && arr.length>1) {
			return arr[1].toLowerCase(); }
		else {
			return ''; }
	}
}

function oas_ad()
{
	var argv = oas_ad.arguments;
	var friendID = 0;
	var AdTopicID = 0;
	var videoID = 0;
	var videoChannel = 0;
	var videoUserCat = 0;
	var downloadCat = 0;
	var page = argv[0];
	var pos = argv[1];
	var pxsize = '';
	var groupCatID =0;
    var isSDCPage = false; 
  
	videoID = get_videoid();
    videoUserCat = get_videoUserCategoryId();
    videoChannel = get_videoChannelId();
    downloadCat = get_DownloadCategory();

    AdTopicID = get_adTopicId();
    groupCatID = get_groupCategoryId();

	subd = 'deSB';

	re_ex = /,/;
	
	temp_flag = 0;
	if(re_ex.test(page)){
		site_arr = page.split(",");
		page = site_arr[1];
	}
	
	switch (pos)
	{
		case 'Frame1':
			friendID = get_url();
			pxsize = 'width=728 height=90';
			pos = 'leaderboard&params.styles=leaderboard';
			subd = 'deLB';
			break;
		case 'Top':
		    friendID = get_url();
			pxsize = 'width=468 height=60';
			pos = 'banner';
			subd = 'deBR';
			break;
		case 'x08':
		    friendID = get_url();
			pxsize = 'width=430 height=600';
			pos = 'halfpage';
			subd = 'deHP';
			break;
		case 'x14':
			pxsize = 'width=300 height=250';
			pos = 'mrec';
			subd = 'deMR';
			friendID = get_url();
			break;
		case 'x15':
		    friendID = get_url();
			pxsize = 'width=160 height=600';
			pos = 'skyscraper';
			subd = 'deSK';
			break;
		case 'x54': //feature profile
			pxsize = 'width=225 height=170';
			pos = 'profile';
			subd = 'deFP';
			break;
		case 'x54-1': //feature profile small
			pxsize = 'width=200 height=170';
			pos = 'profile';
			subd = 'uhpfp';
			break;
		case 'x55': //feature group
			pxsize = 'width=640 height=280';
			pos = 'group';
			subd = 'deFG';
			break;
		case 'x56':
			pxsize = 'width=460 height=140';
			break;
		case 'x69': // This was added for the anchor man inbox add.
			pxsize = 'width=628 height=288';
			break;
		case 'x77':
			pxsize = 'width=1 height=1';
			pos = '1x1';
			subd = 'deSB';
			break;
		case 'x78': // login page
			pxsize = 'width=750 height=600';
			pos = 'interstitial';
			subd = 'deSB';
			break;
		case 'x85':
			pxsize = 'width=300 height=300';
			break;
		case 'x86':
			pxsize = 'width=465 height=360';
			break;
		case 'x87':
			pxsize = 'width=463 height=400';
			break;
		case 'x88':
			pxsize = 'width=440 height=140';
			pos = 'featuredband';
			subd = 'deFB';
			break;
		case 'fspecial':
			pxsize = 'width=440 height=140';
			pos = 'fspecial';
			subd = 'deSB';
			break;
		case 'featblg':
			pxsize = 'width=500 height=100';
			pos = 'featblg';
			subd = 'deSB';
			break;
		case 'uhpfp': //uhp feature profile
			pxsize = 'width=200 height=170';
			pos = 'uhpfp';
			subd = 'deFP';
			break;
		case 'west':
			pxsize = 'width=440 height=160';
			pos = 'west';
			subd = 'deWB';
			break;
		case 'east':
		    friendID = get_url();
			pxsize = 'width=300 height=100';
			pos = 'east';
			subd = 'deEB';
			break;
		case 'featvid':
			pxsize = 'width=300 height=170';
			pos = 'featvid';
			subd = 'deFV';
			break;
		case 'movpro':
			pxsize = 'width=300 height=250';
			pos = 'movpro';
			subd = 'deMP';
			break;
		case 'fmovl':
			pxsize = 'width=229 height=216';
			pos = 'fmovl';
			subd = 'deFML';
			break;
		case 'fmovr':
			pxsize = 'width=229 height=216';
			pos = 'fmovr';
			subd = 'deFMR';
			break;
		case 'vrec':
			pxsize = 'width=240 height=400';
			pos = 'vrec';
			subd = 'deVR';
			break;
        case 'Leaderboard2':
            friendID = get_url();
            pxsize = 'width=728 height=90';
            pos = 'leaderboard2&params.styles=leaderboard';
            subd = 'deLB2';
            break;
		default:
			pxsize = 'width=468 height=60';
			pos = 'test';
			break;
	}
	
    try
    {
        //parse the cookie for JP
        var cultureCookie = readCookie('MSCulture');
        var cookieKey = '&IPCulture=';
        var keyindex = cultureCookie.indexOf(cookieKey);
        var culture = cultureCookie.substring(keyindex + cookieKey.length,cultureCookie.length);
        if (culture.indexOf('&') >= 0) culture = culture.substring(0, culture.indexOf('&'));
        if (culture.indexOf('ja-JP') >= 0) subd = 'adjp01';
    }
    catch(e)
    {}
	
	var rand = randomNumber.substring(2,11);
    var testmode = false;
    var special = '';

	if(friendID){
		friendID = "&friendid="+friendID;
	}
	
	if(AdTopicID){
		AdTopicID = "&category="+AdTopicID;
	}
	else
	{
		AdTopicID = "";
	}

	if(videoID){
		videoID = "&videoID="+videoID;
	}
	else
	{
		videoID = "";
	}
	
	if(videoUserCat){
		videoUserCat = "&rid="+videoUserCat;
	}
	else
	{
		videoUserCat = "";
	}
	
	if(videoChannel){
		videoChannel = "&channelid="+videoChannel;
	}
	else
	{
		videoChannel = "";
	}
	
	if(downloadCat){
		downloadCat = "&downcat="+downloadCat;
	}
	else
	{
		downloadCat = "";
	}
	
	if (QueryString('schoolID') != null)
		var SchoolID = QueryString('schoolID');
	else
		var SchoolID = 0;

	if (QueryString('special') != null)
	{
		testmode = true;
		special = QueryString('special');
	}
	
	var runBandGenreAd=false;
	if(document.getElementById("bandgenre1")){
		runBandGenreAd= (document.getElementById("bandgenre1").parentNode.childNodes.length==3);
	}
	
	isSDCPage = (page == '11002001');
	
	if (isSDCPage && subd != 'adjp01')
	{
	   pxsize = 'width=728 height=90';
	   pos = 'leaderboard';
	   subd = 'deLB';
	
	   document.write("<IFRAME " + pxsize + " style=\"position:relative;z-index:10000\" MARGINWIDTH=0 MARGINHEIGHT=0 HSPACE=0 VSPACE=0 FRAMEBORDER=0 SCROLLING=no src='http://"+subd+".opt.fimserve.com/adopt/?l="+page+"&pos=" + pos + "&r=h&rnd="+rand+"'></iframe>");
    } 
	else
	{
	    if(runBandGenreAd)
	    {
	        if(testmode){
    		    document.write("<IFRAME " + pxsize + " style=\"position:relative;z-index:10000\" MARGINWIDTH=0 MARGINHEIGHT=0 HSPACE=0 VSPACE=0 FRAMEBORDER=0 SCROLLING=no src='http://detst.myspace.com/html.ng/site=myspace&position="+pos+"&page="+page+"&rand="+rand+friendID+AdTopicID+"&acnt="+acnt+"&schoolpage="+SchoolID+"&bandgenre="+document.forms[0].bandgenre1.value+"&bandgenre="+document.forms[0].bandgenre2.value+"&bandgenre="+document.forms[0].bandgenre3.value+"&special="+special+videoID+videoUserCat+videoChannel+downloadCat+"'></iframe>");
    	    }
	        else {
    		    document.write("<IFRAME " + pxsize + " style=\"position:relative;z-index:10000\" MARGINWIDTH=0 MARGINHEIGHT=0 HSPACE=0 VSPACE=0 FRAMEBORDER=0 SCROLLING=no src='http://"+subd+".myspace.com/html.ng/site=myspace&position="+pos+"&page="+page+"&rand="+rand+friendID+AdTopicID+"&acnt="+acnt+"&schoolpage="+SchoolID+"&bandgenre="+document.forms[0].bandgenre1.value+"&bandgenre="+document.forms[0].bandgenre2.value+"&bandgenre="+document.forms[0].bandgenre3.value+videoID+videoUserCat+videoChannel+downloadCat+"'></iframe>");
    	    }
	    }
	    else
	    {
	        if (testmode){
    		    document.write("<IFRAME " + pxsize + " style=\"position:relative;z-index:10000\" MARGINWIDTH=0 MARGINHEIGHT=0 HSPACE=0 VSPACE=0 FRAMEBORDER=0 SCROLLING=no src='http://detst.myspace.com/html.ng/site=myspace&position="+pos+"&page="+page+"&rand="+rand+friendID+AdTopicID+"&acnt="+acnt+"&schoolpage="+SchoolID+"&special="+special+videoID+videoUserCat+videoChannel+downloadCat+"'></iframe>");
    	    }
	        else {
    		    document.write("<IFRAME " + pxsize + " style=\"position:relative;z-index:10000\" MARGINWIDTH=0 MARGINHEIGHT=0 HSPACE=0 VSPACE=0 FRAMEBORDER=0 SCROLLING=no src='http://"+subd+".myspace.com/html.ng/site=myspace&position="+pos+"&page="+page+"&rand="+rand+friendID+AdTopicID+"&acnt="+acnt+"&schoolpage="+SchoolID+videoID+videoUserCat+videoChannel+downloadCat+"'></iframe>");
    	    }
	    }
	}
	acnt = acnt + 1;

}



var serverPath = "";

function reverse(inputString)
{
	var outputString = "";
	for (var i = inputString.length - 1; i >= 0; i--) {outputString += inputString.charAt(i);}
	return outputString;
}

function left(inputString, n)
{
	if (inputString.length > n) {return inputString.substring(0, n);}
	else {return inputString;}
}

function right(inputString, n)
{
	if (inputString.length > n) {return inputString.substring(inputString.length - n);}
	else {return inputString;}
}

function padLeft (inputString, stringLength, padCharacter)
{
	var outputString = inputString;
	var c = padCharacter.substring(0, 1); 
	while (outputString.length < stringLength) {outputString = c + outputString;}
	return outputString;
}

function padRight(inputString, stringLength, padCharacter)
{
	var outputString = inputString;
	var c = padCharacter.substring(0, 1); 
	while (outputString.length < stringLength) {outputString = outputString + c;}
	return outputString;
}

function wddxSerializer_serializeValue(obj)
{
	var bSuccess = true;
	var val;

	if (obj === null)
	{
		this.write("<null/>");
	}
	else if (typeof(val = obj.valueOf()) == "string")
	{
		this.serializeString(val);
	}
	else if (typeof(val = obj.valueOf()) == "number")
	{
		if (
			typeof(obj.getTimezoneOffset) == "function" &&
			typeof(obj.toGMTString) == "function")
		{
			this.write("<dateTime>" + 
				(obj.getYear() < 1000 ? 1900+obj.getYear() : obj.getYear()) + "-" + (obj.getMonth() + 1) + "-" + obj.getDate() +
				"T" + obj.getHours() + ":" + obj.getMinutes() + ":" + obj.getSeconds());
			if (this.useTimezoneInfo)
			{
				this.write(this.timezoneString);
			}
			this.write("</dateTime>");
		}
		else
		{
			this.write("<number>" + val + "</number>");
		}
	}
	else if (typeof(val = obj.valueOf()) == "boolean")
	{
		this.write("<boolean value='" + val + "'/>");
	}
	else if (typeof(obj) == "object")
	{
		if (typeof(obj.wddxSerialize) == "function")
		{
			bSuccess = obj.wddxSerialize(this);
		}
		else if (
			typeof(obj.join) == "function" &&
			typeof(obj.reverse) == "function" &&
			typeof(obj.sort) == "function" &&
			typeof(obj.length) == "number")
		{
			this.write("<array length='" + obj.length + "'>");
			for (var i = 0; bSuccess && i < obj.length; ++i)
			{
				bSuccess = this.serializeValue(obj[i]);
			}
			this.write("</array>");
		}
		else
		{

			if (typeof(obj.wddxSerializationType) == 'string')
			{
				this.write('<struct type="'+ obj.wddxSerializationType +'">');
			}
			else
			{
				this.write("<struct>");
			}
						
			for (var prop in obj)
			{
				if (prop != 'wddxSerializationType')
				{
					bSuccess = this.serializeVariable(prop, obj[prop]);
					if (! bSuccess)
					{
						break;
					}
				}
			}
			
			this.write("</struct>");
		}
	}
	else
	{
		bSuccess = false;
	}
	return bSuccess;
}

function wddxSerializer_serializeAttr(s)
{
	for (var i = 0; i < s.length; ++i)
	{
		this.write(this.at[s.charAt(i)]);
	}
}

function wddxSerializer_serializeAttrOld(s)
{
	this.write(s);
}

function wddxSerializer_serializeString(s)
{
	this.write("<string>");
	for (var i = 0; i < s.length; ++i)
	{
		this.write(this.et[s.charAt(i)]);
	}
	this.write("</string>");
}

function wddxSerializer_serializeStringOld(s)
{
	this.write("<string><![CDATA[");
	
	pos = s.indexOf("]]>");
	if (pos != -1)
	{
		startPos = 0;
		while (pos != -1)
		{
			this.write(s.substring(startPos, pos) + "]]>]]&gt;<![CDATA[");
			
			startPos = pos + 3;
			if (startPos < s.length)
			{
				pos = s.indexOf("]]>", startPos);
			}
			else
			{
				pos = -1;
			}
		}
		this.write(s.substring(startPos, s.length));
	}
	else
	{
		this.write(s);
	}
			
	this.write("]]></string>");
}

function wddxSerializer_serializeVariable(name, obj)
{
	var bSuccess = true;
	
	if (typeof(obj) != "function")
	{
		this.write("<var name='");
		this.preserveVarCase ? this.serializeAttr(name) : this.serializeAttr(name.toLowerCase());
		this.write("'>");

		bSuccess = this.serializeValue(obj);
		this.write("</var>");
	}

	return bSuccess;
}

function wddxSerializer_write(str)
{
	this.wddxPacket[this.wddxPacket.length] = str;
}

function wddxSerializer_writeOld(str)
{
	this.wddxPacket += str;
}

function wddxSerializer_initPacket()
{
	this.wddxPacket = [];
}
function wddxSerializer_initPacketOld()
{
	this.wddxPacket = "";
}

function wddxSerializer_extractPacket()
{
	return this.wddxPacket.join("");
}

function wddxSerializer_extractPacketOld()
{
	return this.wddxPacket;
}

function wddxSerializer_serialize(rootObj)
{
	this.initPacket();

	this.write("<wddxPacket version='1.0'><header/><data>");
	var bSuccess = this.serializeValue(rootObj);
	this.write("</data></wddxPacket>");

	if (bSuccess)
	{
		return this.extractPacket();
	}
	else
	{	
		return null;
	}
}

function WddxSerializer()
{
	if (navigator.appVersion !== "" && navigator.appVersion.indexOf("MSIE 3.") == -1)
	{
		var et = [];
		var n2c = [];
		var c2n = [];
		var at = [];

		for (var i = 0; i < 256; ++i)
		{
			var d1 = Math.floor(i/64);
			var d2 = Math.floor((i%64)/8);
			var d3 = i%8;
			var c = eval("\"\\" + d1.toString(10) + d2.toString(10) + d3.toString(10) + "\"");
			n2c[i] = c;
			c2n[c] = i; 
			if (i < 32 && i != 9 && i != 10 && i != 13)
			{
				var hex = i.toString(16);
				if (hex.length == 1)
				{
					hex = "0" + hex;
				}

				et[n2c[i]] = "<char code='" + hex + "'/>";
				at[n2c[i]] = "";

			}
			else if (i < 128)
			{
				et[n2c[i]] = n2c[i];
				at[n2c[i]] = n2c[i];
			}
			else
			{
				et[n2c[i]] = "&#x" + i.toString(16) + ";";
				at[n2c[i]] = "&#x" + i.toString(16) + ";";
			}
		}
		et["<"] = "&lt;";
		et[">"] = "&gt;";
		et["&"] = "&amp;";

		at["<"] = "&lt;";
		at[">"] = "&gt;";
		at["&"] = "&amp;";
		at["'"] = "&apos;";
		at["\""] = "&quot;";

		this.n2c = n2c;
		this.c2n = c2n;
		this.et = et;    
		this.at = at;
		
		this.serializeString = wddxSerializer_serializeString;
		this.serializeAttr = wddxSerializer_serializeAttr;
		this.write = wddxSerializer_write;
		this.initPacket = wddxSerializer_initPacket;
		this.extractPacket = wddxSerializer_extractPacket;
	}
	else
	{
		// The browser is most likely MSIE 3.x, it is NS 2.0 compatible
		this.serializeString = wddxSerializer_serializeStringOld;
		this.serializeAttr = wddxSerializer_serializeAttrOld;
		this.write = wddxSerializer_writeOld;
		this.initPacket = wddxSerializer_initPacketOld;
		this.extractPacket = wddxSerializer_extractPacketOld;
	}

	var tzOffset = (new Date()).getTimezoneOffset();

	if (tzOffset >= 0)
	{
		this.timezoneString = '-';
	}
	else
	{
		this.timezoneString = '+';
	}
	this.timezoneString += Math.floor(Math.abs(tzOffset) / 60) + ":" + (Math.abs(tzOffset) % 60);

	this.preserveVarCase = false;
	this.useTimezoneInfo = true;

	// Common functions
	this.serialize = wddxSerializer_serialize;
	this.serializeValue = wddxSerializer_serializeValue;
	this.serializeVariable = wddxSerializer_serializeVariable;
}

function wddxRecordset_isColumn(name)
{
	return (typeof(this[name]) == "object" && 
		    name.indexOf("_private_") == -1);
}

function wddxRecordset_getRowCount()
{
	var nRowCount = 0;
	for (var col in this)
	{
		if (this.isColumn(col))
		{
			nRowCount = this[col].length;
			break;
		}
	}
	return nRowCount;
}

function wddxRecordset_addColumn(name)
{
	var nLen = this.getRowCount();
	var colValue = new Array(nLen);
	for (var i = 0; i < nLen; ++i)
	{
		colValue[i] = null;
	}
	this[this.preserveFieldCase ? name : name.toLowerCase()] = colValue;
}

function wddxRecordset_addRows(n)
{
	for (var col in this)
	{
		if (this.isColumn(col))
		{
			var nLen = this[col].length;
			for (var i = nLen; i < nLen + n; ++i)
			{
				this[col][i] = null;
			}
		}
	}
}

function wddxRecordset_getField(row, col)
{
	return this[this.preserveFieldCase ? col : col.toLowerCase()][row];
}

function wddxRecordset_setField(row, col, value)
{
	this[this.preserveFieldCase ? col : col.toLowerCase()][row] = value;
}

function wddxRecordset_wddxSerialize(serializer)
{
	// Create an array and a list of column names
	var colNamesList = "";
	var colNames = [];
	var i = 0;
	for (var col in this)
	{
		if (this.isColumn(col))
		{
			colNames[i++] = col;

		if (colNamesList.length > 0)
			{
				colNamesList += ",";
			}
			colNamesList += col;
		}
	}
	
	var nRows = this.getRowCount();
	
	serializer.write("<recordset rowCount='" + nRows + "' fieldNames='" + colNamesList + "'>");
	
	var bSuccess = true;
	for (i = 0; bSuccess && i < colNames.length; i++)
	{
		var name = colNames[i];
		serializer.write("<field name='" + name + "'>");
		
		for (var row = 0; bSuccess && row < nRows; row++)
		{
			bSuccess = serializer.serializeValue(this[name][row]);
		}
		
		serializer.write("</field>");
	}
	
	serializer.write("</recordset>");
	
	return bSuccess;
}

function wddxRecordset_dump(escapeStrings)
{
	// Get row count
	var nRows = this.getRowCount();
	
	// Determine column names
	var colNames = [];
	var i = 0;
	for (var col in this)
	{
		if (typeof(this[col]) == "object")
		{
			colNames[i++] = col;
		}
	}

	var o = "<table border=1><tr><td><b>RowNumber</b></td>";
	for (i = 0; i < colNames.length; ++i)
	{
		o += "<td><b>" + colNames[i] + "</b></td>";
	}
	o += "</tr>";
	
	// Build data cells
	for (var row = 0; row < nRows; ++row)
	{
		o += "<tr><td>" + row + "</td>";
		for (i = 0; i < colNames.length; ++i)
		{
			var elem = this.getField(row, colNames[i]);
		if (escapeStrings && typeof(elem) == "string")
			{
				var str = "";
				for (var j = 0; j < elem.length; ++j)
				{
					var ch = elem.charAt(j);
					if (ch == '<')
					{
						str += "&lt;";
					}
					else if (ch == '>')
					{
						str += "&gt;";
					}
					else if (ch == '&')
					{
						str += "&amp;";
					}
					else
					{
						str += ch;
					}
				}
				o += ("<td>" + str + "</td>");
			}
			else
			{
				o += ("<td>" + elem + "</td>");
			}
		}
		o += "</tr>";
	}

	o += "</table>";

	return o;
}

function WddxRecordset()
{
	this.preserveFieldCase = false;
	if (typeof(wddxRecordsetExtensions) == "object")
	{
		for (var prop in wddxRecordsetExtensions)
		{
			this[prop] = wddxRecordsetExtensions[prop];
		}
	}
	this.getRowCount = wddxRecordset_getRowCount;
	this.addColumn = wddxRecordset_addColumn;
	this.addRows = wddxRecordset_addRows;
	this.isColumn = wddxRecordset_isColumn;
	this.getField = wddxRecordset_getField;
	this.setField = wddxRecordset_setField;
	this.wddxSerialize = wddxRecordset_wddxSerialize;
	this.dump = wddxRecordset_dump;

	if (WddxRecordset.arguments.length > 0)
	{
		if (typeof(val = WddxRecordset.arguments[0].valueOf()) == "boolean")
		{
			this.preserveFieldCase = WddxRecordset.arguments[0];
		}
		else
		{
			var cols = WddxRecordset.arguments[0];
			var nLen = 0;
			if (WddxRecordset.arguments.length > 1)
			{
				if (typeof(val = WddxRecordset.arguments[1].valueOf()) == "boolean")
				{
					this.preserveFieldCase = WddxRecordset.arguments[1];
				}
				else
				{
					nLen = WddxRecordset.arguments[1];

					if (WddxRecordset.arguments.length > 2)
					{
						this.preserveFieldCase = WddxRecordset.arguments[2];
					}
				}
			}
			
			for (var i = 0; i < cols.length; ++i)
			{
				var colValue = new Array(nLen);
				for (var j = 0; j < nLen; ++j)
				{
					colValue[j] = null;
				}
			
				this[this.preserveFieldCase ? cols[i] : cols[i].toLowerCase()] = colValue;
			}
		}
	}
}

function registerWddxRecordsetExtension(name, func)
{
	// Perform simple validation of arguments
	if (typeof(name) == "string" && typeof(func) == "function")
	{
		// Guarantee existence of wddxRecordsetExtensions object
		if (typeof(wddxRecordsetExtensions) != "object")
		{
			// Create wddxRecordsetExtensions instance
			wddxRecordsetExtensions = {};
		}
		
		// Register extension; override an existing one
		wddxRecordsetExtensions[name] = func;
	}
}

function wddxBinary_wddxSerialize(serializer) 
{
	serializer.write(
		"<binary encoding='" + this.encoding + "'>" + this.data + "</binary>");
	return true;
}

function WddxBinary(data, encoding)
{
	this.data = data !== null ? data : "";
	this.encoding = encoding !== null ? encoding : "base64";

	// Custom serialization mechanism
	this.wddxSerialize = wddxBinary_wddxSerialize;
}

function BrowserDetect() {
	var ua = navigator.userAgent.toLowerCase(); 

	this.isGecko       = (ua.indexOf('gecko') != -1 && ua.indexOf('safari') == -1);
	this.isAppleWebKit = (ua.indexOf('applewebkit') != -1);

	this.isKonqueror   = (ua.indexOf('konqueror') != -1); 
	this.isSafari      = (ua.indexOf('safari') != - 1);
	this.isOmniweb     = (ua.indexOf('omniweb') != - 1);
	this.isOpera       = (ua.indexOf('opera') != -1); 
	this.isIcab        = (ua.indexOf('icab') != -1); 
	this.isAol         = (ua.indexOf('aol') != -1); 
	this.isIE          = (ua.indexOf('msie') != -1 && !this.isOpera && (ua.indexOf('webtv') == -1) ); 
	this.isMozilla     = (this.isGecko && ua.indexOf('gecko/') + 14 == ua.length);
	this.isFirebird    = (ua.indexOf('firebird/') != -1);
	this.isNS          = ( (this.isGecko) ? (ua.indexOf('netscape') != -1) : ( (ua.indexOf('mozilla') != -1) && !this.isOpera && !this.isSafari && (ua.indexOf('spoofer') == -1) && (ua.indexOf('compatible') == -1) && (ua.indexOf('webtv') == -1) && (ua.indexOf('hotjava') == -1) ) );

	this.isIECompatible = ( (ua.indexOf('msie') != -1) && !this.isIE);
	this.isNSCompatible = ( (ua.indexOf('mozilla') != -1) && !this.isNS && !this.isMozilla);

	this.geckoVersion = ( (this.isGecko) ? ua.substring( (ua.lastIndexOf('gecko/') + 6), (ua.lastIndexOf('gecko/') + 14) ) : -1 );
	this.equivalentMozilla = ( (this.isGecko) ? parseFloat( ua.substring( ua.indexOf('rv:') + 3 ) ) : -1 );
	this.appleWebKitVersion = ( (this.isAppleWebKit) ? parseFloat( ua.substring( ua.indexOf('applewebkit/') + 12) ) : -1 );

	this.versionMinor = parseFloat(navigator.appVersion); 

	if (this.isGecko && !this.isMozilla) {
		this.versionMinor = parseFloat( ua.substring( ua.indexOf('/', ua.indexOf('gecko/') + 6) + 1 ) );
	}
	else if (this.isMozilla) {
		this.versionMinor = parseFloat( ua.substring( ua.indexOf('rv:') + 3 ) );
	}
	else if (this.isIE && this.versionMinor >= 4) {
		this.versionMinor = parseFloat( ua.substring( ua.indexOf('msie ') + 5 ) );
	}
	else if (this.isKonqueror) {
		this.versionMinor = parseFloat( ua.substring( ua.indexOf('konqueror/') + 10 ) );
	}
	else if (this.isSafari) {
		this.versionMinor = parseFloat( ua.substring( ua.lastIndexOf('safari/') + 7 ) );
	}
	else if (this.isOmniweb) {
		this.versionMinor = parseFloat( ua.substring( ua.lastIndexOf('omniweb/') + 8 ) );
	}
	else if (this.isOpera) {
		this.versionMinor = parseFloat( ua.substring( ua.indexOf('opera') + 6 ) );
	}
	else if (this.isIcab) {
		this.versionMinor = parseFloat( ua.substring( ua.indexOf('icab') + 5 ) );
	}

	this.versionMajor = parseInt(this.versionMinor, 10); 

	this.isDOM1 = (document.getElementById);
	this.isDOM2Event = (document.addEventListener && document.removeEventListener);

	this.mode = document.compatMode ? document.compatMode : 'BackCompat';

	this.isWin    = (ua.indexOf('win') != -1);
	this.isWin32  = (this.isWin && ( ua.indexOf('95') != -1 || ua.indexOf('98') != -1 || ua.indexOf('nt') != -1 || ua.indexOf('win32') != -1 || ua.indexOf('32bit') != -1 || ua.indexOf('xp') != -1) );
	this.isMac    = (ua.indexOf('mac') != -1);
	this.isUnix   = (ua.indexOf('unix') != -1 || ua.indexOf('sunos') != -1 || ua.indexOf('bsd') != -1 || ua.indexOf('x11') != -1);
	this.isLinux  = (ua.indexOf('linux') != -1);

	this.isNS4x = (this.isNS && this.versionMajor == 4);
	this.isNS40x = (this.isNS4x && this.versionMinor < 4.5);
	this.isNS47x = (this.isNS4x && this.versionMinor >= 4.7);
	this.isNS4up = (this.isNS && this.versionMinor >= 4);
	this.isNS6x = (this.isNS && this.versionMajor == 6);
	this.isNS6up = (this.isNS && this.versionMajor >= 6);
	this.isNS7x = (this.isNS && this.versionMajor == 7);
	this.isNS7up = (this.isNS && this.versionMajor >= 7);

	this.isIE4x = (this.isIE && this.versionMajor == 4);
	this.isIE4up = (this.isIE && this.versionMajor >= 4);
	this.isIE5x = (this.isIE && this.versionMajor == 5);
	this.isIE55 = (this.isIE && this.versionMinor == 5.5);
	this.isIE5up = (this.isIE && this.versionMajor >= 5);
	this.isIE6x = (this.isIE && this.versionMajor == 6);
	this.isIE6up = (this.isIE && this.versionMajor >= 6);
	this.isIE4xMac = (this.isIE4x && this.isMac);
}

var browser = new BrowserDetect();

function _WDDXRemotingClient_addRequestParameter(name, value)
{
	nameValueObject = {};
	nameValueObject.name = name;
	nameValueObject.value = value;
	this.requestNameValueArray[this.requestNameValueArray.length] = nameValueObject;
}


function _WDDXRemotingClient_sendRequest()
{
	for (var i=0; i < this.requestNameValueArray.length; i++)
	{
		this.requestURL += "&" + this.requestNameValueArray[i].name + "=" + this.requestNameValueArray[i].value;
	}
	this.requestURL = this.requestURL.replace(/&/, "?");
	
	var IFrameObj = document.getElementById(this.bufferID);
	if (!IFrameObj) {return;}

	if (browser.isIE)
	{
		IFrameObj.src = this.requestURL;
		return;
	}
	if (IFrameObj.contentDocument)
	{
		IFrameObj.contentDocument.location.replace(this.requestURL);
		return;
	}
	if (IFrameObj.contentWindow)
	{
		IFrameObj.contentWindow.document.location.replace(this.requestURL);
		return;
	}
	IFrameObj.src = this.requestURL;
	return;
}


function _WDDXRemotingClient_receiveResponse()
{
	this.callbackFunction(this.results);
}

function WDDXRemotingClient(requestURL, callbackFunction, bufferID)
{
	/* Initialization */
	if (typeof requestID == "undefined")
	{
		requestID = -1;
		remotingClientArray = [];
	}
	requestID++;
	remotingClientArray[requestID] = this;
	/* Members. */
	this.requestID = requestID;
	this.bufferID = bufferID;
	this.requestURL = requestURL;
	this.callbackFunction = callbackFunction;
	this.requestNameValueArray = [];
	this.results = new WddxRecordset();
	/* Methods. */
	this.addRequestParameter = _WDDXRemotingClient_addRequestParameter;
	this.sendRequest = _WDDXRemotingClient_sendRequest;
	this.receiveResponse = _WDDXRemotingClient_receiveResponse;
}

function _OnlineNowNodeParser_locateNodes()
{
	var CurrentNode = null;
	var i = 0;
	while ((CurrentNode = document.getElementById("UserDataNode" + i)) !== null)
	{
		NodeIndex = this.NodeArray.length;
		this.NodeArray[NodeIndex] = {};
		this.NodeArray[NodeIndex].NodeID = CurrentNode.id;
		var Attributes = CurrentNode.className.split(";");
		for (var AttributeIterator = 0; AttributeIterator < Attributes.length; AttributeIterator++)
		{
			var Name = Attributes[AttributeIterator].split("=")[0];
			var Value = Attributes[AttributeIterator].split("=")[1];
			if (Name !== "" && Value !== "") {eval("this.NodeArray[" + NodeIndex + "]." + Name + "=\"" + Value + "\";");}
		}			
		i++;
	}
}

function _OnlineNowNodeParser_run()
{
	this.locateNodes();	
	var UserIDList = "";
	if (this.NodeArray.length > 0)
	{
		for (var i=0; i < this.NodeArray.length; i++)
		{
			if (UserIDList.indexOf(":" + this.NodeArray[i].UserID + ":") == -1) {UserIDList += ":" + this.NodeArray[i].UserID + ":,";}
		}
		UserIDList = UserIDList.replace(/[:]/g, "").replace(/[,]$/gi, "");
		this.remotingClient.addRequestParameter("UserIDList", UserIDList);
		this.remotingClient.sendRequest();
	}
}

function _OnlineNowNodeParser_processResults(Results)
{
	if (Results.getRowCount() > 0)
	{
		var ThisUserID = "";
		for (var i = 0; i < Results.getRowCount(); i++)
		{
			var UserObject = {};
			UserObject.UserID = Results["userid"][i];
			UserObject.OnlineNow = Results["onlinenow"][i];
			ThisUserID = "" + Results["userid"][i];
			this.UserArray[ThisUserID] = UserObject;
		}
		for (i = 0; i < this.NodeArray.length; i++)
		{
			ThisUserID = "" + this.NodeArray[i].UserID;
			this.replaceUserNode(i, ThisUserID);
		}
	}
}

function _OnlineNowNodeParser_replaceUserNode(NodeIndex, UserIndex)
{
	var NodeObject = this.NodeArray[NodeIndex];
	var UserObject = this.UserArray[UserIndex];

	var ThisNode = document.getElementById(NodeObject.NodeID);
	if (ThisNode)
	{
		if (typeof UserObject != "object")
		{
			UserObject = {};
			UserObject.UserID = -1;
			UserObject.FirstName = "Unknown User";
			UserObject.ImageID = -1;
			UserObject.ImageType = "";
			UserObject.LastLogin = "";
			UserObject.OnlineNow = 0;
		}
		switch (NodeObject.DataPoint.toLowerCase())
		{
			case "onlinenow":
				var OnlineImageURL = ImageStore[0].url + "/site/images/clear.gif";
				if (UserObject.OnlineNow == 1)
				{
					try //atempt to load the localized image
					{ 
						OnlineImageURL = onlineNowImage.src;
					} catch(err) {
						OnlineImageURL = ImageStore[0].url + "/site/images/onlinenow.gif";
					}
				}
				ThisNode.innerHTML = "<IMG BORDER=\"0\" SRC=\"" + OnlineImageURL + "\" WIDTH=\"80\" HEIGHT=\"20\">";
				break;
		}
	}
}

function OnlineNowNodeParser(bufferID)
{
	/* Members. */
	this.UserArray = [];
	this.NodeArray = [];
	this.requestURL = onlineNowInfoURL;
	/* Methods. */
	this.run = _OnlineNowNodeParser_run;
	this.locateNodes = _OnlineNowNodeParser_locateNodes;
	this.replaceUserNode = _OnlineNowNodeParser_replaceUserNode;
	this.processResults = _OnlineNowNodeParser_processResults;
	/* Remoting Client Initialization. */
	var me = this;
	var CallbackFunction = function(Results) {me.processResults(Results);};
	this.remotingClient = new WDDXRemotingClient(this.requestURL, CallbackFunction, bufferID);
}

function adjustIFrameSize(iframeWindow) {
	if (iframeWindow.document.height) {
		var iframeElement = document.getElementById(iframeWindow.name);
		iframeElement.style.height = iframeWindow.document.height + 'px';
		//iframeElement.style.width = iframeWindow.document.width + 'px';
	} else if (document.all) {
		var iframeElement = document.all[iframeWindow.name];
		if (iframeWindow.document.compatMode && iframeWindow.document.compatMode != 'BackCompat') {
			iframeElement.style.height = iframeWindow.document.documentElement.scrollHeight + 5 + 'px';
			//iframeElement.style.width = iframeWindow.document.documentElement.scrollWidth + 5 + 'px';
		} else {
			iframeElement.style.height = iframeWindow.document.body.scrollHeight + 5 + 'px';
			//iframeElement.style.width = iframeWindow.document.body.scrollWidth + 5 + 'px';
		}
	}
}

function encode64(input) {
	var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	var output = "";
	var chr1, chr2, chr3, enc1, enc2, enc3, enc4 = "";
	var i = 0;
	do {
		chr1 = input.charCodeAt(i++);
		chr2 = input.charCodeAt(i++);
		chr3 = input.charCodeAt(i++);
		enc1 = chr1 >> 2;
		enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
		enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
		enc4 = chr3 & 63;
		if (isNaN(chr2)) enc3 = enc4 = 64;
		else if (isNaN(chr3)) enc4 = 64;
		output = output + keyStr.charAt(enc1) + keyStr.charAt(enc2) + keyStr.charAt(enc3) + keyStr.charAt(enc4);
		chr1 = chr2 = chr3 = "";
		enc1 = enc2 = enc3 = enc4 = "";
	} while (i < input.length);
	return output;
}

function decode64(input) {
	var keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	var output = "";
	var chr1, chr2, chr3, enc1, enc2, enc3, enc4 = "";
	var i = 0;
	input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
	do {
		enc1 = keyStr.indexOf(input.charAt(i++));
		enc2 = keyStr.indexOf(input.charAt(i++));
		enc3 = keyStr.indexOf(input.charAt(i++));
		enc4 = keyStr.indexOf(input.charAt(i++));
		chr1 = (enc1 << 2) | (enc2 >> 4);
		chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
		chr3 = ((enc3 & 3) << 6) | enc4;
		output = output + String.fromCharCode(chr1);
		if (enc3 != 64) output = output + String.fromCharCode(chr2);
		if (enc4 != 64) output = output + String.fromCharCode(chr3);
		chr1 = chr2 = chr3 = "";
		enc1 = enc2 = enc3 = enc4 = "";
	} while (i < input.length);
	return output;
}

function readCookie(name) {
	var nameEQ = name + "=";
	var ca = document.cookie.split(';');
	for (var i=0; i < ca.length; i++) {
		var c = ca[i].toString();
		while (c.charAt(0)==' ') c = c.substring(1,c.length);
		if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
	}
	return null;
}

function rsiCheck() {
	rsi_account = '05C63E675C06B32B95D2EB5B05584CF4';
	rsi_site = 'D0A4162C9E7B7CD278E3DFBA81C09652';

	document.write('<sc'+'ript');
	document.write(' type="text/javascript"');
	document.write(' language="JavaScript"');
	document.write(' src="http://ads.revsci.net/adserver/rsi_check.js');
	document.write('">');
	document.write('</sc'+'ript>');
}

function rsiWriteCookie() {
	var expirationDate = new Date();
	var derdbBase64 = readCookie('DERDB');
	if (derdbBase64 != null) {
		derdbPlain = decode64(unescape(derdbBase64));
		if (derdbPlain.indexOf('rsi_want=') != -1) {
			newPair = 'rsi_want=' + rsi_want;
			regEx = /rsi_want=\d*/gi;
			derdbPlain = derdbPlain.replace(regEx, newPair);
		} else {
			derdbPlain = derdbPlain + '&rsi_want=' + rsi_want;
		}
		expirationDate.setYear(expirationDate.getFullYear()+1);
		document.cookie = "DERDB=" + encode64(derdbPlain) + "; path=/; domain=" + document.domain + "; expires=" + expirationDate.toGMTString();
	}
}


// begin MySpace header code

	var rows = new Array()
	rows[0]="row0";
	rows[1]="row1";
	rows[2]="row2";

	var searchItems= new Array;	
	searchItems[0]="tweb";
	searchItems[1]="tms";
	searchItems[2]="tpeople";
	searchItems[3]="tmusic";
	searchItems[4]="tblog";
	searchItems[5]="tvid";
	searchItems[6]="tfilm";
	searchItems[7]="tbooks";
	searchItems[8]="tclass";
	searchItems[9]="tcomedy";
	searchItems[10]="tevents";
	searchItems[11]="tgroups";
	
	//searchLabels array is localized and embedded in the page
	
	function csrch()
	{
		var fs=document.srch.q;
		fs.value=fs.value.replace(/^([ \t])+/gi,"").replace(/([ \t])+$/gi,"");
		if (fs.value.length < 2){
			alert("This search term is too short or blank.");
			fs.focus();
			return false;
		}
		return true;
	}
	
	function getCurrentSearch()
	{	    
	    var item;
		for (i=0;i<searchItems.length; i++)
		{		 		    
		    item = document.getElementById(searchItems[i]);		    
		    if (item != null && item.className=="active")   
			    return i;			    			    
		}
	}
	
	function setSearchTarget(p_t)
	{
	    var item;
		var menuIndex;		
		
		//turn off all selections
		for (x=0; x<searchItems.length-1; x++)
	    {		    
		    item = document.getElementById(searchItems[x]);		  		    
		    if (item != null)
			    item.className="inactive";
		} 								    
		item = document.getElementById(p_t);		
		if (item != null)
		    document.getElementById(p_t).className="active";
		
		var currSearch = getCurrentSearch();						
		if (currSearch != undefined)
			document.srch.submitBtn.value=searchLabels[currSearch];

		document.srch.t.value=p_t;
		return true;
	}
	
	
	function getCurrentRow()
	{
		for (i=0;i<rows.length; i++)
		{
			if (document.getElementById(rows[i]).className=="show") return i;
		}
	}
	
	function showRow(row)
	{
	    var item;
		for (i=0;i<rows.length; i++)
		{		    
		    item = document.getElementById(rows[i]);		  		    
		    if (item != null)
			    item.className="hide";
		}
		
		document.getElementById(rows[row]).className="show";		
		//turn on the first item in each row
				
		if (getCurrentRow()==0) setSearchTarget("tweb");
		if (getCurrentRow()==1) setSearchTarget("tfilm");
		if (getCurrentRow()==2) setSearchTarget("tgroups");
	}
	
	function displayPrevRow()
	{
		cr=getCurrentRow();
		if (cr == 0) pr=rows.length-1;
		else pr=(cr-1);
		showRow(pr);
	}
	
	function displayNextRow()
	{
		cr=getCurrentRow();
		if (cr == rows.length-1) pr=0;
		else pr=(cr+1);
		showRow(pr);
	}
function readCookie(name) {
	var nameEQ = name + "=";
	var ca = document.cookie.split(';');
	for(var i=0;i < ca.length;i++) {
		var c = ca[i];
		while (c.charAt(0)==' ') {c = c.substring(1,c.length);}
		if (c.indexOf(nameEQ) === 0) {return c.substring(nameEQ.length,c.length);}
	}
	return "Unknown";
}
function readFuse(path) {
	var re = new RegExp("fuseaction=([^&]*)");
	var m = re.exec(document.location.href);
  if (m === null) {
  	var n = document.location.href;
	var nm = n.split("/");
	var mn = nm[Math.max(nm.length-1,0)].split(".");
	if (mn[0].length > 0) { return mn[0];
	} else { return nm[0].split(".")[0];
	}
  } else { return m[1].split('.').join("/");
  }
}
// end MySpace header code

// start MySpace IM code
function getIMwin(h,w) {
	var getIMurl = "http://www.myspace.com/Modules/IM/Pages/GetIM.aspx";
	var getIMh = h;
	var getIMw = w;
	var getIMleft = (screen.availwidth-w)/2;
	var getIMtop =(screen.availheight-h)/2;
	window.open(getIMurl,null,'height='+getIMh+',width='+getIMw+',left='+getIMleft+',top='+getIMtop+',status=no,toolbar=no,menubar=no,location=no');
}

function gotIM(){
	try
		 {
		if (document.cookie) 
				{ 
			index = document.cookie.indexOf('imyspaceim'); 
			if (index != -1) 
			{
				return true;
					 } 
				}
		 }
		 catch(err)
		 {
		 }
				
		 try
		 {
		var objMySpaceIMX;
				objMySpaceIMX = new ActiveXObject("MySpaceIMX.MySpaceIMPlugin.1");
				return true;
		 }
		 catch(err)            
		 {
		 }
						
	try
	{
		if (navigator.mimeTypes && navigator.mimeTypes.length > 0)
		{
			var plugin = navigator.mimeTypes["application/myspaceim"];
			if ( plugin ) 
			{
				return true;
			}
		}        
	}
	catch(err)         
	{
	}
	return false             
}

function IsMySpaceIMInstalled(){
	var fid = get_url();
	IsMySpaceIMInstalledById(fid);
}

function IsMySpaceIMInstalledById(fid){
	if(gotIM()) {
		var thisUrl = 'myim:sendIM?uID=0&cID='+fid;
		window.location.href=thisUrl;
	} else {
		getIMwin(475,600);
	}
}
// end MySpace IM code

// Hover Tool Tip 		
// declare main ToolTip variable
var msToolTip = 
{
		// ToolTip properties
		xOffset      : 0,
		yOffset      : 0,
		ID           : "msToolTip",
		arrowID      : "msToolTipArrow",
		showDelay    : 150,
		hideDelay    : 450,
		created      : false,
		timerMsgDiv  : null,
		timerArrowDiv: null,
		msgDiv       : null,
		arrowShow    : 0,
		arrowDiv     : null,
		arrowImgUp   : "http://x.myspace.com/images/arrowUp.jpg", 
		arrowImgDown : "http://x.myspace.com/images/arrowDown.jpg",
		arrowImgLeft : "http://x.myspace.com/images/arrowLeft.jpg", 
		arrowImgRight: "http://x.myspace.com/images/arrowRight.jpg",
		arrowDir     : 0,  // 0 - Up, 1- Down, 2- Left, 3 - Right

		// define Dimension 
	 getLeft : function() 
		{
			this.left = 0;
			if (typeof window.pageXOffset == "number") this.left = window.pageXOffset;
			else if (document.documentElement && document.documentElement.scrollLeft)
							 this.left = document.documentElement.scrollLeft;
			else if (document.body && document.body.scrollLeft) 
							 this.left = document.body.scrollLeft; 
			else if (window.scrollX) this.left = window.scrollX;
		},
	
		getTop : function() 
		{
			this.top = 0;    
			if (typeof window.pageYOffset == "number") this.top = window.pageYOffset;
			else if (document.documentElement && document.documentElement.scrollTop)
							 this.top = document.documentElement.scrollTop;
			else if (document.body && document.body.scrollTop) 
							 this.top = document.body.scrollTop; 
			else if (window.scrollY) this.top = window.scrollY;
		},

		getClientWidth : function() 
		{
			this.width = 0;
			if (window.innerWidth) this.width = window.innerWidth - 20;
			else if (document.documentElement && document.documentElement.clientWidth) 
							 this.width = document.documentElement.clientWidth;
			else if (document.body && document.body.clientWidth) 
							 this.width = document.body.clientWidth;
		},

		getClientHeight : function() 
		{
			this.height = 0;
			if (window.innerHeight) this.height = window.innerHeight - 20;
			else if (document.documentElement && document.documentElement.clientHeight) 
							 this.height = document.documentElement.clientHeight;
			else if (document.body && document.body.clientHeight) 
							 this.height = document.body.clientHeight;
		},
		// declare setup Event 
	
		setUpExtraEvents : function(e) 
		{ 
			e     = e ? e : window.event;
			e.tgt = e.srcElement ? e.srcElement : e.target;
			
			if (!e.stopPropagation) 
					 e.stopPropagation = function() { if (window.event) window.event.cancelBubble = true; }
			if (!e.preventDefault)  
					 e.preventDefault  = function() { return false; }
				 
			return e;
		},
	
		// create div's object that are containers of HTML msgs
		createDivElement : function(ID)
		{
			if (document.createElement && document.body && typeof document.body.appendChild != "undefined")
			{
				 if(!document.getElementById(ID))
				 {
						var e=document.createElement("div");
						e.id=ID; 
						document.body.appendChild(e);
				 }
				 this.created=true;
			}
		},
		// setup timers for the visibility of the div's objects
		setupTimerMsgDiv : function(vis,delay)
		{
			if (this.timerMsgDiv) 
			{
					clearTimeout(this.timerMsgDiv);
					this.timerMsgDiv=0;
			}

			this.timerMsgDiv = setTimeout ("msToolTip.setVisibility('"+this.ID+"', '" + vis + "')",delay);
		},
		setupTimerArrowDiv : function(vis,delay)
		{
			if (this.timerArrowDiv) 
			{
					clearTimeout(this.timerArrowDiv);
					this.timerArrowDiv=0;
			}

			this.timerArrowDiv = setTimeout ("msToolTip.setVisibility('"+this.arrowID+"', '" + vis + "')",delay);
		},
		// init ToolTip	
		initToolTip : function()
		{
			this.createDivElement(this.ID); 
			if (this.arrowShow) 
			{
					this.arrowID = this.ID + "Arrow";    
					this.createDivElement(this.arrowID); 
			}    
		},
		// show ToolTip
		showToolTip : function(e,msg)
		{
			this.setupTimerMsgDiv  ('visible',this.showDelay);
			this.setupTimerArrowDiv('visible',this.showDelay);

			this.msgDiv=document.getElementById(this.ID);
			this.arrowDiv=document.getElementById(this.arrowID);

			this.getClientWidth(); 
			this.getClientHeight();
			this.getLeft(); 
			this.getTop();

			this.writeToolTipHTMLMsg(this.msgDiv,msg);
			this.positionToolTip(e);
			if (this.arrowShow) {
					this.writeToolTipHTMLMsg(this.arrowDiv,
								"<img src='" + 
										(this.arrowDir == 0 ? this.arrowImgUp:
												(this.arrowDir == 1 ? this.arrowImgDown:	
														(this.arrowDir == 2 ? this.arrowImgLeft:	
																this.arrowImgRight)))  + 
										"'>");
			}    
			this.positionToolTip(e);
		},
		// hide ToolTip
		hideToolTip : function()
		{
			this.setupTimerMsgDiv  ('hidden',this.hideDelay);
			this.setupTimerArrowDiv('hidden',this.hideDelay);

			this.msgDiv=null;
			this.arrowDiv=null;
		},
		// write HTML message in innerHTML of the div
		writeToolTipHTMLMsg : function(msgDiv, msg)
		{
			if (msgDiv != null && typeof msgDiv.innerHTML != "undefined") 
					msgDiv.innerHTML=msg;
		},
		// set position of msgs where will be on the screen
		positionToolTip : function(e)
		{
			var msgDiv   = this.msgDiv;
			var arrowDiv = this.arrowDiv;
			var xOffset  = this.xOffset;
			var yOffset  = this.yOffset;
			var xMsg   = 0, yMsg   = 0;
			var xArrow = 0, yArrow = 0;

			if(msgDiv && msgDiv.style) 
			{ 
				 xMsg   = (typeof e.clientX != "undefined" ? e.clientX:e.pageX) + this.left; 
				 yMsg   = (typeof e.clientY != "undefined" ? e.clientY:e.pageY) + this.top; 
				 xArrow =  xMsg; yArrow = yMsg;

				 xMsg = ( xMsg + this.msgDiv.offsetWidth + this.xOffset > this.width  + this.left ?
														 xMsg - this.msgDiv.offsetWidth - this.xOffset:
														 xMsg + xOffset);

				 if (yMsg + this.msgDiv.offsetHeight + this.yOffset > this.height + this.top )
				 {
						 yMsg = yMsg - this.msgDiv.offsetHeight - this.yOffset;
						 if ( yMsg < this.top) yMsg = this.height + this.top - this.msgDiv.offsetHeight;
				 }
				 else 
				 {
						 yMsg = yMsg + yOffset;
				 }   
				 if (xMsg < 0) xMsg=0; 
				 if (yMsg < 0) yMsg=0;
				 msgDiv.style.left = xMsg + "px" ;
				 msgDiv.style.top  = yMsg + "px" ;

				 if(arrowDiv && arrowDiv.style) 
				 {
						if ((yMsg <= yArrow && yArrow+2 < yMsg + this.msgDiv.offsetHeight &&
								 xMsg <= xArrow && xArrow+2 < xMsg + this.msgDiv.offsetWidth) ||
								 xArrow - 2 < xMsg || 
								 xArrow > xMsg + this.msgDiv.offsetWidth+ this.arrowDiv.offsetWidth + 2) 
						{
								this.setupTimerArrowDiv('hidden',this.hideDelay);
						} 
						else 
						{
								if (yArrow <= yMsg) this.arrowDir = 0;
								else if (yArrow > yMsg && yArrow <= yMsg + this.msgDiv.offsetHeight) 
								{
										 if (xArrow <= xMsg) this.arrowDir = 2;
										 else if (xArrow > xMsg)  this.arrowDir = 3;
								} 
								else this.arrowDir = 1;

								this.arrowDiv.style.left =  
										(this.arrowDir == 2 ? xMsg - this.arrowDiv.offsetWidth + 1:
												(this.arrowDir == 3 ? xMsg + this.msgDiv.offsetWidth - 1:
														xArrow)) + "px"; 
								this.arrowDiv.style.top  = 
										((this.arrowDir == 0 ? yMsg - this.arrowDiv.offsetHeight + 2:
												(this.arrowDir == 1 ? yMsg + this.msgDiv.offsetHeight:
														yArrow)) - 1) + "px"; 
						}
				 } 
			}

		},
		// set visibility property of div object 
		setVisibility : function(id,vis)
		{
			var el = document.getElementById(id);
			if (el) el.style.visibility=vis;
		},
		// check the mouse position where is it , Is it still on the object
		divMouseOut : function(e) 
		{
			e = msToolTip.setUpExtraEvents(e);
			var toElm = e.relatedTarget != null ? e.relatedTarget : e.toElement;
			if ( this != toElm && !msToolTip.containedBy(toElm, this) ) 
					 msToolTip.hideToolTip();
		},
		// returns true of oNd is contained by oCnt (container)
		containedBy : function (oNd, oCnt) 
		{
			if (!oNd) 
					 return false; 
			for(oNd = oNd.parentNode ; oNd != null; oNd = oNd.parentNode ) 
					if (oNd == oCnt) 
							return true;
			return false;	
		},
		// Clear time that is responsable for HoverTip option
		clearTimerHover : function() 
		{
			if (msToolTip.tmrIdHover) 
			{ 
					clearTimeout(msToolTip.tmrIdHover); 
					msToolTip.tmrIdHover = 0; 
			}
		},
		// Detach event onmouse out and over
		detachToolTip  : function() 
		{
			if (this.msgDiv != null) 
			{
					this.msgDiv.onmouseout = null;
					this.msgDiv.onmouseover = null; 
					this.msgDiv = null;
			}
			if (this.arrowDiv != null) 
					this.arrowDiv = null;
		}
};
// public function for different behavior
// Hover Tip behavior
var msPublicToolTip = {
		initMsHoverTip  : function () 
		{
				msToolTip.tmrIdHover = 0;
				registerEvent("window", "unload", "msToolTip.detachToolTip", true);
				msToolTip.initToolTip();
		},

		showMsHoverTip : function  (e, msg) 
		{
			 if ( typeof msToolTip == "undefined" || !msToolTip.created )
						return;

			 msToolTip.clearTimerHover();
			 msToolTip.showToolTip(e, msg);

			 if ( msToolTip.msgDiv != null && msToolTip.msgDiv.onmouseout == null ) {
						msToolTip.msgDiv.onmouseout  = msToolTip.divMouseOut;
						msToolTip.msgDiv.onmouseover = msToolTip.clearTimerHover;
			 }
		},

		hideMsHoverTip : function () 
		{
			 if ( typeof msToolTip == "undefined" || !msToolTip.created ) 
						return;

			 msToolTip.tmrIdHover = setTimeout("msToolTip.hideToolTip()", 200);
		}
};
