/* START Let's build the AdHelper Object */
var oas_helper = {
	adCount: 1,
	keys: [], // url name/value pairs arrays
	values: []
}

oas_helper.getID = function(name) {
	var v= this.QueryString(name);
	if (v != null)
		return v;
	else
		return 0;
}
oas_helper.getVar = function(name) {
	var v = eval("typeof("+name+")");
	if(v == "undefined")
		return null;
	return eval(name);
}
oas_helper.getVarOrId = function(varName,queryName) {
	var v = this.getVar(varName);
	if (v == null)
		return null;
	else if (v != 0)
		return v;
	else
		return this.getID(queryName);
}

oas_helper.getDownloadCategory = function () {
	var dcat = "";
	if (this.QueryString('cat') != null)
		dcat =  this.QueryString('cat');
	
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

oas_helper.getURL = function() { //el=str, case_sensitive=bool
	var urls = document.URL;
	urls = urls.replace( /'/g, "" ); // stripTicks
	// look for friend, channel, or group id
	var re = new RegExp( "\\?[\\w\\W]*(friendid|channelid|groupid)=([^\\&\\?#]*)", "i" );
	var arr = re.exec(urls);
	if(arr && arr.length>1){	
		return arr[2];
	}else{ 
		// try vanity url
		var expr = /\/([\w]*)$/i;
		arr = expr.exec(urls);
		if(arr && arr.length>1)
			return arr[1].toLowerCase();
		else
			return '';
	}
} // oas_helper.getURL

oas_helper.random = function(){
	var randomm = 714025;
	var randoma = 4096;
	var randomc = 150889;
	randomseed = (randomseed * randoma + randomc) % randomm;
	return randomseed / randomm;
} //  random

oas_helper.ParseQueryString = function() {
	var query = window.location.search.substring(1);
	var pairs = query.split("&");
	for (var i = 0; i < pairs.length; i++) {
		var pos = pairs[i].indexOf('=');
		if (pos >= 0) {
			var argname = pairs[i].substring(0,pos);
			var value = pairs[i].substring(pos+1);
			this.keys[this.keys.length] = argname;
			this.values[this.values.length] = value;
		}
	}
} // ParseQueryString

oas_helper.QueryString = function(key) {
	if (this.keys.length < 1) this.ParseQueryString();
	var value = null;
	for (var i = 0; i < this.keys.length; i++) {
		if (this.keys[i] == key) {
			value = escape(this.values[i].toLowerCase());
			break;
		}
	}
	return value;
} // QueryString

oas_helper.readCookie = function(name) {
	var nameEQ = name + "=";
	var ca = document.cookie.split(';');
	for(var i=0;i < ca.length;i++) {
		var c = ca[i];
		while (c.charAt(0)==' ') {c = c.substring(1,c.length);}
		if (c.indexOf(nameEQ) === 0) {return c.substring(nameEQ.length,c.length);}
	}
	return "Unknown";
} // readCookie

/* End AdHelper */

// todo: what this? var ad_randomseed = Date.parse(new Date()); 
oas_helper.randomNumber = oas_helper.random() + "";


function sdc_wrapper()
{
    var argv    = sdc_wrapper.arguments;
    var tokenID = argv[0];
    var page    = argv[1];
    var pos     = argv[2].toLowerCase();
   
    var subd    = 'deLB';
     
    var adWidth  = 728;
    var adHeight = 90;

    var frameURL = "";
    var friendID = 0;     

    var rand = oas_helper.randomNumber.substring(2,11);

    re_ex = /,/;

    if(re_ex.test(page)){
	site_arr = page.split(",");
	page = site_arr[1];
    }
     
    switch (pos)
    {
    case 'x08':
	 friendID = oas_helper.getURL();
	 adWidth=430;
	 adHeight=600;
         subd = 'deHP';
	 pos = 'halfpage&params.styles=halfpage';
  	 break;
    case 'x14':
	 adWidth=300;
	 adHeight=250;
	 pos = 'mrec';
         subd = 'deMR';
	 friendID = oas_helper.getURL();
	 break;
    case 'x15':
	 friendID = oas_helper.getURL();
	 adWidth=160;
	 adHeight=600;
         subd = 'deSK';
	 pos = 'skyscraper';
	 break;
    case 'east':
	 friendID = oas_helper.getURL();
	 adWidth=300;
	 adHeight=100;
	 pos = 'east';
	 subd = 'deEB';
	 break;
    default:
         adWidth  = 728;
         adHeight = 90;
         subd    = 'deLB';
         pos     ='leaderboard&params.styles=leaderboard';
         friendID = oas_helper.getURL();
         break;
    }
 
    if (friendID && friendID != '')
	friendID = "&fid="+friendID;

    var ctr = document.getElementById(tokenID);
    if (ctr == null) return;
     
   try
   {
		//parse the cookie for JP
		var cultureCookie = oas_helper.readCookie('MSCulture');
		var cookieKey = '&IPCulture=';
		var keyindex = cultureCookie.indexOf(cookieKey);
		var culture = cultureCookie.substring(keyindex + cookieKey.length,cultureCookie.length);
		if (culture.indexOf('&') >= 0) 
			culture = culture.substring(0, culture.indexOf('&'));
		if (culture.indexOf('ja-JP') >= 0) 
			subd = 'adjp01';
   }
   catch(e)
   {}

   if (subd == 'adjp01')
   {
      ad_wrapper(argv[0], argv[1], argv[2]);
   }
   else
   {
   frameURL = "http://"+subd+".opt.fimserve.com/adopt/?l="+page+"&pos=" + pos + "&r=h&rnd="+rand + friendID;

   ctr.innerHTML = "<IFRAME width=\""+adWidth+"\" height=\""+adHeight+"\" style=\"position:relative;z-index:10000\" MARGINWIDTH=0 MARGINHEIGHT=0 HSPACE=0 VSPACE=0 FRAMEBORDER=0 SCROLLING=no src='"+frameURL+"'></iframe>";
   }
}

function ad_wrapper()
{
	var argv = ad_wrapper.arguments;
	var tokenID = argv[0];
	var page = argv[1];
	var pos = argv[2].toLowerCase();

	var ctr = document.getElementById(tokenID);
	if (ctr == null) return;

	var friendID = 0;
	var AdTopicID = oas_helper.getVar( "ad_Topic_ID" );
	var videoID = oas_helper.getID('videoid');
	var videoChannel = oas_helper.getVarOrId( "ad_Video_CID", "channelid" );
	var videoUserCat = oas_helper.getVarOrId( "ad_Video_RID", "rid" );
	var downloadCat = oas_helper.getDownloadCategory();
	var groupCatID = oas_helper.getVar( "ad_Group_CID" );

    var tvcatmaster_id = oas_helper.getVar( "tvcatmasterid" );
    var tvvideo_id = oas_helper.getVar( "videoid" );
    var tvcat_id = oas_helper.getVar( "tvcat" );
    var tvchan_id = oas_helper.getVar( "tvchanid" );
    
    if(tvcatmaster_id == 1 || tvcatmaster_id == 2)tvcatmaster_id=0;
    if(tvcatmaster_id == 7)tvcatmaster_id=300;
    if(tvcatmaster_id == 9)tvcatmaster_id=100;
    if(tvcatmaster_id == 15)tvcatmaster_id=200;
    if(tvcatmaster_id == 8)tvcatmaster_id=1001;

	var adWidth=0;
	var adHeight=0;
	var isSDCPage = false; 

	subd = 'deSB';

	re_ex = /,/;

	temp_flag = 0;
	if(re_ex.test(page)){
		site_arr = page.split(",");
		page = site_arr[1];
	}

	switch (pos)
	{
		case 'frame1':
			friendID = oas_helper.getURL();
			adWidth=728;
			adHeight=90;
			pos = 'leaderboard&params.styles=leaderboard';
			subd = 'deLB';
			break;
		case 'top':
			friendID = oas_helper.getURL();
			adWidth=468;
			adHeight=60;
			pos = 'banner';
			subd = 'deBR';
			break;
		case 'x08':
			friendID = oas_helper.getURL();
			adWidth=430;
			adHeight=600;
			pos = 'halfpage&params.styles=halfpage';
			subd = 'deHP';
			break;
		case 'x14':
			adWidth=300;
			adHeight=250;
			pos = 'mrec';
			subd = 'deMR';
			friendID = oas_helper.getURL();
			break;
		case 'x15':
			friendID = oas_helper.getURL();
			adWidth=160;
			adHeight=600;
			pos = 'skyscraper';
			subd = 'deSK';
			break;
		case 'x54': //feature profile
			adWidth=225;
			adHeight=170;
			pos = 'profile';
			subd = 'deFP';
			break;
		case 'x54-1': //feature profile small
			adWidth=200;
			adHeight=170;
			pos = 'profile';
			subd = 'uhpfp';
			break;
		case 'x55': //feature group
			adWidth=640;
			adHeight=280;
			pos = 'group';
			subd = 'deFG';
			break;
		case 'x56':
			adWidth=460;
			adHeight=140;
			break;
		case 'x69': // This was added for the anchor man inbox add.
			adWidth=628;
			adHeight=288;
			break;
		case 'x77':
			adWidth=1;
			adHeight=1;
			pos = '1x1';
			subd = 'deSB';
			break;
		case 'x78': // login page
			adWidth=750;
			adHeight=600;
			pos = 'interstitial&params.styles=halfpage';
			subd = 'deSB';
			break;
		case 'x85':
			adWidth=300;
			adHeight=300;
			break;
		case 'x86':
			adWidth=465;
			adHeight=360;
			break;
		case 'x87':
			adWidth=463;
			adHeight=400;
			break;
		case 'x88':
			adWidth=440;
			adHeight=140;
			pos = 'featuredband';
			subd = 'deFB';
			break;
		case 'fspecial':
			adWidth=440;
			adHeight=140;
			pos = 'fspecial';
			subd = 'deSB';
			break;
		case 'featblg':
			adWidth=500;
			adHeight=100;
			pos = 'featblg';
			subd = 'deSB';
			break;
		case 'uhpfp': //uhp feature profile
			adWidth=200;
			adHeight=170;
			pos = 'uhpfp';
			subd = 'deFP';
			break;
		case 'west':
			adWidth=440;
			adHeight=160;
			pos = 'west';
			subd = 'deWB';
			break;
		case 'east':
			friendID = oas_helper.getURL();
			adWidth=300;
			adHeight=100;
			pos = 'east';
			subd = 'deEB';
			break;
		case 'featvid':
			adWidth=300;
			adHeight=170;
			pos = 'featvid';
			subd = 'deFV';
			break;
		case 'movpro':
			adWidth=300;
			adHeight=250;
			pos = 'movpro';
			subd = 'deMP';
			break;
		case 'fmovl':
			adWidth=229;
			adHeight=216;
			pos = 'fmovl';
			subd = 'deFML';
			break;
		case 'fmovr':
			adWidth=229;
			adHeight=216;
			pos = 'fmovr';
			subd = 'deFMR';
			break;
		case 'vrec':
			adWidth=240;
			adHeight=400;
			pos = 'vrec';
			subd = 'deVR';
			break;
		case 'leaderboard2':
			friendID = oas_helper.getURL();
			adWidth=728;
			adHeight=90;
			pos = 'leaderboard2&params.styles=leaderboard';
			subd = 'deLB2';
			break;
		default:
			adWidth=468;
			adHeight=60;
			pos = 'test';
			break;
	}
	
	try
	{
		//parse the cookie for JP
		var cultureCookie = oas_helper.readCookie('MSCulture');
		var cookieKey = '&IPCulture=';
		var keyindex = cultureCookie.indexOf(cookieKey);
		var culture = cultureCookie.substring(keyindex + cookieKey.length,cultureCookie.length);
		if (culture.indexOf('&') >= 0) 
			culture = culture.substring(0, culture.indexOf('&'));
		if (culture.indexOf('ja-JP') >= 0) 
			subd = 'adjp01';
	}
	catch(e)
	{}
	
	var rand = oas_helper.randomNumber.substring(2,11);
	var testmode = false;
	var special = '';
	
	if(friendID)
		friendID = "&friendid="+friendID;
	
	if(AdTopicID)
		AdTopicID = "&category="+AdTopicID;
	else
		AdTopicID = "";
	
	if(videoID)
		videoID = "&videoID="+videoID;
	else
		videoID = "";
	
	if(videoUserCat)
		videoUserCat = "&rid="+videoUserCat;
	else
		{
		if(videoID!="")videoUserCat = "&rid=0"; else videoUserCat = "";
		}
	
	if(videoChannel)
		videoChannel = "&channelid="+videoChannel;
	else
		videoChannel = "";
	
	if(downloadCat)
		downloadCat = "&downcat="+downloadCat;
	else
		downloadCat = "";
		
	if(tvcatmaster_id==null)tvcatmaster_id = "";
	else
		tvcatmaster_id = "&tvmastercategory="+tvcatmaster_id;
		 
    if(tvvideo_id)
		tvvideo_id  = "&tvvideoid="+tvvideo_id;
	else
		tvvideo_id = "";
		 
	if(tvcat_id)
		tvcat_id = "&tvcategoryid="+tvcat_id;
	else
		tvcat_id = "";
		 
	if(tvchan_id)
		tvchan_id = "&tvchannelid="+tvchan_id;
	else
		tvchan_id = "";
		
		
	
	if (oas_helper.QueryString('schoolID') != null)
		var SchoolID = oas_helper.QueryString('schoolID');
	else
		var SchoolID = 0;
	
	if (oas_helper.QueryString('special') != null)
	{
		testmode = true;
		special = oas_helper.QueryString('special');
	}
	
	var runBandGenreAd=false;
	if(document.getElementById("bandgenre1")){
		runBandGenreAd= (document.getElementById("bandgenre1").parentNode.childNodes.length==3);
	}
	
	isSDCPage = (page == '11002001' ||
                     page == '11013008' || 
                     page == '11011019' ||
                     page == '11013004' );
	
	var frameURL = "";
	if (isSDCPage && subd != 'adjp01')
	{
		adWidth=728;
		adHeight=90;
		pos = 'leaderboard';
		subd = 'deLB';
		
		frameURL = "http://"+subd+".opt.fimserve.com/adopt/?l="+page+"&pos=" + pos + "&r=h&rnd="+rand;
	} 
	else
	{
		if(runBandGenreAd)
		{
			if(testmode)
				frameURL = "http://detst.myspace.com/html.ng/site=myspace&position="+pos+"&page="+page+"&rand="+rand+friendID+AdTopicID+"&acnt="+oas_helper.adCount+"&schoolpage="+SchoolID+"&bandgenre="+document.forms[0].bandgenre1.value+"&bandgenre="+document.forms[0].bandgenre2.value+"&bandgenre="+document.forms[0].bandgenre3.value+"&special="+special+videoID+videoUserCat+videoChannel+downloadCat+tvcatmaster_id+tvvideo_id+tvcat_id+tvchan_id;
			else
				frameURL = "http://"+subd+".myspace.com/html.ng/site=myspace&position="+pos+"&page="+page+"&rand="+rand+friendID+AdTopicID+"&acnt="+oas_helper.adCount+"&schoolpage="+SchoolID+"&bandgenre="+document.forms[0].bandgenre1.value+"&bandgenre="+document.forms[0].bandgenre2.value+"&bandgenre="+document.forms[0].bandgenre3.value+videoID+videoUserCat+videoChannel+downloadCat+tvcatmaster_id+tvvideo_id+tvcat_id+tvchan_id;
		}
		else
		{
			if (testmode)
				frameURL = "http://detst.myspace.com/html.ng/site=myspace&position="+pos+"&page="+page+"&rand="+rand+friendID+AdTopicID+"&acnt="+oas_helper.adCount+"&schoolpage="+SchoolID+"&special="+special+videoID+videoUserCat+videoChannel+downloadCat+tvcatmaster_id+tvvideo_id+tvcat_id+tvchan_id;
			else 
				frameURL = "http://"+subd+".myspace.com/html.ng/site=myspace&position="+pos+"&page="+page+"&rand="+rand+friendID+AdTopicID+"&acnt="+oas_helper.adCount+"&schoolpage="+SchoolID+videoID+videoUserCat+videoChannel+downloadCat+tvcatmaster_id+tvvideo_id+tvcat_id+tvchan_id;
		}
	}
	ctr.innerHTML = "<IFRAME width=\""+adWidth+"\" height=\""+adHeight+"\" style=\"position:relative;z-index:10000\" MARGINWIDTH=0 MARGINHEIGHT=0 HSPACE=0 VSPACE=0 FRAMEBORDER=0 SCROLLING=no src='"+frameURL+"'></iframe>";
	oas_helper.adCount++;
}