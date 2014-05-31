var colorfulTabs =
	{
	tabColors: ['rgb(147, 174, 229)','rgb(255, 218, 117)','rgb(188, 204, 157)','rgb(239, 157, 159)','rgb(186, 167, 225)','rgb(155, 191, 180)','rgb(247, 180, 130)','rgb(216, 171, 192)','rgb(147, 229, 174)','rgb(255, 117, 218)','rgb(188, 157, 204)','rgb(239, 159, 157)','rgb(186, 225, 167)','rgb(155, 180, 191)','rgb(247, 130, 180)','rgb(216, 192, 171)','rgb(174, 147, 229)','rgb(218, 255, 117)','rgb(204, 188, 157)','rgb(157, 239, 159)','rgb(167, 186, 225)','rgb(191, 155, 180)','rgb(180, 247, 130)','rgb(171, 216, 192)','rgb(229, 174, 147)','rgb(117, 218, 255)','rgb(157, 204, 188)','rgb(159, 157, 239)','rgb(225, 167, 186)','rgb(180, 191, 155)','rgb(130, 180, 247)','rgb(192, 171, 216)'],
	newVersion:null,//version of the version being installed
	ctVersion:null,//version of the currently installed version
	fadedeg:null,//variable 'fadedeg' tracks fade degree starting 0 to 9 translates to mozopacity 0 to 1 **some explaination mising**.
	scheme:null,//the coloring scheme viz. fixed pallette, random, domain based, manual only - 0,1,2,3 res.
	txtshadow:null,//text glow
	tablabelblink:null,//tab label blink on hover
	currenttab:null,	//fixed color for selected tab?
	currenttabclr:null,
	clr:0,//tracks the tab color when using fixed pallette
	isSeamonkey:'',
	isFlock:'',
	clrAllTabsPopPref:'',
	isMac:'',
	isAustralis:'',
	clrSession:window.navigator.userAgent.toLowerCase().indexOf('seamonkey')>=0?Components.classes["@mozilla.org/suite/sessionstore;1"].getService(Components.interfaces.nsISessionStore):Components.classes["@mozilla.org/browser/sessionstore;1"].getService(Components.interfaces.nsISessionStore),
	adv:null,//advanced pref enabled?1:0;
	satmax:null,//max saturation
	satmin:null,//min saturation
	lummax:null,//max luminance
	lummin:null,//min luminance
	sat:null,//saturation of domain based coloring
	lum:null,//luminance of domain based coloring
	txtreverse:null,//reversing of the tabs' text-color
	enabledomain:null,//enable domain presets?1:0
	dpref:null,//domain-color combo prefs
	ctdebug:0,//enable message dump  to console?1:0
	colorunmatcheddomain:null,//color unmatched domains?1:0 - currently unused
	aggressive:'',
	standout:'',
	minify:false,
	dispStack:'',
	uncoloredbgclr:'',
	tabtextclr:'',
	clrtabsInit: function()
		{
		
		colorfulTabs.cl("useragent="+window.navigator.userAgent.toLowerCase());
		
		
		
		colorfulTabs.isFlock=(window.navigator.userAgent.toLowerCase().indexOf('flock')>=0)?true:false;
		colorfulTabs.setCtPref();		
		Components.utils.import("resource://gre/modules/AddonManager.jsm");		
		colorfulTabs.chkRestore();
		colorfulTabs.showHideColorfulTabsStack();
		document.addEventListener("TabOpen", colorfulTabs.calcTabClr, false);
		document.addEventListener("SSTabRestored",colorfulTabs.restoreTabClr,false);
		document.addEventListener("TabClose", colorfulTabs.showHideColorfulTabsStack, false);
		//document.addEventListener("TabSelect", colorfulTabs.opacitycss, false);
		//document.addEventListener("TabOpen", colorfulTabs.setTaBottomClr, false);
		document.addEventListener("TabSelect", colorfulTabs.setTaBottomClr, false);
		document.addEventListener("TabSelect", colorfulTabs.setstandout, false);
		//document.addEventListener("mouseover", colorfulTabs.effectMouseIn, false);
		//document.addEventListener("mouseout", colorfulTabs.effectMouseOut, false);
		
		try { gBrowser.mTabContainer.mAllTabsPopup.addEventListener("popupshowing", colorfulTabs.setMIcolor, false); } catch(e){} //seamonkey doesn't have tabs popup
		colorfulTabs.initTabcontext();
		colorfulTabs.setMinify();
		return;
		},
//first run
frInit: function ()
	{	
	AddonManager.getAddonByID("{0545b830-f0aa-4d7e-8820-50a4629a56fe}", function(addon) {
			colorfulTabs.newVersion = addon.version;
			if ( colorfulTabs.ctVersion != colorfulTabs.newVersion)
				{				
				if(window.navigator.onLine )
					{
					colorfulTabs.ctFirstRun(colorfulTabs.newVersion)					
					}
				else
					{
					}
				}
			});	
	},  
	
executeSoon: function(aFunc)
	{	
	var tm = Components.classes["@mozilla.org/thread-manager;1"].getService(Components.interfaces.nsIThreadManager);
	tm.mainThread.dispatch(
		{
		run: function()
			{
			aFunc();	
			}
		},
	Components.interfaces.nsIThread.DISPATCH_NORMAL);
	},
//first run
ctFirstRun: function(ctVersion)
	{
	var clrUrl;
	if(colorfulTabs.ctVersion == '0')
		{
		clrUrl = 'http://colorfultabs.binaryturf.com/?vi='
		}
	else
		{
		clrUrl = 'http://colorfultabs.binaryturf.com/?vu='
		}
	clrUrl = clrUrl+escape(ctVersion);
	colorfulTabs.executeSoon(function(){gBrowser.selectedTab = gBrowser.addTab(clrUrl); });
	Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).setCharPref("extensions.clrtabs.firstrun", colorfulTabs.newVersion);
	},
	
//checks if session restore is in progress
 chkRestore: function()
	{
	var tab,tabClr;
	var tabLen = gBrowser.mTabContainer.childNodes.length;
	for(var tn=0;tn<tabLen;tn++)
		{
		tab = gBrowser.mTabContainer.childNodes[tn];
		switch (colorfulTabs.scheme)
			{
			case 0:	
				if(colorfulTabs.clrSession.getTabValue(tab,"ctreadonly") == 1)
					{
					break;
					}
				tabClr = colorfulTabs.tabColors[colorfulTabs.clr%32];				
				colorfulTabs.setColor(tab,tabClr);
				colorfulTabs.clr++;
				break;
			case 1:
				if(colorfulTabs.clrSession.getTabValue(tab,"ctreadonly") == 1)
					break;
					var clrSat = colorfulTabs.clrRand(colorfulTabs.satmin,colorfulTabs.satmax);	//for keeping saturation to match the old static template we need the saturation between 30 and 95;ideally could be min 30; add advanced  prefs later
					var clrLum = colorfulTabs.clrRand(colorfulTabs.lummin,colorfulTabs.lummax);	//for keeping saturation to match the old static template we need the luminance between 68 and 78
					var randkey = parseInt(Math.random()*100000000000000).toString();	//generate a really random int
					tabClr ='hsl('+Math.abs(colorfulTabs.clrHash(randkey))%360+','+clrSat+'%,'+clrLum+'%)';
				colorfulTabs.setColor(tab,tabClr);
				break;
			case 2:				
				tab.linkedBrowser.addProgressListener(colorfulTabsUrlListener);
				break;
			case 3:
				//colorfulTabs.setTaBottomClr();
				colorfulTabs.setColor(tab,colorfulTabs.uncoloredbgclr);
			break;
			}
		}
	},
	
//resets tab color
resetTabClr :function()
	{
	var clrObj = document.popupNode;
	if(!clrObj)
		{
		clrObj = gBrowser.selectedTab;
		}
	if(clrObj.className=='tabbrowser-tabs')
		{
		clrObj=gBrowser.selectedTab;
		}
	
		colorfulTabs.setColor(clrObj, "rgb(255,255,255)");
		colorfulTabs.clrSession.setTabValue(clrObj, "ctreadonly", 0);
	},
	
//also add ability to go to last tab	
clrScroll: function()
	{	
	gBrowser.mTabContainer.mTabstrip.ensureElementIsVisible(gBrowser.selectedTab, false);
	},

setDomainPref: function()
	{	
	var clrObj = document.popupNode;
	if(!clrObj)
		{
		clrObj = gBrowser.selectedTab;
		}
	if(clrObj.className=='tabbrowser-tabs')
		{
		clrObj=gBrowser.selectedTab;
		}
	var params = {inn:{oldColor:'rgb('+colorfulTabs.clrSession.getTabValue(clrObj, "tabClr").toString()+')',domain:clrObj.linkedBrowser.contentDocument.location.host, enabled:0}, out:null};
	window.openDialog('chrome://clrtabs/content/domainclr.xul','_blank','modal,chrome,centerscreen,resizable=no, dialog=yes,close=no', params).focus();
	if (params.inn.enabled)
		{
		var clrNewColor = params.inn.oldColor;
		var domain = params.inn.domain;
		colorfulTabs.setColor(clrObj, clrNewColor.toString());
		colorfulTabs.clrSession.setTabValue(clrObj, "ctreadonly", 1);
		
		//merge domain preference
		//does the domain already exist?change existing value:append the new domain to preset
		var domainsPref = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getCharPref("extensions.clrtabs.dpref");
		domainsPref = domainsPref.split("`");
		var domainExists = 0;	
		for(var i=0;i<domainsPref.length;i++)
			{
			if(domainsPref[i].split("~")[0].indexOf(domain) >= 0)
				{				
				domainsPref[i] = domain+'~'+clrNewColor.toString();
				domainExists = 1;
				}
			}
		if(domainExists == 0)
			{
			domainsPref.push(domain+'~'+clrNewColor);
			}
		
		domainsPref = domainsPref.join('`');
		Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).setCharPref("extensions.clrtabs.dpref",domainsPref);
		}
	else
		{
		}	
	},

	
//initialises tabs' context menu as per pref.
initTabcontext: function()
	{
	if(Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getBoolPref("extensions.clrtabs.menu").toString()=='true')
		{
		var clrMenu1 = document.createElement("menu");
		clrMenu1.setAttribute("label","ColorfulTabs");
		clrMenu1.setAttribute("id","colorfulTabsContext");
		var clrMenu2 = document.createElement("menupopup");
		clrMenu2.setAttribute("id","colorfulTabsContextPopup");
		clrMenu1.appendChild(clrMenu2);
		
		var clrItemScroll = document.createElement("menuitem");
		clrItemScroll.addEventListener("command",colorfulTabs.clrScroll,false);
		clrItemScroll.setAttribute("label", "Go To Current Tab");
		clrItemScroll.setAttribute("id", "colorfulTabsScroll");
		clrItemScroll.setAttribute("key", "colorfulTabsScroller");
		//clrItemScroll.setAttribute("acceltext", "Alt+Shift+C");
		clrItemScroll.setAttribute("tooltiptext", "Scroll To The Currently Selected Tab {Or Use Shortcut Key: Alt+Shift+C}");
		clrMenu2.appendChild(clrItemScroll);
		
		var clrItemRecolor = document.createElement("menuitem");
		clrItemRecolor.addEventListener("command",colorfulTabs.regenClr,false);
		clrItemRecolor.setAttribute("label", "Re-Color Tab");
		clrItemRecolor.setAttribute("id", "colorfulTabsRecolor");
		clrItemRecolor.setAttribute("key", "colorfulTabsRecolorMI");
		//clrItemRecolor.setAttribute("acceltext", "Alt+Shift+R");
		clrItemRecolor.setAttribute("tooltiptext", "Recolor The Tab {Or Use Shortcut Key: Alt+Shift+R}");
		clrMenu2.appendChild(clrItemRecolor);
		
		var clrMenu3 = document.createElement("menuitem");
    	clrMenu3.addEventListener("command",colorfulTabs.setUserClr,false);
		clrMenu3.setAttribute("label", "Change Tab Color");
		clrMenu3.setAttribute("key", "colorfulTabsChangeTabColor");
		//clrMenu3.setAttribute("acceltext", "Alt+Shift+I");
		clrMenu2.appendChild(clrMenu3);
		
		var clrMenu3a = document.createElement("menuitem");
		clrMenu3a.addEventListener("command",colorfulTabs.resetTabClr,false);
		clrMenu3a.setAttribute("label", "Reset Color");
		clrMenu3a.setAttribute("key", "colorfulTabsResetColor");
		//clrMenu3a.setAttribute("acceltext", "Alt+Shift+U");
		clrMenu2.appendChild(clrMenu3a);
		
		var clrMenu4 = document.createElement("menuitem");
		clrMenu4.addEventListener("command",colorfulTabs.showOptions,false);
		clrMenu4.setAttribute("key","colorfulTabsShowOptions",false);
		clrMenu4.setAttribute("label", "Options");
		clrMenu2.appendChild(clrMenu4);
		
		var clrMenu5 = document.createElement("menuitem");
		clrMenu5.addEventListener("command",colorfulTabs.toggleMinify,false);
		clrMenu5.setAttribute("label", "Mini-Mode");
		clrMenu5.setAttribute("type", "checkbox");
		clrMenu5.setAttribute("key", "colorfulTabsMinify");
		clrMenu5.setAttribute("id", "colorfulTabsmini");
		clrMenu2.appendChild(clrMenu5);		
		
		var ctSep = document.createElement("menuseparator");
		ctSep.setAttribute('id','colorfulTabsSeparator');
		window.getBrowser().mStrip.childNodes[1].appendChild(ctSep);
    	window.getBrowser().mStrip.childNodes[1].appendChild(clrMenu1);
		
		colorfulTabs.initDomainContext();
		
		}
	else
		{
		if(document.getElementById('colorfulTabsSeparator'))
		try
			{
			var ctwm = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
			var ctenumerator = ctwm.getEnumerator('navigator:browser');
			var ctwin;
			var ctItem1,ctItem2,ctBrowser;
			while(ctenumerator.hasMoreElements())
				{
				ctwin = ctenumerator.getNext();
				ctItem1 = ctwin.document.getElementById('colorfulTabsSeparator');
				ctItem2 = ctwin.document.getElementById('colorfulTabsContext');
				ctBrowser = ctwin.getBrowser();
				ctBrowser.mStrip.childNodes[1].removeChild(ctItem1);
			 	ctBrowser.mStrip.childNodes[1].removeChild(ctItem2);
				}
			}
		catch(e){colorfulTabs.cl('Error in inittabcontext: '+e);return;}
		}
	},
toggleMinify: function(){
var prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefService).getBranch("extensions.clrtabs.");
    try {       
        if(prefs.getBoolPref("minify") ==  true)
            {
			prefs.setBoolPref("minify", false)
			
			}     
        else
            {
			prefs.setBoolPref("minify", true)
			
			}
        }
    catch(e)
        {
        colorfulTabs.cl(e);
        }
},
setMinify: function(){
	colorfulTabs.cl('setMinify');
	var tabs = document.getElementById("tabbrowser-tabs");
    var origClass = tabs.hasAttribute("class") ? tabs.getAttribute("class") : null;
    if(colorfulTabs.minify == false)
		{
		origClass = origClass.replace(/ ?colorfultabs\-minified/, '');
        if (origClass)
			{
			tabs.setAttribute("class", origClass);
            }
		else
			{
			tabs.removeAttribute("class");
			}
		try
			{
			document.getElementById('colorfulTabsmini').removeAttribute("checked");
			}
		catch(e)
			{
			colorfulTabs.cl(e);
			}
		}
	if(colorfulTabs.minify == true) 
		{
		origClass = (origClass) ? (origClass+" "+"colorfultabs-minified") : ("colorfultabs-minified");
		tabs.setAttribute("class", origClass);
		try
			{
			document.getElementById('colorfulTabsmini').setAttribute("checked","true");
			}
		catch(e)
			{
			colorfulTabs.cl(e);
			}
		}
},
initDomainContext: function()
	{
	if(colorfulTabs.scheme == 2)
			{
			var clrMenuDomain = document.createElement("menuitem");
			clrMenuDomain.addEventListener("command",colorfulTabs.setDomainPref,false);
			clrMenuDomain.setAttribute("label", "Add Domain Preset");
			clrMenuDomain.setAttribute("id", "clrDomainCtx");
			clrMenuDomain.setAttribute("key", "colorfulTabsAddDomain");
			document.getElementById("colorfulTabsContextPopup").insertBefore(clrMenuDomain,document.getElementById("colorfulTabsRecolor"));
			}
		else
			{
			try
				{
				var elem = document.getElementById("clrDomainCtx")
				elem.parentNode.removeChild(elem);
				}
			catch(e)
				{
				colorfulTabs.cl(e);
				}
			}
	},
//shows the recolor option in the tabs' ctx menu
showRecolor: function()
		{
		return;
		var showCtCtx = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getBoolPref("extensions.clrtabs.menu").toString();
		if(!showCtCtx) return;
		if((colorfulTabs.scheme == 1 || colorfulTabs.scheme == 2 || 1) && !document.getElementById('colorfulTabsRecolorMI')) //If the menu option has been turned on
			{
			var clrMenu2a = document.createElement("menuitem");
    		clrMenu2a.addEventListener("command",colorfulTabs.regenClr,false);
			clrMenu2a.setAttribute("label", "Re-Color");
			clrMenu2a.setAttribute("id", "colorfulTabsRecolor");
			clrMenu2a.setAttribute("key", "colorfulTabsRecolorMI");
			clrMenu2a.setAttribute("acceltext", "Alt+Shift+R");
			document.getElementById('colorfulTabsContextPopup').appendChild(clrMenu2a);
			}
		else
			{
			if(document.getElementById('colorfulTabsContextPopup')) 			//remove the element....
			try
				{
				var ctwm = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
				var ctenumerator = ctwm.getEnumerator('navigator:browser');
				var ctwin;
				var ctItem1,ctItem2,ctBrowser;
				while(ctenumerator.hasMoreElements())
					{
					ctwin = ctenumerator.getNext();
					ctItem2 = ctwin.document.getElementById('colorfulTabsContextPopup');
					ctBrowser = ctwin.getBrowser();
					ctItem2.removeChild(document.getElementById('colorfulTabsRecolorMI'));
					}
				}
			catch(e){colorfulTabs.cl(e);return;}
			}
		},
		
//generates a random color
regenClr: function()
	{
	var clrObj;
	if(document.popupNode)
		{
		clrObj = document.popupNode;
		if(clrObj.nodeName!=('tab') && clrObj.nodeName != "xul:tab")
		clrObj = gBrowser.selectedTab;
		}
	else
		{
		clrObj = gBrowser.selectedTab;
		}
	var clrSat = colorfulTabs.clrRand(colorfulTabs.satmin,colorfulTabs.satmax);	//for keeping saturation to match the old static template we need the saturation between 30 and 95;ideally could be min 30; add advanced  prefs later
	var clrLum = colorfulTabs.clrRand(colorfulTabs.lummin,colorfulTabs.lummax);	//for keeping saturation to match the old static template we need the luminance between 68 and 78
	var randkey = parseInt(Math.random()*100000000000000).toString();	//generate a really random int
	var tabClr ='hsl('+Math.abs(colorfulTabs.clrHash(randkey))%360+','+clrSat+'%,'+clrLum+'%)';
	colorfulTabs.setColor(clrObj,tabClr);
	colorfulTabs.clrSession.setTabValue(clrObj, "ctreadonly", 1);
	},
	
//opens the ct. options box from the ctx menu
showOptions: function()
	{
	var features;
	try
		{
		var instantApply = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getBoolPref("browser.preferences.instantApply");
		features = "chrome,titlebar,toolbar,centerscreen"// + (instantApply ? ",dialog=no" : ",modal");
		}
	catch (e)
		{
		features = "chrome,titlebar,toolbar,centerscreen,modal";
		}
	//use these anyway
	features = "chrome,centerscreen,resizable=no,dialog=yes,toolbar,close=yes,dependent=yes";
	var optionsURL = "chrome://clrtabs/content/clrtabsopt.xul";
	openDialog(optionsURL, "", features);
	} ,
	
//sets the initial prefs
setCtPref: function()
	{
	//cl:     useragent=mozilla/5.0 (windows nt 6.2; wow64; rv:29.0) gecko/20100101 firefox/29.0
	colorfulTabs.cl(window.navigator.userAgent);
	colorfulTabs.isAustralis = (window.navigator.userAgent.toLowerCase().indexOf('firefox/29')>=0)?true:false;
	if(colorfulTabs.isAustralis)
		{
		document.getElementById('main-window').className=document.getElementById('main-window').className+" australis";
		el = document.getElementById('colorfulTabsStack');
		parent = el.parentNode;
		throwaway = el.parentNode.removeChild(el);
		parent.insertBefore(throwaway, document.getElementById('nav-bar'));
		}
	colorfulTabs.isMac = (window.navigator.userAgent.toLowerCase().indexOf('macintosh')>=0)?true:false;
		if(colorfulTabs.isMac)
			{
			document.getElementById('main-window').className=document.getElementById('main-window').className+" mac";
			}
	colorfulTabsPrefObserver.register();
	colorfulTabsStackPrefObserver.register();
	var clrprefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
	try
		{
		var ppref = clrprefs.getCharPref("extensions.clrtabs.ppref");
		ppref = ppref.split('~');
		colorfulTabs.tabColors = ppref;
		colorfulTabs.minify = clrprefs.getBoolPref("extensions.clrtabs.minify");		
		colorfulTabs.txtshadow = clrprefs.getBoolPref("extensions.clrtabs.txtshadow");
		colorfulTabs.tablabelblink = clrprefs.getBoolPref("extensions.clrtabs.tablabelblink");
		colorfulTabs.dispStack = clrprefs.getBoolPref("extensions.clrtabs.dispstack");
		colorfulTabs.currenttab = clrprefs.getBoolPref("extensions.clrtabs.currenttab");
		colorfulTabs.currenttabclr = clrprefs.getCharPref("extensions.clrtabs.currenttabclr");		
		colorfulTabs.uncoloredbgclr = clrprefs.getCharPref("extensions.clrtabs.uncoloredbgclr");
		colorfulTabs.tabtextclr = clrprefs.getCharPref("extensions.clrtabs.tabtextclr");	
		colorfulTabs.aggressive = clrprefs.getBoolPref("extensions.clrtabs.aggressive")?'important':'';
		colorfulTabs.fadedeg = clrprefs.getIntPref("extensions.clrtabs.fadedeg");
		colorfulTabs.scheme = clrprefs.getIntPref("extensions.clrtabs.scheme");
		colorfulTabs.ctVersion = clrprefs.getCharPref("extensions.clrtabs.firstrun");
		colorfulTabs.txtreverse = clrprefs.getBoolPref("extensions.clrtabs.txtreverse");
		colorfulTabs.enabledomain=clrprefs.getBoolPref("extensions.clrtabs.enabledomain");
		colorfulTabs.colorunmatcheddomain=clrprefs.getBoolPref("extensions.clrtabs.colorunmatcheddomain");
		colorfulTabs.dpref=clrprefs.getCharPref("extensions.clrtabs.dpref");
		colorfulTabs.dpref=colorfulTabs.dpref.split("`");
		colorfulTabs.standout=clrprefs.getBoolPref("extensions.clrtabs.standout");
		colorfulTabs.clrAllTabsPopPref=clrprefs.getBoolPref("extensions.clrtabs.clrAllTabsPopPref");
		colorfulTabs.txtshadowcss();
		colorfulTabs.tabtextclrcss();
		colorfulTabs.tablabelblinkcss();
		colorfulTabs.currenttabcss();
		colorfulTabs.dispstackcss();
		colorfulTabs.opacitycss();
		colorfulTabs.setstandout();
		colorfulTabs.adv = clrprefs.getBoolPref("extensions.clrtabs.advanced");
		colorfulTabs.ctdebug = clrprefs.getBoolPref("extensions.clrtabs.consolelog");
		if(colorfulTabs.adv==false)//satmax,satmin,lummax,lummin;
			{
			colorfulTabs.satmax=100;
			colorfulTabs.satmin=22;
			colorfulTabs.lummax=78;
			colorfulTabs.lummin=68;
			colorfulTabs.sat=61;
			colorfulTabs.lum=73;
			}
		else
			{
			colorfulTabs.satmax=clrprefs.getIntPref("extensions.clrtabs.satmax");
			colorfulTabs.satmin=clrprefs.getIntPref("extensions.clrtabs.satmin");
			colorfulTabs.lummax=clrprefs.getIntPref("extensions.clrtabs.lummax");
			colorfulTabs.lummin=clrprefs.getIntPref("extensions.clrtabs.lummin");
			colorfulTabs.sat=clrprefs.getIntPref("extensions.clrtabs.sat");
			colorfulTabs.lum=clrprefs.getIntPref("extensions.clrtabs.lum");
			}
		if(clrprefs.getBoolPref("extensions.clrtabs.bgpic")==true)
			{
			if(colorfulTabs.isSeamonkey)
				{
				colorfulTabs.setSeamonkeyContainerBg(true);
				}
			else
				{
				gBrowser.mTabContainer.style.backgroundImage="url("+clrprefs.getCharPref("extensions.clrtabs.bgpicpath")+")";
				gBrowser.mTabContainer.style.backgroundRepeat="repeat";
				}
			}
		}
	catch(e)
		{
		colorfulTabs.cl('Error in setCtPref'+e)
		
		}
	},
	
//calculates the tab clr based on the preferred algo.
calcTabClr:function(event)
	{
	try
		{
		if(Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getBoolPref("browser.tabs.autoHide").toString()=='true')
			{
			var tabLen = gBrowser.mTabContainer.childNodes.length;
			if(tabLen > 1)
				{
				colorfulTabs.show_ctStack();
				}
			}
		}
	catch(e)
		{
		}
	var tab;
	var clrSat,clrLum,tabClr;
	if(event)
		{
		tab = event.originalTarget;
		}
	else
		{
		tab = gBrowser.mTabContainer.childNodes[0];
		}
	switch (colorfulTabs.scheme)
		{
		case 0:
				if(colorfulTabs.clrSession.getTabValue(tab,"ctreadonly") == 1)
					break;
					tabClr = colorfulTabs.tabColors[colorfulTabs.clr%32];
				colorfulTabs.setColor(tab,tabClr);
				colorfulTabs.clr++;
				break;
		case 1:
				if(colorfulTabs.clrSession.getTabValue(tab,"ctreadonly") == 1)
					{
					return;
					}
					clrSat = colorfulTabs.clrRand(colorfulTabs.satmin,colorfulTabs.satmax);	//for keeping saturation to match the old static template we need the saturation between 30 and 95;ideally could be min 30; add advanced  prefs later
					clrLum = colorfulTabs.clrRand(colorfulTabs.lummin,colorfulTabs.lummax);	//for keeping saturation to match the old static template we need the luminance between 68 and 78
					var randkey = parseInt(Math.random()*100000000000000).toString();	//generate a really random int
					tabClr ='hsl('+Math.abs(colorfulTabs.clrHash(randkey))%360+','+clrSat+'%,'+clrLum+'%)';
				colorfulTabs.setColor(tab,tabClr);
			break;
		case 2:
			tab.linkedBrowser.addProgressListener(colorfulTabsUrlListener);
			break;
		case 3:
			//colorfulTabs.setTaBottomClr();
			colorfulTabs.setColor(tab,colorfulTabs.uncoloredbgclr);
		break;
		}
	},
	
//returns hsl for the passed rgb clr values
get_hsl:function gethsl(r,g,b)
	{
    r /= 255, g /= 255, b /= 255;
    var max = Math.max(r, g, b), min = Math.min(r, g, b);
    var h, s, l = (max + min) / 2;
    if(max == min)
    	{
        h = s = 0; // achromatic
    	}
    else
    	{
        var d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch(max){
            case r: h = (g - b) / d + (g < b ? 6 : 0); break;
            case g: h = (b - r) / d + 2; break;
            case b: h = (r - g) / d + 4; break;
        }
        h /= 6;
    	}
    h=Math.floor(h*360)
    while(h>360)
	    {
	    h = h-360;
	    }
   	s = Math.floor(s*100);
	l = Math.floor(l*100);
    return [h,s,l];
	},
	
//takes a valid CSS color(?) and colors the tab with it.
setColor:function(tab, tabClr)
	{
	//alert("caller is " + arguments.callee.caller.toString());
	tabClr=tabClr.replace(/^\s+|\s+$/, '').replace(' ','');
	tabClr=colorfulTabs.rgbclr(tabClr);	
	if(!colorfulTabs.isMac)
		{
		tab.style.setProperty('background-image','-moz-linear-gradient(rgba(255,255,255,.7),rgba('+tabClr+',.5),rgb('+tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))',colorfulTabs.aggressive);
		}
	else
		{
		var macClr = '-moz-linear-gradient(rgba(255,255,255,0),rgb('+tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))';
		document.getAnonymousElementByAttribute(tab, "class", "tab-background-start").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
		document.getAnonymousElementByAttribute(tab, "class", "tab-background-middle").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
		document.getAnonymousElementByAttribute(tab, "class", "tab-background-end").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
		}
	
	try
		{
		colorfulTabs.clrSession.setTabValue(tab, "tabClr", tabClr.toString()); //session doesn't initialize unless tabs are finished restoring, so this may not work for tabs whose color hasn't been saved in session
		}
	catch(e)
		{
		colorfulTabs.cl('Error in setColor: '+e);
		}
	colorfulTabs.setMIcolor(tab,tabClr);
	colorfulTabs.setstandout();
	colorfulTabs.setTaBottomClr();
	},
	
//takes a color and returns the array of r,g,b components like "255,0,0".
//helps to use these colors to create rgba/gradients etc.
//only rgb,hsl & color names are supported.
rgbclr:function(clr){
	clr=clr.toString();
	clr=clr.replace(/^\s+|\s+$/, '');	//trim
	if(clr.indexOf('rgb')>=0 && clr.indexOf('rgba')<0)
		{
		clr=clr.replace('rgb','');
		clr=clr.replace('(','')
		clr=clr.replace(')','')
		}
	else
		{
		if(clr.indexOf('hsl')>=0 && clr.indexOf('hsla')<0)
			{
			//colorfulTabs.cl('hsl');
			clr=clr.replace('hsl','');
			clr=clr.replace('%','')
			clr=clr.replace('%','')
			clr=clr.replace('(','')
			clr=clr.replace(')','')
			clr= clr.split(',');
			clr=colorfulTabs.hsl2rgb(clr[0],clr[1],clr[2]);
			}
		else
			{
			if(clr.indexOf('#')>=0)
				{
				clr=clr.replace('#','');
				var r = parseInt(clr.substring(0,2),16);
				var g = parseInt(clr.substring(2,4),16)
				var b = parseInt(clr.substring(4,6),16);
				if(clr.length == 3)
					{
					r = clr.substring(0,1)+''+clr.substring(0,1)
					g = clr.substring(1,2)+''+clr.substring(1,2)
					b = clr.substring(2,3)+''+clr.substring(2,3)
					r = parseInt(r,16);
					g = parseInt(g,16)
					b = parseInt(b,16);
					 r
					}
				
				clr=r+","+g+","+b;
				}
			else
				{
				try
					{
					var clrKeys = {aliceblue : "rgb(240,248,255)",antiquewhite : "rgb(250,235,215)",aqua : "rgb(0,255,255)",aquamarine : "rgb(127,255,212)",azure : "rgb(240,255,255)",beige : "rgb(245,245,220)",bisque : "rgb(255,228,196)",black : "rgb(0,0,0)",blanchedalmond : "rgb(255,235,205)",blue : "rgb(0,0,255)",blueviolet : "rgb(138,43,226)",brown : "rgb(165,42,42)",burlywood : "rgb(222,184,135)",cadetblue : "rgb(95,158,160)",chartreuse : "rgb(127,255,0)",chocolate : "rgb(210,105,30)",coral : "rgb(255,127,80)",cornflowerblue : "rgb(100,149,237)",cornsilk : "rgb(255,248,220)",crimson : "rgb(220,20,60)",cyan : "rgb(0,255,255)",darkblue : "rgb(0,0,139)",darkcyan : "rgb(0,139,139)",darkgoldenrod : "rgb(184,134,11)",darkgray : "rgb(169,169,169)",darkgreen : "rgb(0,100,0)",darkgrey : "rgb(169,169,169)",darkkhaki : "rgb(189,183,107)",darkmagenta : "rgb(139,0,139)",darkolivegreen : "rgb(85,107,47)",darkorange : "rgb(255,140,0)",darkorchid : "rgb(153,50,204)",darkred : "rgb(139,0,0)",darksalmon : "rgb(233,150,122)",darkseagreen : "rgb(143,188,143)",darkslateblue : "rgb(72,61,139)",darkslategray : "rgb(47,79,79)",darkslategrey : "rgb(47,79,79)",darkturquoise : "rgb(0,206,209)",darkviolet : "rgb(148,0,211)",deeppink : "rgb(255,20,147)",deepskyblue : "rgb(0,191,255)",dimgray : "rgb(105,105,105)",dimgrey : "rgb(105,105,105)",dodgerblue : "rgb(30,144,255)",firebrick : "rgb(178,34,34)",floralwhite : "rgb(255,250,240)",forestgreen : "rgb(34,139,34)",fuchsia : "rgb(255,0,255)",gainsboro : "rgb(220,220,220)",ghostwhite : "rgb(248,248,255)",gold : "rgb(255,215,0)",goldenrod : "rgb(218,165,32)",gray : "rgb(128,128,128)",green : "rgb(0,128,0)",greenyellow : "rgb(173,255,47)",grey : "rgb(128,128,128)",honeydew : "rgb(240,255,240)",hotpink : "rgb(255,105,180)",indianred : "rgb(205,92,92)",indigo : "rgb(75,0,130)",ivory : "rgb(255,255,240)",khaki : "rgb(240,230,140)",lavender : "rgb(230,230,250)",lavenderblush : "rgb(255,240,245)",lawngreen : "rgb(124,252,0)",lemonchiffon : "rgb(255,250,205)",lightblue : "rgb(173,216,230)",lightcoral : "rgb(240,128,128)",lightcyan : "rgb(224,255,255)",lightgoldenrodyellow : "rgb(250,250,210)",lightgray : "rgb(211,211,211)",lightgreen : "rgb(144,238,144)",lightgrey : "rgb(211,211,211)",lightpink : "rgb(255,182,193)",lightsalmon : "rgb(255,160,122)",lightseagreen : "rgb(32,178,170)",lightskyblue : "rgb(135,206,250)",lightslategray : "rgb(119,136,153)",lightslategrey : "rgb(119,136,153)",lightsteelblue : "rgb(176,196,222)",lightyellow : "rgb(255,255,224)",lime : "rgb(0,255,0)",limegreen : "rgb(50,205,50)",linen : "rgb(250,240,230)",magenta : "rgb(255,0,255)",maroon : "rgb(128,0,0)",mediumaquamarine : "rgb(102,205,170)",mediumblue : "rgb(0,0,205)",mediumorchid : "rgb(186,85,211)",mediumpurple : "rgb(147,112,219)",mediumseagreen : "rgb(60,179,113)",mediumslateblue : "rgb(123,104,238)",mediumspringgreen : "rgb(0,250,154)",mediumturquoise : "rgb(72,209,204)",mediumvioletred : "rgb(199,21,133)",midnightblue : "rgb(25,25,112)",mintcream : "rgb(245,255,250)",mistyrose : "rgb(255,228,225)",moccasin : "rgb(255,228,181)",navajowhite : "rgb(255,222,173)",navy : "rgb(0,0,128)",oldlace : "rgb(253,245,230)",olive : "rgb(128,128,0)",olivedrab : "rgb(107,142,35)",orange : "rgb(255,165,0)",orangered : "rgb(255,69,0)",orchid : "rgb(218,112,214)",palegoldenrod : "rgb(238,232,170)",palegreen : "rgb(152,251,152)",paleturquoise : "rgb(175,238,238)",palevioletred : "rgb(219,112,147)",papayawhip : "rgb(255,239,213)",peachpuff : "rgb(255,218,185)",peru : "rgb(205,133,63)",pink : "rgb(255,192,203)",plum : "rgb(221,160,221)",powderblue : "rgb(176,224,230)",purple : "rgb(128,0,128)",red : "rgb(255,0,0)",rosybrown : "rgb(188,143,143)",royalblue : "rgb(65,105,225)",saddlebrown : "rgb(139,69,19)",salmon : "rgb(250,128,114)",sandybrown : "rgb(244,164,96)",seagreen : "rgb(46,139,87)",seashell : "rgb(255,245,238)",sienna : "rgb(160,82,45)",silver : "rgb(192,192,192)",skyblue : "rgb(135,206,235)",slateblue : "rgb(106,90,205)",slategray : "rgb(112,128,144)",slategrey : "rgb(112,128,144)",snow : "rgb(255,250,250)",springgreen : "rgb(0,255,127)",steelblue : "rgb(70,130,180)",tan : "rgb(210,180,140)",teal : "rgb(0,128,128)",thistle : "rgb(216,191,216)",tomato : "rgb(255,99,71)",turquoise : "rgb(64,224,208)",violet : "rgb(238,130,238)",wheat : "rgb(245,222,179)",white : "rgb(255,255,255)",whitesmoke : "rgb(245,245,245)",yellow : "rgb(255,255,0)",yellowgreen : "rgb(154,205,50)"}
					clr=clrKeys[clr];
					clr=clr.replace('rgb','');
					clr=clr.replace('(','')
					clr=clr.replace(')','')
					}
				catch(e)
					{
					this.cl("rgbclr Could not convert color to rgb because of the following error:\n"+e)
					}
				}
			}
		}
	return clr;
},

//does... figure it out by the functionname
hsl2rgb:function(h, s, l) {
	var m1, m2, hue;
	var r, g, b
	s /=100;
	l /= 100;
	if (s == 0)
		r = g = b = (l * 255);
	else {
		if (l <= 0.5)
			m2 = l * (s + 1);
		else
			m2 = l + s - l * s;
		m1 = l * 2 - m2;
		hue = h / 360;
		r = colorfulTabs.HueToRgb(m1, m2, hue + 1/3);
		g = colorfulTabs.HueToRgb(m1, m2, hue);
		b = colorfulTabs.HueToRgb(m1, m2, hue - 1/3);
	}
	return Math.round(r)+','+Math.round(g)+','+Math.round(b);//255,255,255
},

//does... figure it out by the functionname
HueToRgb:function(m1, m2, hue) {
	var v;
	if (hue < 0)
		hue += 1;
	else if (hue > 1)
		hue -= 1;
	if (6 * hue < 1)
		v = m1 + (m2 - m1) * hue * 6;
	else if (2 * hue < 1)
		v = m2;
	else if (3 * hue < 2)
		v = m1 + (m2 - m1) * (2/3 - hue) * 6;
	else
		v = m1;
	return 255 * v;
},

//sets the color of the alltabspopuplist items
setMIcolor:function(tab, tabClr)
	{
	for(var i = 0 ; i < gBrowser.mTabs.length;i++)
		{
		var tab = gBrowser.mTabs[i];
		var tabClr;
		if(tab.mCorrespondingMenuitem)
			{
			if(colorfulTabs.clrAllTabsPopPref)
				{
				tabClr = colorfulTabs.clrSession.getTabValue(gBrowser.mTabs[i], "tabClr").toString();
				tab.mCorrespondingMenuitem.style.setProperty('background-image','-moz-linear-gradient(rgba(255,255,255,.7),rgba('+tabClr+',.5),rgb('+tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))','important');
				}
			else{tab.mCorrespondingMenuitem.style.setProperty('background-image','none','important');}
			}
		}
	},
	
//restores a tabs color when a tab is restored
 restoreTabClr:function(event)
	{
	var tab = event.originalTarget;
	var myClr = colorfulTabs.clrSession.getTabValue(tab, "tabClr");
	if(myClr)
		{
		colorfulTabs.setColor(tab,'rgb('+myClr+')')
		}
	else
		{
		//colorfulTabs.regenClr();
		}
	},
	
//calculates a hash of passed string
 clrHash:function(clrString)
	{
	var hash = colorfulTabs.SHA256(clrString);
	var iClr, clrConst = 5381;// var clrString = ;
		for (iClr = 0; iClr < hash.length; iClr++)
		{
		clrConst = ((clrConst << 5) + clrConst) + hash.charCodeAt(iClr);
		}
	return clrConst;
	},
	
//returns a random number between two given numbers (for customizable algo)
 clrRand:function(min,max)
	{
	return (Math.round(Math.random()*(max-min)))+min;
	},
	
//manages the display of ctstack
showHideColorfulTabsStack:function(event)
	{
	try
		{
		if(Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getBoolPref("browser.tabs.autoHide").toString()=='true')
			{
			var tabLen = gBrowser.mTabContainer.childNodes.length;
			if(tabLen <= 2)
				{
				colorfulTabs.hide_ctStack();
				}
			}
		}
	catch(e)
		{
		}
	},
	
//hides the ctstack if less than 2 tabs
hide_ctStack:function()
	{
	document.getElementById('colorfulTabsStack').style.setProperty('display','none','important');
	},
	
//shows the ctstack if more than 1 tab
show_ctStack:function()
	{
	document.getElementById('colorfulTabsStack').style.setProperty('display','-moz-stack','important');
	},
	
//a formatted dump()
 cl:function(msg)
	{
	if(colorfulTabs.ctdebug) dump("\ncl:\t"+msg);
	},
	
//fades a node
fadeNode:function(node,opacity)
	{
	//node.style.setProperty('opacity',opacity,'important');
	},
	
//fades alltabs
fadeAllTabs:function(event)
	{	
	try
		{
		var tblength = gBrowser.mTabContainer.childNodes.length;
		for(var loop = 0; loop < tblength; loop++)
			{
			if(colorfulTabs.fadedeg)
				{
				//colorfulTabs.fadeNode(gBrowser.mTabContainer.childNodes[loop],(10-colorfulTabs.fadedeg)/10);
				}
			else
				{
				//colorfulTabs.fadeNode(gBrowser.mTabContainer.childNodes[loop],'1');
				}
			}
		}
	catch(e)
		{
		colorfulTabs.cl('Error in fadealltabs: '+e);
		}
	var tabClr;
	try
		{//remove highlighting from all other tabs
		for(var count=0;count< gBrowser.mTabContainer.childNodes.length;count++)
			{
			tabClr = colorfulTabs.clrSession.getTabValue(gBrowser.mTabContainer.childNodes[count], "tabClr");
			if(!colorfulTabs.isMac)
				{
				gBrowser.mTabContainer.childNodes[count].style.setProperty('background-image','-moz-linear-gradient(rgba(255,255,255,.7),rgba('+tabClr+',.5),rgb('+tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))',colorfulTabs.aggressive);
				}
			else
				{
				var macClr = '-moz-linear-gradient(rgba(255,255,255,0),rgb('+tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))';
				document.getAnonymousElementByAttribute(gBrowser.mTabContainer.childNodes[count], "class", "tab-background-start").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
				document.getAnonymousElementByAttribute(gBrowser.mTabContainer.childNodes[count], "class", "tab-background-middle").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
				document.getAnonymousElementByAttribute(gBrowser.mTabContainer.childNodes[count], "class", "tab-background-end").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
				}
			}
		}
	catch(e)
		{
		colorfulTabs.cl("\nColorfulTabs Error in function colorfulTabs.fadeAllTabs: "+e+". standout "+count2);
		}
	//add highlighting to the selected tab
	tabClr = colorfulTabs.clrSession.getTabValue(gBrowser.selectedTab, "tabClr");
	if(colorfulTabs.standout)
		{
		if(!colorfulTabs.isMac)
			{
			gBrowser.selectedTab.style.setProperty('background-image','-moz-linear-gradient(rgba(125,125,125,.1),rgba(225,225,225,.1),rgb('+tabClr+'),rgb('+ tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))',colorfulTabs.aggressive);
			}
		else
			{
			var macHClr = '-moz-linear-gradient(rgb('+tabClr+'),rgba('+tabClr+',.5),rgb('+tabClr+')),-moz-linear-gradient(white,white)';
			document.getAnonymousElementByAttribute(gBrowser.selectedTab, "class", "tab-background-start").style.setProperty('background-image',macHClr,colorfulTabs.aggressive);
			document.getAnonymousElementByAttribute(gBrowser.selectedTab, "class", "tab-background-middle").style.setProperty('background-image',macHClr,colorfulTabs.aggressive);
			document.getAnonymousElementByAttribute(gBrowser.selectedTab, "class", "tab-background-end").style.setProperty('background-image',macHClr,colorfulTabs.aggressive);
			}
		}		
	if(colorfulTabs.fadedeg)
		{
		try
			{
			//colorfulTabs.fadeNode(gBrowser.selectedTab,"1");
			}
		catch(e)
			{
			colorfulTabs.cl('Error in fadealltabs: '+e);
			}
		}
	colorfulTabs.setTaBottomClr();
	},
setstandout:function(){
	var tabClr;
	try
		{//remove highlighting from all other tabs
		for(var count=0;count< gBrowser.mTabContainer.childNodes.length;count++)
			{
			tabClr = colorfulTabs.clrSession.getTabValue(gBrowser.mTabContainer.childNodes[count], "tabClr");
			if(!colorfulTabs.isMac)
				{
				gBrowser.mTabContainer.childNodes[count].style.setProperty('background-image','-moz-linear-gradient(rgba(255,255,255,.7),rgba('+tabClr+',.5),rgb('+tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))',colorfulTabs.aggressive);
				}
			else
				{
				var macClr = '-moz-linear-gradient(rgba(255,255,255,0),rgb('+tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))';
				document.getAnonymousElementByAttribute(gBrowser.mTabContainer.childNodes[count], "class", "tab-background-start").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
				document.getAnonymousElementByAttribute(gBrowser.mTabContainer.childNodes[count], "class", "tab-background-middle").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
				document.getAnonymousElementByAttribute(gBrowser.mTabContainer.childNodes[count], "class", "tab-background-end").style.setProperty('background-image',macClr,colorfulTabs.aggressive);
				}
			}
		}
	catch(e)
		{
		colorfulTabs.cl("\nColorfulTabs Error in function colorfulTabs.fadeAllTabs: "+e+". standout "+count2);
		}
	//add highlighting to the selected tab
	tabClr = colorfulTabs.clrSession.getTabValue(gBrowser.selectedTab, "tabClr");
	if(colorfulTabs.standout)
		{
		if(!colorfulTabs.isMac)
			{
			gBrowser.selectedTab.style.setProperty('background-image','-moz-linear-gradient(rgba(125,125,125,.1),rgba(225,225,225,.1),rgb('+tabClr+'),rgb('+ tabClr+')),-moz-linear-gradient(rgb('+tabClr+'),rgb('+ tabClr+'))',colorfulTabs.aggressive);
			}
		else
			{
			var macHClr = '-moz-linear-gradient(rgb('+tabClr+'),rgba('+tabClr+',.5),rgb('+tabClr+')),-moz-linear-gradient(white,white)';
			document.getAnonymousElementByAttribute(gBrowser.selectedTab, "class", "tab-background-start").style.setProperty('background-image',macHClr,colorfulTabs.aggressive);
			document.getAnonymousElementByAttribute(gBrowser.selectedTab, "class", "tab-background-middle").style.setProperty('background-image',macHClr,colorfulTabs.aggressive);
			document.getAnonymousElementByAttribute(gBrowser.selectedTab, "class", "tab-background-end").style.setProperty('background-image',macHClr,colorfulTabs.aggressive);
			}
		}
	},	
//sets the color of the tab-bottom strip
setTaBottomClr:function()
	{
	try
		{
		var tabClr=colorfulTabs.clrSession.getTabValue(gBrowser.selectedTab, "tabClr");//session doesn't initialize unless tabs are finished restoring, so this may not work for tabs which color hasn't been saved in session
		var transTab = false;
		if(tabClr == ""){
		transTab = true;
		}
		tabClr=tabClr.replace(/^\s+|\s+$/, '');		
		if(!colorfulTabs.aggressive && colorfulTabs.currenttab)//currenttab is fixed color for selected tab
			{
			tabClr = colorfulTabs.rgbclr(colorfulTabs.currenttabclr);			
			}
		if(transTab)
			{
			document.getElementById('colorfulTabsStack').style.setProperty('background-color','rgb(240,246,252)',colorfulTabs.aggressive);
			}
		else
			{
			document.getElementById('colorfulTabsStack').style.setProperty('background-color','rgb('+tabClr+')',colorfulTabs.aggressive);
			}		 
		}
	catch(e){colorfulTabs.cl("Error in setTaBottomClr: "+e)}
	},
	
//seamonkey specific function
setSeamonkeyContainerBg:function(yes)
	{
	var clrPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getCharPref("extensions.clrtabs.bgpicpath");
	var ss = new Array();
	var ss = document.styleSheets;
	for (var i=0; i < ss.length; i++)
		{
		switch (ss[i].href)
			{
			case 'chrome://clrtabs/skin/clrtabs-seamonkey.css':
				var clrSS = ss[i];
				break;
			}
		}
	try
		{
		if(yes)
			{
			clrSS.cssRules[3].style.setProperty('background-image',"url("+clrPrefs+")" ,'important' );
			clrSS.cssRules[3].style.setProperty('background-repeat', "repeat","important");
			}
		else
			{
			clrSS.cssRules[3].style.setProperty('background-image',"url('chrome://clrtabs/skin/seamonkey-bg.png')" ,'important' );
			clrSS.cssRules[3].style.setProperty('background-repeat',"repeat-x" ,'important' );
			}
		}
	catch(e)
		{
		colorfulTabs.cl('Error in setSeamonkeyContainerBg: '+e);
		}
	},
	
//highlights the unselected tab on mouseover
effectMouseIn:function(event)
	{
	if (event.target.nodeName != "xul:tab" && event.target.nodeName != "tab") { return; }
	if((event.target.getAttribute('selected')=='true') ||(event.target.nodeName=='xul:tabs'))
		return;
	try
		{
		colorfulTabs.fadeNode(event.target,1);
		}
	catch(e)
		{		
		colorfulTabs.cl('Error in effectMouseIn: '+e);
		}
	},
	
//highlights the unselected tab on mouseover
effectMouseOut:function(event)
	{
	if (event.target.nodeName != "xul:tab" && event.target.nodeName != "tab") { return; }
	if((event.target.getAttribute('selected')=='true') ||(event.target.nodeName=='xul:tabs'))
		return;
	try
		{
		colorfulTabs.fadeNode(event.target,(10-colorfulTabs.fadedeg)/10);
		}
	catch(e)
		{
		}
	},
	
//colors the tab with a user-chosen clr
setUserClr:function()
	{
	colorfulTabs.cl('setUserClr');
	var clrObj = document.popupNode;
	if(!clrObj)
		{
		clrObj = gBrowser.selectedTab;
		}
	if(clrObj.className=='tabbrowser-tabs')
		{
		clrObj=gBrowser.selectedTab;
		}
	var params = {inn:{oldColor:'rgb('+colorfulTabs.clrSession.getTabValue(clrObj, "tabClr").toString()+')', enabled:0}, out:null};
	window.openDialog('chrome://clrtabs/content/clrpkr.xul','_blank','modal,chrome,centerscreen,resizable=no, dialog=yes,close=no', params).focus();
	if (params.inn.enabled)
		{
		var clrNewColor = params.inn.oldColor;
		colorfulTabs.setColor(clrObj, clrNewColor.toString());
		colorfulTabs.clrSession.setTabValue(clrObj, "ctreadonly", 1);
		}
	else
		{
		}
	},
	
//super-secret algo :)
SHA256:function(s)
	{
	var chrsz   = 8;
	var hexcase = 0;
	function safe_add (x, y)
		{
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
		}
	function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
	function R (X, n) { return ( X >>> n ); }
	function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
	function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
	function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
	function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
	function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
	function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }
	function core_sha256 (m, l)
		{
	var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
	var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
	var W = new Array(64);
	var a, b, c, d, e, f, g, h, i, j;
	var T1, T2;
	m[l >> 5] |= 0x80 << (24 - l % 32);
	m[((l + 64 >> 9) << 4) + 15] = l;
	for ( var i = 0; i<m.length; i+=16 )
		{
	a = HASH[0];
	b = HASH[1];
	c = HASH[2];
	d = HASH[3];
	e = HASH[4];
	f = HASH[5];
	g = HASH[6];
	h = HASH[7];
	for ( var j = 0; j<64; j++)
		{
		if (j < 16) W[j] = m[j + i];
		else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
		T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
		T2 = safe_add(Sigma0256(a), Maj(a, b, c));
		h = g;
		g = f;
		f = e;
		e = safe_add(d, T1);
		d = c;
		c = b;
		b = a;
		a = safe_add(T1, T2);
		}
	HASH[0] = safe_add(a, HASH[0]);
	HASH[1] = safe_add(b, HASH[1]);
	HASH[2] = safe_add(c, HASH[2]);
	HASH[3] = safe_add(d, HASH[3]);
	HASH[4] = safe_add(e, HASH[4]);
	HASH[5] = safe_add(f, HASH[5]);
	HASH[6] = safe_add(g, HASH[6]);
	HASH[7] = safe_add(h, HASH[7]);
	}
	return HASH;
	}
	function str2binb (str)
		{
	var bin = Array();
	var mask = (1 << chrsz) - 1;
	for(var i = 0; i < str.length * chrsz; i += chrsz)
		{
		bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
	}
	return bin;
	}
	function Utf8Encode(string)
		{
		string = string.replace(/\r\n/g,"\n");
		var utftext = "";
		for (var n = 0; n < string.length; n++)
			{
			var c = string.charCodeAt(n);
			if (c < 128)
				{
				utftext += String.fromCharCode(c);
				}
			else if((c > 127) && (c < 2048))
				{
				utftext += String.fromCharCode((c >> 6) | 192);
				utftext += String.fromCharCode((c & 63) | 128);
				}
				else
				{
				utftext += String.fromCharCode((c >> 12) | 224);
				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
				utftext += String.fromCharCode((c & 63) | 128);
				}
			}
		return utftext;
	}
	function binb2hex (binarray)		{
	var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
	var str = "";
	for(var i = 0; i < binarray.length * 4; i++)
		{
		str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) +
		hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
		}
	return str;
	}
	s = Utf8Encode(s);
	return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
	},
dispstackcss: function()
	{
	var clrSS;
	var clrPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getCharPref("extensions.clrtabs.bgpicpath");
	var ss = new Array();
	var ss = document.styleSheets;
	for (var i=0; i < ss.length; i++)
		{
		switch (ss[i].href)
			{
			case 'chrome://clrtabs/skin/prefs.css':
				clrSS = ss[i];
				break;
			}
		}
	try
		{
		if(colorfulTabs.dispStack)
			{
			clrSS.cssRules[7].style.setProperty('display','-moz-stack',colorfulTabs.aggressive);			
			}
		else
			{
			clrSS.cssRules[7].style.setProperty('display','none',colorfulTabs.aggressive);			
			}
		}
	catch(e){
		colorfulTabs.cl(e);
		}
	},
opacitycss: function()
	{
	var clrSS;
	var clrPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getCharPref("extensions.clrtabs.bgpicpath");
	var ss = new Array();
	var ss = document.styleSheets;
	for (var i=0; i < ss.length; i++)
		{
		switch (ss[i].href)
			{
			case 'chrome://clrtabs/skin/prefs.css':
				clrSS = ss[i];
				break;
			}
		}
	opacity = (10-colorfulTabs.fadedeg)/10;
	try
		{
		
		if(colorfulTabs.fadedeg)
			{
			clrSS.cssRules[10].style.setProperty('opacity', opacity,colorfulTabs.aggressive);			
			}
		else
			{
			clrSS.cssRules[10].style.setProperty('opacity','1',colorfulTabs.aggressive);			
			}
		}
	catch(e){
		colorfulTabs.cl(e);
		}
	},
tabtextclrcss: function()
	{
	var clrSS;
	var clrPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getCharPref("extensions.clrtabs.tabtextclr");
	var ss = new Array();
	var ss = document.styleSheets;
	for (var i=0; i < ss.length; i++)
		{
		switch (ss[i].href)
			{
			case 'chrome://clrtabs/skin/prefs.css':
				clrSS = ss[i];
				break;
			}
		}
	try
		{
		if(colorfulTabs.tabtextclr)
			{			
			clrSS.cssRules[0].style.setProperty('color',colorfulTabs.tabtextclr,colorfulTabs.aggressive);			
			}		
		}
	catch(e){}
	},	
txtshadowcss: function()
	{
	var clrSS;
	var clrPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getCharPref("extensions.clrtabs.bgpicpath");
	var ss = new Array();
	var ss = document.styleSheets;
	for (var i=0; i < ss.length; i++)
		{
		switch (ss[i].href)
			{
			case 'chrome://clrtabs/skin/prefs.css':
				clrSS = ss[i];
				break;
			}
		}
	try
		{
		if(colorfulTabs.txtshadow)
			{
			clrSS.cssRules[0].style.setProperty('text-shadow','white 1px 1px 1.5px',colorfulTabs.aggressive);
			clrSS.cssRules[1].style.setProperty('text-shadow','1px 1px 1px #fff',colorfulTabs.aggressive);
			clrSS.cssRules[2].style.setProperty('text-shadow','1px 1px 1px #000',colorfulTabs.aggressive);
			}
		else
			{
			clrSS.cssRules[0].style.setProperty('text-shadow',"none" ,colorfulTabs.aggressive );
			clrSS.cssRules[1].style.setProperty('text-shadow','none',colorfulTabs.aggressive);
			clrSS.cssRules[2].style.setProperty('text-shadow','none',colorfulTabs.aggressive);				
			}
		}
	catch(e)
		{
		colorfulTabs.cl('Error in txtshadowcss: '+e);
		}
	},
tablabelblinkcss: function()
	{
	var clrSS;
	var clrPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getCharPref("extensions.clrtabs.bgpicpath");
	var ss = new Array();
	var ss = document.styleSheets;
	for (var i=0; i < ss.length; i++)
		{
		switch (ss[i].href)
			{
			case 'chrome://clrtabs/skin/prefs.css':
				clrSS = ss[i];
				break;
			}
		}
	try
		{
		if(colorfulTabs.tablabelblink)
			{
			clrSS.cssRules[0].style.setProperty('color','black',null);
			clrSS.cssRules[8].style.setProperty('animation','myanim 1s infinite','important');
			clrSS.cssRules[8].style.setProperty('text-shadow','none','important');
			}
		else
			{
			clrSS.cssRules[0].style.setProperty('color','black','important');
			clrSS.cssRules[8].style.setProperty('animation','none','important');
			clrSS.cssRules[8].style.removeProperty('text-shadow');
			}
		}
	catch(e)
		{
		colorfulTabs.cl('Error in tablabelblinkcss: '+e);
		}
	},
	
/*
handles fixed color for selected tab
depending on agressive mode. Agressive mode determines whether this option is enabled or disabled
*/
currenttabcss: function()
		{
		var clrSS;
		var clrPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getCharPref("extensions.clrtabs.bgpicpath");
		var ss = new Array();
		var ss = document.styleSheets;
		for (var i=0; i < ss.length; i++)
			{
			switch (ss[i].href)
				{
				case 'chrome://clrtabs/skin/prefs.css':
					clrSS = ss[i];
					break;
				}
			}
		try
			{
			var sclr = colorfulTabs.rgbclr(colorfulTabs.currenttabclr);
			if(colorfulTabs.currenttab && !colorfulTabs.aggressive)
				{				
				if(colorfulTabs.standout == true)
					{
					if(!colorfulTabs.isMac)
						{						
						clrSS.cssRules[3].style.setProperty('background-image','-moz-linear-gradient(rgba(125,125,125,.1),rgba(225,225,225,.1),rgb('+sclr+'),rgb('+ sclr+')),-moz-linear-gradient(rgb('+sclr+'),rgb('+ sclr+'))','important');
							
						}
					else
						{ // is a mac
						var macHClr = '-moz-linear-gradient(rgb('+sclr+'),rgba('+sclr+',.5),rgb('+sclr+')),-moz-linear-gradient(white,white)';
						clrSS.cssRules[4].style.setProperty('background-image',macHClr,'important');
						clrSS.cssRules[5].style.setProperty('background-image',macHClr,'important');
						clrSS.cssRules[6].style.setProperty('background-image',macHClr,'important');
						}
					}
				else
					{ //no highlighting
					if(!colorfulTabs.isMac)
						{
						clrSS.cssRules[3].style.setProperty('background-image','-moz-linear-gradient(rgba(255, 255, 255, 0.7), rgba('+sclr+', 0.5), rgb('+sclr+')), -moz-linear-gradient(rgb('+sclr+'), rgb('+sclr+'))','important');
						}
					else
						{
						var macHClr = '-moz-linear-gradient(rgba(255,255,255,0),rgb('+sclr+')),-moz-linear-gradient(rgb('+sclr+'),rgb('+ sclr+'))';
						clrSS.cssRules[4].style.setProperty('background-image',macHClr,'important');
						clrSS.cssRules[5].style.setProperty('background-image',macHClr,'important');
						clrSS.cssRules[6].style.setProperty('background-image',macHClr,'important');
						}
					}
				}
			else
				{
				if(!colorfulTabs.isMac)
					{
					clrSS.cssRules[3].style.removeProperty('background-image');
					}
				else
					{
					clrSS.cssRules[4].style.removeProperty('background-image');
					clrSS.cssRules[5].style.removeProperty('background-image');
					clrSS.cssRules[6].style.removeProperty('background-image');
					}		
				}
			//colorfulTabs.setTaBottomClr();
			}
		catch(e)
			{
			
			colorfulTabs.cl('Error in currenttabcss: '+e);
			}
		},		
wOpen:function(url)
		{
		var wm = Components.classes['@mozilla.org/appshell/window-mediator;1'].getService();
		var wmi = wm.QueryInterface(Components.interfaces.nsIWindowMediator);
		var win = wmi.getMostRecentWindow("navigator:browser");
		if (win)
			{
			var tab = win.gBrowser.addTab(url);
			win.gBrowser.selectedTab = tab;
			return;
			}
		},
		
//unregisters ct
clrtabsUnload: function()
		{
		colorfulTabsStackPrefObserver.unregister();
		colorfulTabsPrefObserver.unregister();
		}
	}
	
var colorfulTabsStackPrefObserver =
	{
	register: function()
		{
		var prefService = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService);
		this._branch = prefService.getBranch("browser.tabs.");
		this._branch.QueryInterface(Components.interfaces.nsIPrefBranch);
		this._branch.addObserver("", this, false);
		},
	unregister: function()
		{
		if(!this._branch) return;
		this._branch.removeObserver("", this);
		},
	observe: function(subject, topic, data)
		{
		if (topic != "nsPref:changed")
			{
			return;
			}
		switch(data)
			{
			case "autoHide":
			if(Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getBoolPref("browser.tabs.autoHide").toString()=='true')
				{
				var tabLen = gBrowser.mTabContainer.childNodes.length;
				if(tabLen <= 2)
					{
					colorfulTabs.hide_ctStack();
					}
				}
			else
				{
				colorfulTabs.show_ctStack();
				}
			break;
			}
		}
	}
	
//ct pref observer
var colorfulTabsPrefObserver =
	{
	register: function()
		{
		var prefService = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService);
		this._branch = prefService.getBranch("extensions.clrtabs.");
		this._branch.QueryInterface(Components.interfaces.nsIPrefBranch);
		this._branch.addObserver("", this, false);
		},
	unregister: function()
		{
		if(!this._branch) return;
		this._branch.removeObserver("", this);
		},
	observe: function(aSubject, aTopic, aData)
		{
		if(aTopic != "nsPref:changed") return;
		var prefBranch = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.clrtabs.");
		switch (aData)
			{
			case "ppref":var ppref = prefBranch.getCharPref("ppref");
				ppref = ppref.split('~');
				colorfulTabs.tabColors = ppref;
				break;
			case "txtshadow":
				//enable disable the text glow via prefs.css
				colorfulTabs.txtshadow = prefBranch.getBoolPref("txtshadow");
				colorfulTabs.txtshadowcss();
				break;				
			case "uncoloredbgclr":	
				colorfulTabs.uncoloredbgclr = prefBranch.getCharPref("uncoloredbgclr");			
				break;
			case "tabtextclr":			
				colorfulTabs.tabtextclr = prefBranch.getCharPref("tabtextclr");			
				colorfulTabs.tabtextclrcss();
				break;		
			case "tablabelblink":
				//enable disable the text glow via prefs.css
				colorfulTabs.tablabelblink = prefBranch.getBoolPref("tablabelblink");
				colorfulTabs.tablabelblinkcss();
				break;
			case "minify":
				colorfulTabs.minify = prefBranch.getBoolPref("minify");
				colorfulTabs.setMinify();
				break;
			case "aggressive":
				//enable disable the text glow via prefs.css
				colorfulTabs.aggressive = prefBranch.getBoolPref("aggressive")?'important':'';
				colorfulTabs.opacitycss();
				colorfulTabs.currenttabcss();
				break;				
			case "fadedeg":
				colorfulTabs.fadedeg = prefBranch.getIntPref("fadedeg");				
				colorfulTabs.opacitycss();
				break;
			case "dispstack":
				//enable disable the text glow via prefs.css
				colorfulTabs.dispStack = prefBranch.getBoolPref("dispstack");
				colorfulTabs.dispstackcss();
				break;				
			case "currenttab":
				//enable disable the text glow via prefs.css
				colorfulTabs.currenttab = prefBranch.getBoolPref("currenttab");
				colorfulTabs.currenttabcss();
				break;
			case "currenttabclr":
				colorfulTabs.currenttabclr = prefBranch.getCharPref("currenttabclr");
				colorfulTabs.currenttabcss();
				break;
			case "scheme":
				colorfulTabs.scheme = prefBranch.getIntPref("scheme");
				colorfulTabs.initDomainContext();
				break;
			case "menu":
				colorfulTabs.initTabcontext();
				break;
			case "enabledomain":
				colorfulTabs.enabledomain=prefBranch.getBoolPref("enabledomain");
				break;
			case "dpref":
				colorfulTabs.dpref=prefBranch.getCharPref("dpref");
				colorfulTabs.dpref=colorfulTabs.dpref.split("`");
				break;
			case "standout":
				colorfulTabs.standout=prefBranch.getBoolPref("standout");
				colorfulTabs.setstandout();
				colorfulTabs.opacitycss();
				colorfulTabs.currenttabcss();
				break;
			case "advanced":
				colorfulTabs.adv=prefBranch.getBoolPref("advanced");
				if(colorfulTabs.adv==false)
					{
					colorfulTabs.satmax=95;
					colorfulTabs.satmin=30;
					colorfulTabs.lummax=78;
					colorfulTabs.lummin=68;
					colorfulTabs.sat=60;
					colorfulTabs.lum=73;
					}
				else
					{
					colorfulTabs.satmax=prefBranch.getIntPref("satmax");
					colorfulTabs.satmin=prefBranch.getIntPref("satmin");
					colorfulTabs.lummax=prefBranch.getIntPref("lummax");
					colorfulTabs.lummin=prefBranch.getIntPref("lummin");
					colorfulTabs.sat=prefBranch.getIntPref("sat");
					colorfulTabs.lum=prefBranch.getIntPref("lum");
					}
				break;
			case "satmax":
				colorfulTabs.satmax=Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getIntPref("extensions.clrtabs.satmax");
				break;
			case "satmin":
				colorfulTabs.satmin=Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getIntPref("extensions.clrtabs.satmin");
				break;
			case "lummax":
				colorfulTabs.lummax=Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getIntPref("extensions.clrtabs.lummax");
				break;
			case "lummin":
				colorfulTabs.lummin=Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getIntPref("extensions.clrtabs.lummin");
				break;
			case "sat":
				colorfulTabs.sat=Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getIntPref("extensions.clrtabs.sat");
				break;
			case "lum":
				colorfulTabs.lum=Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getIntPref("extensions.clrtabs.lum");
				break;
			case "bgpicpath":
				if(colorfulTabs.isSeamonkey)
					{
					colorfulTabs.setSeamonkeyContainerBg(true);
					}
				else
					{
					gBrowser.mTabContainer.style.backgroundImage="url("+prefBranch.getCharPref("bgpicpath")+")";
					gBrowser.mTabContainer.style.backgroundRepeat="repeat";
					}
				break;
			case "txtreverse":
				colorfulTabs.txtreverse = prefBranch.getBoolPref("txtreverse");
				colorfulTabs.reverseTxtColor();
				break;
			case "clrAllTabsPopPref":
				colorfulTabs.clrAllTabsPopPref = prefBranch.getBoolPref("clrAllTabsPopPref");
			colorfulTabs.setMIcolor();
				break;
			case "consolelog":
				colorfulTabs.ctdebug = prefBranch.getBoolPref("consolelog");				
				break;
			case "bgpic":
				var togglePic = prefBranch.getBoolPref("bgpic");
				if(togglePic)
					{
					if(colorfulTabs.isSeamonkey)
						{
						colorfulTabs.setSeamonkeyContainerBg(true);
						}
					else
						{
						gBrowser.mTabContainer.style.backgroundImage="url("+prefBranch.getCharPref("bgpicpath")+")";
						gBrowser.mTabContainer.style.backgroundRepeat="repeat";
						}
					}
				else
					{
					if(colorfulTabs.isSeamonkey)
						{
						colorfulTabs.setSeamonkeyContainerBg(false);
						}
					else
						{	//not seamonkey
						gBrowser.mTabContainer.style.backgroundImage="none";
						gBrowser.mTabContainer.style.backgroundRepeat="no-repeat";
						}
					}
				break;
			}
		}
	}
	
//generates a color by the domain
var colorfulTabsUrlListener =
	{
	QueryInterface: function(aIID)
		{
		if (aIID.equals(Components.interfaces.nsIWebProgressListener) || aIID.equals(Components.interfaces.nsISupportsWeakReference) || aIID.equals(Components.interfaces.nsISupports))
     			return this;
		throw Components.results.NS_NOINTERFACE;
		},
	onLocationChange: function(aProgress, aRequest, aURI)
		{
		var doc = aProgress.DOMWindow.document;
		var tab = gBrowser.mTabs[gBrowser.getBrowserIndexForDocument(doc)];
		if(tab == null)	//fix for docs in iFrames etc.
			{
			return;
			}
		if(colorfulTabs.clrSession.getTabValue(tab,"ctreadonly") == 1)
			{
			return;
			}
		var tabClr;
		try
			{
			var host = tab.linkedBrowser.contentDocument.location.host;
			if(host.length == 0){host="about:blank"};
			var url = tab.linkedBrowser.contentDocument.location;
			var testWWW = /^www\.(.+\..+)$/.exec(host);
			var colored = 0;			
			if(colorfulTabs.enabledomain)
				{
				for (var i=0;i<colorfulTabs.dpref.length;i++)
					{
					if(host.match(colorfulTabs.dpref[i].split("~")[0]))
						{
						tabClr = colorfulTabs.dpref[i].split("~")[1];
						colored = 1;//set the flag that the domain got a color
						}
					}
				if(colored == 0) //if  the domain didn't get a match, (preference - color unmatched domains)generate a default color?
					{
					tabClr = 'hsl('+Math.abs(colorfulTabs.clrHash(host))%360+','+colorfulTabs.sat+'%,'+colorfulTabs.lum+'%)';
					}
				}
			else
				{
				tabClr = 'hsl('+Math.abs(colorfulTabs.clrHash(host))%360+','+colorfulTabs.sat+'%,'+colorfulTabs.lum+'%)';
				}
			colorfulTabs.setColor(tab,tabClr);
			}
		catch (e)
			{
			var host = "about:blank"; // might not always be true, but this makes us ignore it.
			tabClr ='-moz-dialog'; //use fixed values for sat and lum for host. to do - will use userprefs later for them
			}
		},
	// For definitions of the remaining functions see XulPlanet.com
	onStateChange:function() { return 0;},
	onProgressChange: function() { return 0;},
	onStatusChange: function() { return 0;},
	onSecurityChange: function() { return 0;},
	onLinkIconAvailable: function() { return 0;}
	}
var colorfulTabsfrObserver = {

    register: function() {
        var observerService = Components.classes["@mozilla.org/observer-service;1"]
            .getService(Components.interfaces.nsIObserverService);
        observerService.addObserver(colorfulTabsfrObserver, "sessionstore-windows-restored", false);
    },

    observe: function(subject, topic, data) {
        switch (topic) {
            case 'sessionstore-windows-restored':
                // do stuff
				//colorfulTabs.setMinify();
				colorfulTabs.frInit();
				//ObserverTest.unregister();
                break;
            case 'user-interaction-inactive':
                // do stuff
                break;
            case 'user-interaction-active':
                // every 5 seconds and immediately when user becomes active
                //alert("active"); 
                break;			
        }
    },

    unregister: function() {
        var observerService = Components.classes["@mozilla.org/observer-service;1"]
            .getService(Components.interfaces.nsIObserverService);
        observerService.removeObserver(colorfulTabsfrObserver, "sessionstore-windows-restored");
    }
}
//adds domains to the preference
var colorfulTabsOptions1 = {
	tweakspaneload:function() {
		//for future
		document.getElementById('currenttabenable').disabled = document.getElementById('aggressiveenable').checked;
		//document.getElementById('currenttabtextenable').disabled = document.getElementById('aggressiveenable').checked;
		document.getElementById('currentclrselector').disabled = document.getElementById('aggressiveenable').checked;
		//document.getElementById('currenttextclrselector').disabled = document.getElementById('aggressiveenable').checked;
	},
	preftxtshadow:function(state)
		{
		//for future
	},
	addDomain:function(){
		var i = document.getElementsByAttribute("rel","domain").length;
		var a = document.createElement('row');
		var b =  document.createElement('textbox');
		b.setAttribute("id","domain"+i);
		b.setAttribute("rel","domain");
		b.setAttribute("preference-editable","true");
		b.setAttribute("onchange","colorfulTabsOptions.saveDomains");
		var bb =document.createElement('textbox');
		bb.setAttribute("id","clrTxt"+i);
		bb.setAttribute("rel","color");
		bb.setAttribute("preference-editable","true");
		bb.setAttribute("onchange","colorfulTabsOptions.saveDomains");
		var c =  document.createElement('colorpicker');
		c.setAttribute("id","clrPkr"+i);
		c.setAttribute("type","button")
		c.setAttribute("palettename","standard")
		c.setAttribute("preference-editable","true");
		c.setAttribute("onchange","colorfulTabsOptions.saveDomains");
		var d =  "document.getElementById('clrTxt"+i+"').value=this.color"
		c.setAttribute("onchange",d)
		a.appendChild(b)
		a.appendChild(bb)
		a.appendChild(c)
		document.getElementById("domainrows").appendChild(a)
		},
		
	//modifies the ct options box
	changeUI:function(el,prompt)
		{
		var elsd = document.getElementById('domainrows').getElementsByAttribute("rel","domain");
		var elsc = document.getElementById('domainrows').getElementsByAttribute("rel","color");
		var elsk = document.getElementById('domainrows').getElementsByTagName("colorpicker");
		var clrScheme =  Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.clrtabs.").getIntPref("scheme");
		if(!el.checked || (clrScheme != 2))
			{
			if(prompt && clrScheme != 2)
				{
				alert("Please select \"Generate colors by Domain hostname\" under \"General\" and click  \"OK\".")
				el.removeAttribute("checked");
				}
			for(var i=0;i<elsd.length;i++)
				{
				elsd[i].setAttribute("disabled","true");
				elsc[i].setAttribute("disabled","true");
				elsk[i].setAttribute("disabled","true");
				}
			}
		else
			{
			for(var i=0;i<elsd.length;i++)
				{
				elsd[i].removeAttribute("disabled");
				elsc[i].removeAttribute("disabled");
				elsk[i].removeAttribute("disabled");
				}
			}
		},
		
	//sets domain prefs
	setDomainPref:function()
		{
		//Appends domain rows depending on preferences during preferencepane onload
		var a,b,c,bb,d,domain,color;
		var dpref = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.clrtabs.").getCharPref("dpref");
		if(!dpref.length) return;
		dpref = dpref.split("`");
		for(var i = 0 ; i < dpref.length ; i++)
			{
			domain = dpref[i].split("~")[0]
			color =dpref[i].split("~")[1];
			a = document.createElement('row');
			b =  document.createElement('textbox');
				b.setAttribute("value",domain);
				b.setAttribute("id","domain"+i);
				b.setAttribute("rel","domain");
				b.setAttribute("onchange","colorfulTabsOptions.saveDomains");
			bb =document.createElement('textbox');
			bb.setAttribute("value",color)
			bb.setAttribute("id","clrTxt"+i);
			bb.setAttribute("rel","color");
			bb.setAttribute("onchange","colorfulTabsOptions.saveDomains");
			c =  document.createElement('colorpicker');
				c.setAttribute("id","clrPkr"+i);
				c.setAttribute("color",color);
				c.setAttribute("type","button")
				c.setAttribute("onchange","colorfulTabsOptions.saveDomains");
				d =  "document.getElementById('clrTxt"+i+"').value=this.color"
				c.setAttribute("palettename","standard");
				c.setAttribute("onchange",d);
			a.appendChild(b)
			a.appendChild(bb)
			a.appendChild(c)
			try{document.getElementById("domainrows").appendChild(a)}
			catch(e){				
				colorfulTabs.cl('Error in setDomainPref: '+e);
				}
			}
		return true;
		},
	setPalette:function()
		{
		dump('palette');
		//Appends domain rows depending on preferences during preferencepane onload
		var ppref = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.clrtabs.").getCharPref("ppref");
		
		var pprefUI = document.getElementById("palettecolors").getElementsByTagName("button");
		ppref = ppref.split("~");
		for(var i = 0 ; i < ppref.length ; i++)
			{
			try{			
				pprefUI[i].setAttribute('paletteclr',ppref[i]);
				pprefUI[i].setAttribute('style',"background-color:" + ppref[i]);
				}
			catch(e){				
				colorfulTabs.cl('Error in setPalette: '+e);
				}
			}
		return true;
		},
	//sets the text color
	setTxtClr:function(id)
		{
		var clr = document.getElementById("clrPkr"+id).color;
		document.getElementById("clrTxt"+id).value = clr;
		document.getElementById("clrPkr"+id).color = clr;
		},
		
	//resets ct prefs
	resetPref:function()
		{
		var ctPref = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
		//	try because of http://developer.mozilla.org/en/docs/Preferences_System:preference
		//	https://developer.mozilla.org/en/Preferences_System/preference>> methods throws exception if not a user value
		try
			{
			try
				{
				ctPref.clearUserPref("extensions.clrtabs.advanced");
				}
			catch(e)
				{};
			adv = ctPref.getBoolPref('extensions.clrtabs.advanced')
			colorfulTabsOptions1.adv_toggle_state(adv);	//
			document.getElementById('advenable').checked = adv;
			}
		catch(e)
			{			
			colorfulTabs.cl('Error in resetPref: '+e);
			}
			
		var scheme = ctPref.getIntPref("extensions.clrtabs.scheme")
		if(scheme == 1)
			{
			try{ctPref.clearUserPref("extensions.clrtabs.satmin");}catch(e){};
			try{ctPref.clearUserPref("extensions.clrtabs.satmax");}catch(e){};
			try{ctPref.clearUserPref("extensions.clrtabs.lummin");}catch(e){};
			try{ctPref.clearUserPref("extensions.clrtabs.lummax");}catch(e){};
			}
		if(scheme == 2)
			{
			try{ctPref.clearUserPref("extensions.clrtabs.sat");}catch(e){};
			try{ctPref.clearUserPref("extensions.clrtabs.lum");}catch(e){};
			}
		},
		
	//validates values
	val:function(txtbox)
		{
		var test = txtbox.value
		if(isNaN(parseInt(txtbox.value)) || 0  > test || test > 100 )
			{
			alert('Please provide a valid integer between 0 and 100.');
			}
		else
			{
			txtbox.value=parseInt(txtbox.value);
			}
		},
		
	//initializes adv prefs
	advPrefInit:function()
		{
		colorfulTabsOptions1.adv_toggle_state(document.getElementById('advenable').checked,1);
		},
		
	//detects when adv prefs have been toggled
	adv_toggle_state:function(checked,caller)
		{
		var scheme = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getIntPref("extensions.clrtabs.scheme");
		if(scheme == 3 || scheme == 0)
					{
					document.getElementById('advenable').style.setProperty("visibility", 'hidden' ,'important');
					var altLabel = document.createElement('label');
					var altLabel2 = document.createElement('label');
					var txt = document.createTextNode("Advanced Preferences are only available for random or domain based coloring.");
					var txt2 = document.createTextNode("You will need to save the options before this setting will become available.");
					altLabel.appendChild(txt);
					altLabel2.appendChild(txt2);
					var refEl = document.getElementById('advenable');
					refEl.parentNode.insertBefore(altLabel2,refEl);
					refEl.parentNode.insertBefore(altLabel,refEl);
					}
		else
			{
			document.getElementById('advenable').style.setProperty("visibility", 'visible' ,'important');
			}
		try
			{
			if(checked)
				{
				if(scheme == 1)
					{
					document.getElementById('adv_group').style.setProperty("visibility", 'visible' ,'important');
					}
				if(scheme == 2)
					{
					document.getElementById('adv_group2').style.setProperty("visibility", 'visible' ,'important');
					}
				}
			else
				{
				if(scheme == 1)
					{
					document.getElementById('adv_group').style.setProperty("visibility", 'hidden' ,'important');
					}
				if(scheme == 2)
					{
					document.getElementById('adv_group2').style.setProperty("visibility", 'hidden' ,'important');
					}
				}
			}
		catch(e){colorfulTabs.cl(e);}
		return true;
		},
		
	//sets sat and lum
	setSatLum:function()
		{
		// validation before saving
		var scheme = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getIntPref("extensions.clrtabs.scheme");
		if(Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch).getBoolPref("extensions.clrtabs.advanced") == true)
			{
			if(scheme==1)
				{
				var satmax=document.getElementById('satmax');
				var satmin=document.getElementById('satmin');
				var lummax=document.getElementById('lummax');
				var lummin=document.getElementById('lummin');
				if(satmin.value >= satmax.value  || lummin.value >= lummax.value ||  satmin.value > 100  || satmax.value > 100  || lummin.value > 100 || lummax.value > 100 )
					{
					alert("Maximum values should be greater than minimum values chosen.\nValues shouldn't be greated than 100.");
					return false;
					}
				else
					{
					return true;
					}
				}
			if(scheme==2)
				{
				var sat=document.getElementById('sat');
				var lum=document.getElementById('lum');
				if(sat>100 || lum>100)
					{
					alert('Maximum values should not be greater than 100.');
					return false;
					}
				}
			}
		else {return;}
		},
		
	//browse for a bg image
	browsebgnd:function()
		{
		const nsIFilePicker = Components.interfaces.nsIFilePicker;
		var fp = Components.classes["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
		fp.init(window, "Dialog Title", nsIFilePicker.modeOpen);
		fp.appendFilters(nsIFilePicker.filterImages);
		var rv = fp.show();
		if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace)
			{
			var file = fp.file;
			// Get the path as string. Note that you usually won't
			// need to work with the string paths.
			//var path = fp.file.path;
			var path = fp.fileURL.spec;
			// work with returned nsILocalFile...
			document.getElementById('image-path').value=path;
			document.getElementById("clrBgPicPath").value = path;
			}
		},
		
	//load prefpane
	clrPrefPaneLoad:function(event)
		{
		document.getElementById('image-path').disabled=!(document.getElementById('clrTabBgnd').checked);
		document.getElementById('browseBgnd').disabled=!(document.getElementById('clrTabBgnd').checked);
		}
}