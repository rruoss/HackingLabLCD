var delim = "_#$%_";

var CookieListBox;
var DomainsListBox;

var showDomainsText;
var showCookiesTextBox;

var EditCookieButton;
var AddCookieLink;

var CookieOperationsRow;
var AddCookieControlsRow;

//cookie details controls
var CookieName;
var CookieValue;
var CookieDomain;
var CookieCreationTime;
var CookiePath;
var CookieIsSecure;
var CookieIsSession;
var CookieHttpOnly;

var dateControl;
var timeControl;
var dateRow;
var timeRow;
//var liveCookieFilter;
var numberOfLiveEntries;
var myCookieListBox;
var monitorCookiesListBox;

var facebook_url ="http://www.facebook.com/plugins/like.php?href=http%3A%2F%2Fwww.facebook.com%2Fpages%2FAdvanced-Cookie-Manager-Addon-For-Firefox%2F194360817277515&send=false&layout=button_count&width=100&show_faces=true&font&colorscheme=light&action=like&height=20";

Components.utils.import("resource://gre/modules/Services.jsm");

const clipboardHelper = Components.classes["@mozilla.org/widget/clipboardhelper;1"].getService(Components.interfaces.nsIClipboardHelper);
const prompt = Services.prompt;

var cookiemgr = new CookieManager();
//var myListenerCookie = new CookieListener();    

function CookieManager () 
{
    this.cookieMgrDoc = document;
    this.nsiCookieManager = undefined;
    this.prefsBranch = undefined;
}


CookieManager.prototype.onLoad = function()
{
	//show facebook like button
	document.getElementById('flike').src = facebook_url;

	//initialize
    DomainsListBox = document.getElementById("domains");
    CookieListBox = document.getElementById("cookies");
    myCookieListBox = CookieListBox;
    showDomainsText = document.getElementById("showDomains");
    showCookiesTextBox = document.getElementById("showCookies");
    monitorCookiesListBox = document.getElementById("livecookienames");
    
//    this.updateCookieMonitoringStatus();
    //Cookie Details Grid Control

    CookieName          = document.getElementById("Name");
    CookieValue         = document.getElementById("Value");
    CookieDomain        = document.getElementById("Domain");    
    CookiePath          = document.getElementById("Path");        
    CookieIsSecure      = document.getElementById("isSecure");
    CookieIsSession      = document.getElementById("isSession");    
    CookieHttpOnly      = document.getElementById("httpOnly");
    CookieCreationTime  = document.getElementById("CookieCreationTime");

    EditCookieButton    = document.getElementById("EditCookie");
    
    CookieOperationsRow     = document.getElementById("cookieOperationsRow");
    AddCookieControlsRow    = document.getElementById("addCookieControlsRow");
    AddCookieControlsRow.hidden = true;
    numberOfLiveEntries     = document.getElementById("numberOfLiveEntries");
    dateControl = document.getElementById("date");
    timeControl = document.getElementById("time");
    
    dateRow = document.getElementById("dateRow");
    timeRow = document.getElementById("timeRow");
    
    this.getNsiCookieManager();
    this.register();
	
	if (this.getBoolPreference("import.onstartup"))
	{
		if(this.getBoolPreference("import.onstartup.delete-all-cookies"))
		{
			this.nsiCookieManager.removeAll();
		}
		var fileName =  this.getStringPreference("import.onstartup.filename")
		if (fileName == null || fileName == "")
		{
			prompt.alert(null, "Cookie Manager", "Invalid backup file name. Skipping restore on startup");
		}
		else
		{
			var localFile = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsILocalFile);
			localFile.initWithPath(fileName);
			
			if(localFile.exists() == false)
			{
				prompt.alert(null, "Cookie Manager", "	Restore cookies on startup failed.\nInvalid input file : " +fileName + "\n\nSkippping restore cookies on startup");
				return;
			}
			
			this.importCookiesFromFile(localFile);
			
		}
	}
    this.populateCookiesDialog(false);
 
    cookiemgr.addCopyListnersToListBoxes();
    
    this.showHideImportOnStartupFileName(this.getBoolPreference("import.onstartup"));
    
    
};

CookieManager.prototype.populateCookiesDialog = function (PreserveState)
{    
	if (PreserveState == undefined)
	{
		PreserveState = false;
	}

	var FullListOfDomains = this.GetDomains();
	var Domains = this.FilterDomains(FullListOfDomains);
    
	var prevState = DomainsListBox.selectedIndex;
	var tempDomain = "";
	
	//Clear items
	this.clearListBox(DomainsListBox);
	
	//populate items
	for(var i=0; i < Domains.length; i++)
	{
		//Remove duplicates
		if (Domains[i] != tempDomain)
		{
			tempDomain = Domains[i];
    		DomainsListBox.appendItem(Domains[i], Domains[i]);
		}
	}

	//select default or the previous item
	if ( PreserveState == false || prevState < 0)
	{
		prevState = 0;
	}
    //if the prevStatue is > row count, select last row
	else if (prevState >= DomainsListBox.getRowCount())
    {
        prevState = DomainsListBox.getRowCount() -1;
    }

	//To preserve cookie selected state, send it to displayCookes function.
	var prevSelectedCookieIndex = CookieListBox.selectedIndex;

    if (DomainsListBox.getRowCount() > 0)
    {
        DomainsListBox.ensureIndexIsVisible(prevState);
        DomainsListBox.selectedIndex = prevState;
        
        this.displayCookies(PreserveState, prevSelectedCookieIndex);
    }
    else
    {
        this.clearListBox(CookieListBox);
        this.setCookieFormData("");
    }

};

CookieManager.prototype.CloseDialog = function()
{
    this.unregister();
 	window.close();
};

CookieManager.prototype.MinimizeDialog = function()
{
	window.minimize();
};

CookieManager.prototype.displayCookies = function(PreserveState, prevSelectedCookieIndex)
{
	//if no domain is selected, skip it
	if (DomainsListBox.selectedIndex == -1)
	{
		return;
	}

	if (PreserveState == undefined)
	{
		PreserveState = false;
	}

	var prevCookieIndex = prevSelectedCookieIndex == undefined ? (CookieListBox.selectedIndex != -1 ? CookieListBox.selectedIndex : 0) : prevSelectedCookieIndex;
	
    //clear list box
    this.clearListBox(CookieListBox);

	var selectedDomains = DomainsListBox.selectedItems;
	var cookiesArray = null;
    if (selectedDomains != null)
    {
		for (var iCounter=0;  iCounter < selectedDomains.length; iCounter++)
		{
			var selectedHost = selectedDomains[iCounter].value;
			
			if(iCounter == 0)
			{
				cookiesArray = this.getCookiesFromHost(selectedHost);
			}
			else
			{
				cookiesArray = cookiesArray.concat(this.getCookiesFromHost(selectedHost));
			}
		}
			
		var filteredCookiesArray = showCookiesTextBox.value != "" ? this.filterCookies(cookiesArray) : cookiesArray;


		if(filteredCookiesArray == null || filteredCookiesArray.length <= 0)
		{
			this.setCookieFormData("");
			return;
		}

		this.updateCookiesListBox(filteredCookiesArray, selectedHost);
	}
	if (!(PreserveState == true && prevCookieIndex > 0 && CookieListBox.getRowCount() > prevCookieIndex))
	{
		prevCookieIndex = 0;	
	}
	if (CookieListBox.getRowCount() == 0)
	{
//	   this.populateCookiesDialog();
    }
	CookieListBox.ensureIndexIsVisible( prevCookieIndex );
	CookieListBox.selectedIndex = prevCookieIndex;
}


CookieManager.prototype.updateCookiesListBox = function(nsiCookiesArray, host)
{
    var cookiesDataArray =  this.getSortedCookiesData(nsiCookiesArray);
	for (var cookieIndex in cookiesDataArray)
	{
 	    var cookie = cookiesDataArray[cookieIndex];
 	    
      //dont show cookies if the show-expired-cookies is false and the cookie has expired
        if ((!this.getBoolPreference("show-expired-cookies")) && (cookie.expires != 0 && cookie.expires * 1000 < (new Date()).getTime()))
        {
            continue;   
        }

		// create the new elements 
		var newListItem = document.createElement("listitem");
		var newCell1 = document.createElement("listcell"); 
		var newCell2 = document.createElement("listcell");
        
		newCell1.setAttribute("label",cookie.name);
		newCell2.setAttribute("label",cookie.value);
		
		newListItem.setAttribute("value",cookie.host+delim+cookie.name+delim+cookie.path);

		newListItem.appendChild(newCell1);
		newListItem.appendChild(newCell2);

        if (cookie.expires != 0 && cookie.expires * 1000 < (new Date()).getTime())
        {
            newListItem.setAttribute("style", "color: red;");
        }

		CookieListBox.appendChild(newListItem);
	}
};

CookieManager.prototype.getSortedCookiesData = function(nsiCookiesArray)
{
    var cookiesArray = new Array();
    var counter = 0;
	for (var cookieIndex in nsiCookiesArray)
	{
	   var cookie = nsiCookiesArray[cookieIndex];
	   //cookiesArray[counter++] = cookie.name + delim + cookie.value + delim + cookie.host+delim + cookie.path+delim + cookie.isSecure;
	   cookiesArray[counter] = new Array(2);
	   cookiesArray[counter][0] = cookie.name;
	   cookiesArray[counter][1] = cookie
	   counter++;
    }
    cookiesArray.sort();
    var sortedNsiCookiesArray = new Array();
    counter = 0;
    for (var cookieIndex in cookiesArray)
	{
	   //ignore [0]
 	    sortedNsiCookiesArray[counter++] = cookiesArray[cookieIndex][1];
    }
    return sortedNsiCookiesArray;
};

CookieManager.prototype.ShowCookieDetails = function()
{
    if (myCookieListBox == undefined)
    {
        return;
    }

	if(myCookieListBox.selectedCount != 1)
	{
		this.showHideCookieDetailsGroupBox("collapse");
	}
	else
	{
		this.showHideCookieDetailsGroupBox("visible");
	}
	if (myCookieListBox.selectedIndex != -1)
	{
        var cookieDomainAndName = myCookieListBox.selectedItem.value.split(delim);
        var cookie = this.getCookie(cookieDomainAndName[0],cookieDomainAndName[1],cookieDomainAndName[2]);
        
        this.setCookieFormData(cookie);

        //hide add cookie controls row and show cookie controls row
        CookieOperationsRow.hidden = false;
        AddCookieControlsRow.hidden = true;
        
        //disable Edit buttons
        EditCookieButton.disabled = true;
	}
};

CookieManager.prototype.ChangeCookie = function(action)
{
	var Domain = CookieDomain.value;
	var Name = CookieName.value;
	var Value = CookieValue.value;
	
	//check mandatory values
	if (Domain == "" || Name == "" || Value =="")
	{
	    prompt.alert(null, "Cookie Manager", "Please fill Domain, Name and Value fields properly and try again");
        return;
    }
	
   	var Path = CookiePath.value;
	var IsSecure = (CookieIsSecure.value.toLowerCase().trim() == "true")? true : false;
	var IsSession = (CookieIsSession.value.toLowerCase().trim() == "true")? true : false;
	var httpOnly = (CookieHttpOnly.value.toLowerCase().trim() == "true")? true : false;

    //set default values to path and secure (if not present)
    Path = Path == "" ? "\/" : Path;
        
	if (action.toLowerCase() == "delete")
	{
        if (this.getBoolPreference("confirm-delete"))
        {
            if (false == prompt.confirm(null, "Cookie Manager", "Are you sure you want to delete \""+Name+"\" cookie?"))
            {
                return;
            }
        }
        this.deleteCookie(Domain, Name, Path);
		this.displayCookies(false);
	}
	else
	{

        var newDate = dateControl.dateValue;
        
        //set time explicitly        
        newDate.setHours(timeControl.hour);
        newDate.setMinutes(timeControl.minute);
        newDate.setSeconds(timeControl.second);

        var Expires = newDate.getTime();

		//if it is a session cookie, don't send the last param as nsiCookieManager2.add is not 
		// ignoring the expiry param when nIsSession on is true
		if (IsSession)
		{
			//set expiry to 100000000000 seconds from now (almost 4 years)
			Expires = new Date().getTime() + 100000000000;
		}
        else if(Expires < (new Date().getTime()))
        {
            var c = prompt.confirm(null, "Cookie Manager", "Past date is given as \"Expiry\" date. Continuing will DELETE cookie."); 
            if (c != true)
            {
                return;   
            } 
        }
		this.nsiCookieManager.add(Domain, Path, Name, Value, IsSecure,httpOnly, IsSession, Expires / 1000);
		if (action.toLowerCase() == "edit")
		{
            this.displayCookies(true);
        }
        else
        {
            this.displayCookies(false);
        }
	}	
	

};

CookieManager.prototype.deleteCookie = function(Domain,Name, Path)
{

	this.nsiCookieManager.remove(Domain,Name, Path,false);
	//this.displayCookies(true);
};

CookieManager.prototype.GetDomains = function ()
{
	var domainsList = new Array();
	var tempDomain = "";
	var prevDomain = "";
	var counter = 0;

    //loop through each cookie and prepare domains list
	for (var e = this.nsiCookieManager.enumerator; e.hasMoreElements();) 
	{
	   //get all cookies
		var cookie = e.getNext().QueryInterface(Components.interfaces.nsICookie2);

		tempDomain = cookie.host;
		
		//check whether "active tab only" checked in...
		//remove the preceeding . (if exists)
		if (tempDomain.charAt(0) == ".")
		{
			tempDomain = tempDomain.substr(1,tempDomain.length-1);	
		}

		if (tempDomain != prevDomain)
		{
			domainsList[counter++] = tempDomain; // + delim + cookie.host;
			prevDomain = tempDomain;
		}

	}
	//Sort domains
	domainsList.sort();
	return domainsList;
};

CookieManager.prototype.FilterDomains = function(domainsList)
{
    var searchDomainsText = showDomainsText.value;
    //implement , seperated values
    if (searchDomainsText == "" || searchDomainsText.length <= 0)
    {
        return domainsList;
    }
    else
    {
    	return this.getMatchingDomainsList (domainsList, searchDomainsText);
    }
}

CookieManager.prototype.getMatchingDomainsList = function(masterList, matchText)
{
    var matchingDomainsList = new Array();
    var counter = 0;
 
    for (var index in masterList) 
    {
        var listItem = masterList[index];
        if (listItem.indexOf(matchText) != -1)
        {
            matchingDomainsList[counter++] = listItem;
        }
    }
    return matchingDomainsList;
};


CookieManager.prototype.getCurrentDomain = function()
{
	var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
	var mainWindow = wm.getMostRecentWindow("navigator:browser");

	var currentURI = mainWindow.getBrowser().currentURI;
	if (currentURI.spec == "about:blank" || currentURI.spec == "about:home")
	{
        return "";
	}
	return currentURI.host;
}

CookieManager.prototype.getCookiesFromHost = function(host)
{
	var cookiesEnum = this.nsiCookieManager.getCookiesFromHost(host+"");

    var nsiCookieArray = [];
    var counter = 0;
    
    while (cookiesEnum.hasMoreElements())
    {
        var cookie = cookiesEnum.getNext().QueryInterface(Components.interfaces.nsICookie2);
        
        //discard parent domain cookies
        if (cookie.host == host || cookie.host == "."+host)
        {
              nsiCookieArray[counter++] = cookie;
        }
    }
    return nsiCookieArray;
};


CookieManager.prototype.filterCookies = function(nsiCookieArray)
{
    if (nsiCookieArray == null || nsiCookieArray.lenght <=0)
    {
        return null;
    }
    var cookieFilterText = showCookiesTextBox.value;
 
    //return input as it is if filter text is empty  
    if (cookieFilterText == undefined || cookieFilterText.length <= 0)
    {
        return nsiCookieArray;    
    }
    
    var filteredNsiCookieArray = new Array();
    var counter = 0;
    for (var cookieIndex in nsiCookieArray)
    {
        var cookie = nsiCookieArray[cookieIndex];
        
        if (cookie.name.indexOf(cookieFilterText) != -1)
        {
            filteredNsiCookieArray[counter++] = cookie;
        }
    }

    return filteredNsiCookieArray;
};

CookieManager.prototype.getCookie = function(host, cookieName, cookiePath)
{
    var nsiCookieArray = this.getCookiesFromHost(host);
    var counter = 0;
    
    for (var cookieIndex in nsiCookieArray)
    {
        var cookie = nsiCookieArray[cookieIndex];

        if (cookie.name == cookieName && cookie.path == cookiePath)
        {
            return cookie;
        }
    }
    
    return "";
};

CookieManager.prototype.clearListBox = function(listBox)
{
 	for (var i= listBox.getRowCount() -1; i>=0; i--)
	{
		listBox.removeItemAt(i);
	}
};

CookieManager.prototype.setEditCookieButtonStatus = function(status)
{
    if (status == undefined)
    {
        status = false;
    }

    if (CookieIsSession.value == "false")
    {
            dateRow.style.visibility = "visible";
            timeRow.style.visibility = "visible";
    }
    else
    {
            dateRow.style.visibility = "hidden";
            timeRow.style.visibility = "hidden";
    }    
    //set it to !status as you are setting disable property
    EditCookieButton.disabled = !status;
};


CookieManager.prototype.showAddCookieForm = function()
{
    this.setCookieFormData("default");
    
    AddCookieControlsRow.hidden = false;
    CookieOperationsRow.hidden = true;
};

CookieManager.prototype.setCookieFormData = function(cookie)
{
    if (cookie == undefined || cookie == "")
    {
        //document.getElementById("CookieDetailsGrid").hidden = true;
        
        CookieCreationTime.value    = "";
        CookieDomain.value          = "";
        CookieName.value            = "";
        CookieValue.value           = "";
        CookiePath.value            = "";
        CookieIsSecure.value        = false;
        CookieIsSession.value        = false;
        CookieHttpOnly.value        = true;
        dateControl.dateValue = new Date(0);
        timeControl.dateValue = new Date(0);

        dateRow.style.visibility = "hidden";
        timeRow.style.visibility = "hidden";

    }
    else if(cookie == "default")
    {
        document.getElementById("CookieDetailsGrid").hidden = false;

        //Don't clean up the domain to maintain the previous domain
        //CookieDomain.value          = "";
        CookieCreationTime.value          = "";
        CookieName.value            = "";
        CookieValue.value           = "";
        CookiePath.value            = "";
        CookieIsSecure.value     = false;
        CookieIsSession.value        = false;
        CookieHttpOnly.value        = true;
        
        CookieDomain.setAttribute("style", "color: black;");
        CookieName.setAttribute("style", "color: black;");
        CookiePath.setAttribute("style", "color: black;");
        
        CookieName.focus();
        var time = new Date().getTime() + 86400000; //add a day
        dateControl.dateValue = new Date(time);
        timeControl.dateValue = new Date(time);

        //set read only properties
        CookieDomain.readOnly = false;
        CookieName.readOnly = false;
        CookiePath.readOnly = false;

        //show defalt text
        CookiePath.value ="/";
        dateRow.style.visibility = "visible";
        timeRow.style.visibility = "visible";
        
    }
    else
    {
        document.getElementById("CookieDetailsGrid").hidden = false;

        var date = new Date();
        date.setTime(cookie.creationTime / 1000);

        CookieCreationTime.value    = date.toLocaleString();
        CookieDomain.value          = cookie.host;
        CookieName.value            = cookie.name;
        CookieValue.value           = cookie.value;
        CookiePath.value            = cookie.path;
        CookieIsSecure.value        = cookie.isSecure;
        CookieIsSession.value       = cookie.expires == 0 ? true : false;
        CookieHttpOnly.value        = cookie.isHttpOnly;
        
        CookieDomain.setAttribute("style", "color: grey;");
        CookieName.setAttribute("style", "color: grey;");
        CookiePath.setAttribute("style", "color: grey;");

        if (cookie.expires != 0)
        {
            date.setTime(cookie.expires * 1000);
            dateRow.style.visibility = "visible";
            timeRow.style.visibility = "visible";
        }
        else
        {
            date = new Date();
            dateRow.style.visibility = "hidden";
            timeRow.style.visibility = "hidden";
        }    
            dateControl.dateValue = date;
            timeControl.dateValue = date;

        //set read only properties
        CookieDomain.readOnly = true;
        CookieName.readOnly = true;
        CookiePath.readOnly = true;
    }
};

CookieManager.prototype.deleteDomainMenuAction = function()
{

	var selectedDomains = DomainsListBox.selectedItems;
	
    if (selectedDomains != null)
    {
		for (var iCounter=0;  iCounter < selectedDomains.length; iCounter++)
		{
			this.deleteCookiesFromDomain(selectedDomains[iCounter].value);
		}

	    this.populateCookiesDialog(true);
    }
};

CookieManager.prototype.deleteDomainKeyAction = function(e)
{
    if (e != undefined && e.keyCode != undefined)
    {
        if (e.keyCode == 46)
        {
            this.deleteDomainMenuAction();        
        }
    }
};

CookieManager.prototype.deleteCookieKeyAction = function(e)
{
    if (e != undefined && e.keyCode != undefined)
    {
        if (e.keyCode == 46)
        {
            this.deleteCookieMenuAction();
        }
    }
};


CookieManager.prototype.deleteCookieMenuAction = function()
{
	var selectedCookies = myCookieListBox.selectedItems;
	
    if (selectedCookies != null)
    {
		for (var iCounter=0;  iCounter < selectedCookies.length; iCounter++)
		{
			var cookieData = selectedCookies[iCounter].value.split(delim);
			if (this.getBoolPreference("confirm-delete"))
			{
				if (false == prompt.confirm(null, "Cookie Manager", "Are you sure you want to delete \""+cookieData[1]+"\" cookie?"))
				{
					continue;
				}
			}
			this.deleteCookie(cookieData[0], cookieData[1], cookieData[2]);
		}
		this.displayCookies(true);
	}
};

CookieManager.prototype.deleteCookiesFromDomain = function(domain)
{
    if (this.getBoolPreference("confirm-delete"))
    {
        if (false == prompt.confirm(null, "Cookie Manager", "Are you sure you want to delete all cookies from \""+domain+"\"?"))
        {
            return;
        }
    }
    var nsiCookiesList = this.getCookiesFromHost(domain);
    for (var index in nsiCookiesList)
    {
        var nsiCookie = nsiCookiesList[index];
        this.deleteCookie(nsiCookie.host,nsiCookie.name, nsiCookie.path);
    }
};

CookieManager.prototype.clearAllCookies = function()
{
    if (this.getBoolPreference("confirm-delete"))
    {
        if (false == prompt.confirm(null, "Cookie Manager", "Are you sure you want to delete all cookies from all domains?"))
        {
            return;
        }
    }
    this.nsiCookieManager.removeAll();
    this.populateCookiesDialog(false);   
};

CookieManager.prototype.updateCookiesListBoxMonitor = function(subject, topic, data)
{
    if (subject == undefined)
    {
        return;
    }

    if (topic != "cookie-changed")
    {
        return;
    }

    if (!this.getBoolPreference("monitoring-enabled"))
    {
        return;
    }
    
    var cookie = subject.QueryInterface(Components.interfaces.nsICookie);
    
    //dont add cookie
    var liveCookieFilterValue = document.getElementById("liveCookieFilter").value;

    if (liveCookieFilterValue != undefined && liveCookieFilterValue != "" && cookie.host.indexOf(liveCookieFilterValue) == -1)
    {
        return;
    }
    
 		// create the new elements 
		var newListItem = document.createElement("listitem");
		var newCell1 = document.createElement("listcell"); 
		var newCell2 = document.createElement("listcell");
		var newCell3 = document.createElement("listcell");
		var newCell4 = document.createElement("listcell");

		newCell1.setAttribute("label",(new Date()).toLocaleString()+"  ");
		newCell2.setAttribute("label",data+"  ");
		newCell3.setAttribute("label",cookie.host+"  ");
		newCell4.setAttribute("label",cookie.name);
		
		newListItem.setAttribute("value",cookie.host+delim+cookie.name+delim+cookie.path);

		newListItem.appendChild(newCell1);
		newListItem.appendChild(newCell2);
		newListItem.appendChild(newCell3);
		newListItem.appendChild(newCell4);
		
        
        if (cookie.expires * 1000 < (new Date()).getTime())
        {
            newListItem.setAttribute("style", "color: red;");
        }

        if (monitorCookiesListBox.getRowCount() > 0)
        {
    		monitorCookiesListBox.insertBefore(newListItem, monitorCookiesListBox.getItemAtIndex(0));
        }
        else
        {
            monitorCookiesListBox.appendChild(newListItem);
        }
        cookiemgr.trimListBox(monitorCookiesListBox,
            cookiemgr.getIntPreference("monitoring-list-size") != -1 ? cookiemgr.getIntPreference("monitoring-list-size") : 500);
};   


CookieManager.prototype.trimListBox = function(ListBox, count)
{
    if (ListBox.getRowCount() >  count)
    {
            for (var i= ListBox.getRowCount() ; i > count; i--)
            {
                ListBox.removeItemAt(i - 1);
            }
    }
};

CookieManager.prototype.updateCookieMonitoringStatus = function() 
{

    if (this.getBoolPreference("monitoring-enabled"))
    {
        this.register();   
    }
    else
    {
        this.unregister();
    }
};


CookieManager.prototype.observe = function (subject, topic, data)
{
    this.updateCookiesListBoxMonitor (subject, topic, data);
};
    
CookieManager.prototype.register = function() {
    var cl = Components.classes['@mozilla.org/observer-service;1'].getService(Components.interfaces.nsIObserverService);
    if(cl != undefined)
    {
        cl.addObserver(this, "cookie-changed", false);
    }
};

CookieManager.prototype.unregister = function() {
    try
    {
        var cl = Components.classes['@mozilla.org/observer-service;1'].getService(Components.interfaces.nsIObserverService);
        cl.removeObserver(this,'cookie-changed');
    }
    catch(err)
    {
    }
};

CookieManager.prototype.handleTabChangeEvent = function()
{
	var selectedTab = document.getElementById("myTabs").selectedIndex;
    if (selectedTab == 0)
    {
        if (CookieListBox != undefined)
        {
            myCookieListBox = CookieListBox;
        }
		this.ShowCookieDetails();
		this.showHideCookieDetailsGroupBox ("visible");
    }
	else if (selectedTab == 1)
    {
        myCookieListBox = monitorCookiesListBox;
		this.ShowCookieDetails();
		this.showHideCookieDetailsGroupBox ("visible");
    }
	else 
	{
		this.showHideCookieDetailsGroupBox ("collapse");
	}
    
};

CookieManager.prototype.clearMonitorData = function()
{
    this.clearListBox(monitorCookiesListBox);
};

CookieManager.prototype.liveFilterHelp = function()
{
    prompt.alert(null, "Cookie Manager", "Filter works only for newly added cookies here after. \nPlease browse a few pages to see filtered domains only.");
};


CookieManager.prototype.getBoolPreference = function (preference)
{
    if (!this.prefsBranch)
    {   
        this.prefsBranch = this.getPrefsBranch();
    }

    return this.prefsBranch.getBoolPref(preference);
};

CookieManager.prototype.getIntPreference = function (preference)
{
    if (!this.prefsBranch)
    {   
        this.prefsBranch = this.getPrefsBranch();
    }
    
    if (this.prefsBranch.getPrefType(preference) == this.prefsBranch.PREF_INVALID)
    {
        return -1;
    }
    return this.prefsBranch.getIntPref(preference);
};

CookieManager.prototype.getStringPreference = function (preference)
{
    if (!this.prefsBranch)
    {   
        this.prefsBranch = this.getPrefsBranch();
    }
    
    if (this.prefsBranch.getPrefType(preference) == this.prefsBranch.PREF_INVALID)
    {
        return null;
    }
    return this.prefsBranch.getCharPref(preference);
};

CookieManager.prototype.getPrefsBranch = function ()
{
    // Get the "extensions.myext." branch
	var prefs = Services.prefs;
        
    return this.prefsBranch =  prefs.getBranch("extensions.cookiemgr.");
};

CookieManager.prototype.showOptionsDialog = function()
{
    var cookiemgr_options_window = window.openDialog("chrome://cookiemgr/content/options.xul","Cookie Manager Options", "chrome,resizable,modal");
};

CookieManager.prototype.showAboutDialog = function()
{
    var cookiemgr_about_window = window.openDialog("chrome://cookiemgr/content/about.xul","About Cookie Manager", "chrome,resizable,modal,centerscreen");
};

CookieManager.prototype.showFeedbackDialog = function()
{
    var cookiemgr_feedback_window = window.openDialog("chrome://cookiemgr/content/feedback.xul","Feedback", "chrome,resizable,modal,centerscreen");
};

CookieManager.prototype.getNsiCookieManager = function ()
{
    this.nsiCookieManager = Components.classes["@mozilla.org/cookiemanager;1"].getService(Components.interfaces.nsICookieManager2);
};


CookieManager.prototype.importCookies = function()
{

    var nsIFilePicker = Components.interfaces.nsIFilePicker;
    var fp = Components.classes["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
    fp.init(window, "Select Cookies file to import", nsIFilePicker.modeOpen);
    fp.appendFilters(nsIFilePicker.filterText | nsIFilePicker.filterAll);
    fp.filterIndex = 1;
    
    var res = fp.show();
    if (res != nsIFilePicker.returnCancel){
//        this.nsiCookieManager.importCookies(fp.file);
		this.importCookiesFromFile (fp.file);
	}
};

CookieManager.prototype.importCookiesFromFile = function(nsIlocalFile)
{
	if(nsIlocalFile.exists() == false)
	{
		prompt.alert(null, "Cookie Manager", "File doesn't exists to import cookies: " +nsIlocalFile.nativePath);
		return;
	}

	var inputStream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance(Components.interfaces.nsIFileInputStream);
	inputStream.init(nsIlocalFile,0x01,0,null);
	inputStream = inputStream.QueryInterface(Components.interfaces.nsILineInputStream);

	var line = {};

	var HOST        = 0;
	var DOMAIN      = 1;
	var PATH        = 2;
	var IS_SECURE   = 3; 
	var EXPIRY      = 4;
	var NAME        = 5;
	var VALUE       = 6;
	var IsSession = false;
	var dataFound;
	var counter = 0;
	do 
	{
		dataFound = inputStream.readLine(line);
		if (line.value == "")
		{
			continue;
		}
		var cookieData = line.value.split("\t");
		if (cookieData.length == 7)
		{
			
			var iExpiry = parseInt(cookieData[EXPIRY]);
			if (iExpiry == 0)
			{
				IsSession = true;           
				//As cookieManager.add is not ignoring expiry on session = true, set a future date to expiry
				iExpiry = new Date().getTime() + 100000000000;
			}
			else
			{
				IsSession = false;
			}

			//add(in AUTF8String aHost, in AUTF8String aPath, in ACString aName, in ACString aValue, in boolean aIsSecure, in boolean aIsHttpOnly, in boolean aIsSession, in PRInt64 aExpiry);
			this.nsiCookieManager.add(cookieData[HOST], cookieData[PATH], cookieData[NAME], cookieData[VALUE], (cookieData[IS_SECURE].toUpperCase() == "TRUE" ? true : false), false, IsSession, iExpiry);   
			counter++;
		}
	}while(dataFound);
	if (counter ==0)
	{
		prompt.alert(null, "Cookie Manager", "No cookies are imported. Please check your input file format.");
	}
	this.populateCookiesDialog(true);        
	inputStream.close();
}

CookieManager.prototype.exportAllCookies = function()
{

    var cookiesString = this.getAllCookiesAsStringInExportFormat();
    this.writeToFile(cookiesString);
};

CookieManager.prototype.exportCookiesOfADomain = function()
{
	var selectedDomains = DomainsListBox.selectedItems;
	var cookiesString = "";
    if (selectedDomains != null)
    {
		for (var iCounter=0;  iCounter < selectedDomains.length; iCounter++)
		{
			cookiesString = cookiesString + "\n" + this.getDomainCookiesAsStringInExportFormat(selectedDomains[iCounter].value);
		}
		
		if(cookiesString != "")
		{
			this.writeToFile(cookiesString);
		}
    }

};

CookieManager.prototype.getAllCookiesAsStringInExportFormat = function()
{
    var cookieInfo = "";
    //loop through each cookie and prepare domains list
	for (var e = this.nsiCookieManager.enumerator; e.hasMoreElements();) 
	{
	   //get all cookies
		var cookie = e.getNext().QueryInterface(Components.interfaces.nsICookie2);

		cookieInfo =  cookieInfo + "\r\n" + this.getCookieAsString(cookie); 
    }
    return cookieInfo;	

};

CookieManager.prototype.getDomainCookiesAsStringInExportFormat = function(domain)
{
    var cookieInfo = "";
    var cookiesArray = this.getCookiesFromHost(domain);
	for (var cookie in cookiesArray) 
	{
		cookieInfo =  cookieInfo + "\r\n" + this.getCookieAsString(cookiesArray[cookie]); 
    }
    return cookieInfo;	

};

CookieManager.prototype.getCookieAsString = function (cookie)
{
    return  cookie.host 
            + "\t" + new String(cookie.isDomain).toUpperCase()
			+ "\t" + cookie.path
			+ "\t" + new String(cookie.isSecure).toUpperCase()
			+ "\t" + cookie.expires
			+ "\t" + cookie.name
			+ "\t" + cookie.value;
};

CookieManager.prototype.writeToFile = function (data)
{
    try
    {
       var nsIFilePicker = Components.interfaces.nsIFilePicker;
        var fp = Components.classes["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
        fp.init(window, "Select Cookies file to export", nsIFilePicker.modeSave);
        fp.appendFilters(nsIFilePicker.filterText | nsIFilePicker.filterAll);
        fp.filterIndex = 1;
    
        var res = fp.show();
    	if (res == fp.returnOK || res == fp.returnReplace) {
            var outputStream = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance(Components.interfaces.nsIFileOutputStream);
            outputStream.init(fp.file, 0x02 | 0x08 | 0x20 , 0x666 ,0);
            outputStream.write(data, data.length);
            outputStream.close();
        }
    }catch(err)
    {}

}

CookieManager.prototype.showHideCookieDetailsGroupBox = function (visibility)
{
	document.getElementById("CookieDetailsGrid").style.visibility = visibility;
}

CookieManager.prototype.onCookieManagerTab = function ()
{
	if(myCookieListBox.selectedCount != 1)
	{
		this.showHideCookieDetailsGroupBox("collapse");
	}
	else
	{
		this.showHideCookieDetailsGroupBox("visible");
	}
}

CookieManager.prototype.onCookieMonitorTab = function ()
{
		this.showHideCookieDetailsGroupBox ("visible");
}

CookieManager.prototype.onSettingsTab = function ()
{
	this.showHideCookieDetailsGroupBox ("collapse");
}

CookieManager.prototype.showHideImportOnStartupFileName = function (status)
{
	if(status)
		document.getElementById("importonstartup_filename").style.visibility = "visible";
	else
		document.getElementById("importonstartup_filename").style.visibility = "hidden";
}


CookieManager.prototype.openURL = function (url)
{
	var nsioservice= Components.classes["@mozilla.org/network/io-service;1"].getService(Components.interfaces.nsIIOService);
	 
	var uri = nsioservice.newURI(url, null, null);
	 
	var eps = Components.classes["@mozilla.org/uriloader/external-protocol-service;1"].getService(Components.interfaces.nsIExternalProtocolService);
	 
	eps.loadURI(uri, null);
}

CookieManager.prototype.copyArrayToClipBoard = function (array)
{
    var textToCopy = "";
    for (item in array) {
	textToCopy = textToCopy + array[item] + "\r\n";
    }
    clipboardHelper.copyString (textToCopy);
}

CookieManager.prototype.copySelectedDomainsToClipBoard = function ()
{
    var selectedDomains = new Array();
    
    for (var i = 0; i< DomainsListBox.selectedCount; i++)
    {
	    selectedDomains[i] = DomainsListBox.getSelectedItem(i).value;
    }
    selectedDomains.sort();
    
    cookiemgr.copyArrayToClipBoard(selectedDomains);
}


CookieManager.prototype.copySelectedCookiesToClipBoard = function ()
{
	var selectedCookies = new Array();
	
	for (var i = 0; i< CookieListBox.selectedCount; i++)
	{
	    var cookieDomainAndName = CookieListBox.getSelectedItem(i).value.split(delim);
            var cookie = this.getCookie(cookieDomainAndName[0],cookieDomainAndName[1],cookieDomainAndName[2]);
	    selectedCookies[i] = cookie.name + "\t" + cookie.value;
	}
	selectedCookies.sort();

	cookiemgr.copyArrayToClipBoard(selectedCookies);
}

CookieManager.prototype.copyCookieDetailsToClipBoard = function ()
{
    var cookieDomainAndName = CookieListBox.selectedItem.value.split(delim);
    var cookie = this.getCookie(cookieDomainAndName[0],cookieDomainAndName[1],cookieDomainAndName[2]);
    var cookieDetails= "";
    
    var cookieDetails = "Creation Time : "	+ CookieCreationTime.value + "\r\n" +
		    "Domain : " 	+ CookieDomain.value + "\r\n" +
		    "Name : " 		+ CookieName.value + "\r\n" +
		    "Value : "		+ CookieValue.value + "\r\n" +
		    "Path : " 		+ CookiePath.value + "\r\n" +
		    "isHttpOnly : " 	+ CookieHttpOnly.value+ "\r\n" +
		    "isSecure : " 	+ CookieIsSecure.value + "\r\n" +
		    "isSession : "	+ CookieIsSession.value + "\r\n" +
		    "Expires On : "	+ dateControl.dateValue;

    clipboardHelper.copyString (cookieDetails );
}

CookieManager.prototype.addCopyListnersToListBoxes = function ()
{
    //add Ctrl + C listner to domains list box  
    var domainsListController = {
	supportsCommand : function(cmd){ return (cmd == "cmd_copy"); },
	isCommandEnabled : function(cmd){
	    if (cmd == "cmd_delete") return (DomainsListBox.selectedItem != null);
	    return false;
	},
	doCommand : function(cmd){
	    cookiemgr.copySelectedDomainsToClipBoard();
	},
	onEvent : function(evt){ }
    };
    
    //add Ctrl + C listner to cookies list box
    var cookiesListController = {
	supportsCommand : function(cmd){ return (cmd == "cmd_copy"); },
	isCommandEnabled : function(cmd){
	    if (cmd == "cmd_delete") return (CookieListBox.selectedItem != null);
	    return false;
	},
	doCommand : function(cmd){
	    cookiemgr.copySelectedCookiesToClipBoard();
	},
	onEvent : function(evt){ }
    };

    DomainsListBox.controllers.appendController(domainsListController);
    CookieListBox.controllers.appendController(cookiesListController);
}
