/* See license.txt for terms of usage */

/**
 * @author <a href="mailto:stefano.dipaola@mindedsecurity.com">Stefano Di Paola</a>
 * @namespace SeecurityHeaders is a Firebug extension that shows if a response contains 
 * - "X-Frame-Options"
 * - "X-Content-Security-Policy"
 * - "X-Content-Security-Policy-Report-Only",
 * - "X-XSS-Protection"
 * - "Strict-Transport-Security"      
 * should work with Firebug 1.8   
*/
FBL.ns(function() {

with (FBL) {
try{
  var Ci = Components.interfaces;
  var Cc = Components.classes;
  var Cu = Components.utils;
}catch(e){}
const FirebugPrefDomain = "extensions.firebug";
const lastSortedColumn = "seecurityheaders.lastSortedColumn";
const nsIPrefBranch = Ci.nsIPrefBranch;
// Preferences
const PrefService = Cc["@mozilla.org/preferences-service;1"];
const nsIPrefService = Ci.nsIPrefService;
const nsIPrefBranch2 = Ci.nsIPrefBranch2;
const prefService = PrefService.getService(nsIPrefService);
const prefs = PrefService.getService(nsIPrefBranch2);
function now()
{
    return (new Date()).getTime();
}

var allowedMIME = ["text/html"];
var securityHeaders={ "xfo":"X-Frame-Options","csp":"X-Content-Security-Policy","cspro":"X-Content-Security-Policy-Report-Only","xss":"X-XSS-Protection","sts":"Strict-Transport-Security"};
function dumpObj(obj){
 for(var i in obj){
  try{
   dump(i+' '+obj[i]+'\n')
  }catch(e){
   dump(e+' '+e.lineNumber+'\n')
  }
 }
}
// This functions are different in 1.05 and 1.2
// So, this is a stable version.
function getPref(prefDomain, name)
{
    var prefName = prefDomain + "." + name;

    var type = prefs.getPrefType(prefName);
    if (type == nsIPrefBranch.PREF_STRING)
        return prefs.getCharPref(prefName);
    else if (type == nsIPrefBranch.PREF_INT)
        return prefs.getIntPref(prefName);
    else if (type == nsIPrefBranch.PREF_BOOL)
        return prefs.getBoolPref(prefName);
}

function setPref(prefDomain, name, value)
{
    var prefName = prefDomain + "." + name;

    var type = prefs.getPrefType(prefName);
    if (type == nsIPrefBranch.PREF_STRING)
        prefs.setCharPref(prefName, value);
    else if (type == nsIPrefBranch.PREF_INT)
        prefs.setIntPref(prefName, value);
    else if (type == nsIPrefBranch.PREF_BOOL)
        prefs.setBoolPref(prefName, value);
}
 
// Model 
Firebug.SeecurityHeaders={};

Firebug.SeecurityHeaders.Module = extend(Firebug.Module,
{

 initialize: function()
    {
        Firebug.Module.initialize.apply(this, arguments);
        Firebug.NetMonitor.addListener( this );
    },
   showPanel: function(browser, panel) {
        var isHwPanel = panel && panel.name ==  "seecurityheaders";

        if(isHwPanel)
          this.panel=panel;
    },
    shutdown: function()
    {
        Firebug.Module.shutdown.apply(observer, arguments);
 
        Firebug.NetMonitor.removeListener(this);
    },
     onExamineResponse:function (context, request) { 
       try{ 
        this.examineResponse(context,request);
       }catch(e){dump(e)}
    },
    onExamineCachedResponse:function (context, request) { 
       try{ 
       this.examineResponse(context,request);
 
       }catch(e){dump(e)}
    },
    examineResponse: function (context, request) { 
       try{ 
       if(this.panel==null)
        this.panel= context.getPanel("seecurityheaders");
        var ct=null;
        var status=200;
        try{
        // dump("Request: "+request.name+'\n');
         ct=request.contentType;
         
         status = request.responseStatus ;
        }catch(e){ct=""}
        if(request && (status<300 || status > 400)  && ct && allowedMIME.indexOf(ct)>-1){
         if(!context.seecurityHeaders) {
           context.seecurityHeaders=[];
           }
           //dumpObj(request);
         var args={
          url:   request.name 
         };
         for(var i in securityHeaders){
          try{
          args[i]=request.getResponseHeader(securityHeaders[i]);
          }catch(e){args[i]=""}
         }
          //context.seecurityHeaders.push(args);
          this.panel.addRow(context,args);
        }
       }catch(e){dump(e)}
    }
 
});
Firebug.SeecurityHeaders.MonitorPanel = function() {};
Firebug.SeecurityHeaders.MonitorPanel.prototype = extend(Firebug.Panel, {
   name: "seecurityheaders",
   title: "SeecurityHeaders",
    initialize: function(context, doc)
    {
        var hcr = HeaderColumnResizer;
        this.onMouseClick = bind(hcr.onMouseClick, hcr);
        this.onMouseDown = bind(hcr.onMouseDown, hcr);
        this.onMouseMove = bind(hcr.onMouseMove, hcr);
        this.onMouseUp = bind(hcr.onMouseUp, hcr);
        this.onMouseOut = bind(hcr.onMouseOut, hcr);

        Firebug.Panel.initialize.apply(this, arguments);
        if(!context.seecurityHeaders)
         context.seecurityHeaders=[];
        // Just after the initialization, so the this.document member is set.
        //  Firebug.SeecurityHeaders.Module.addStyleSheet(this);
        this.refresh(context);
         
    },
    refresh:function(context){ 
        // dump("Refresh: "+this.panelNode+'\n');
       try{
       
        if(! context.seecurityHeaders){
          context.seecurityHeaders=[];
        }
        var argsArr= context.seecurityHeaders;
          this.table = Templates.SeecurityTable.tableTag.replace({cookie: argsArr},this.panelNode); 
         var header = getElementByClass(this.table, "seecurityHeaderRow");
          var doc= header.ownerDocument;
 
        }catch(ex){dump("[Exc]"+ex+' '+ex.lineNumber+' '+ Error().stack+'\n')}
    },
    destroy: function(state)
    {
        Firebug.Panel.destroy.apply(this, arguments);
 
        // TODO: Panel cleanup.
    },
    setRow: function(doc, args){
      var tr=doc.createElement("tr");
      tr.className +=" seecurityRow";
      for(var i in args){
      var td=doc.createElement("td");
      if(args[i]!=''){
      td.className +=" seecurityCol";
      td.textContent=args[i];
      }else{
      td.className +=" seecurityColRed";
       
      }
      tr.appendChild(td);
       
     }
      return tr;
    },
    addRow: function(context,args){ 
     
       try{
        if(! context.seecurityHeaders){
          context.seecurityHeaders=[];
           
        }
        context.seecurityHeaders.push(args);
        this.refresh(context);
      
      }catch(e){dump('[Exc] '+e+' '+e.filename+' '+Error().stack+'\n')}
   } ,
   
       initializeNode: function(oldPanelNode)
    {
        if (FBTrace.DBG_COOKIES)
            FBTrace.sysout("cookies.FireCookiePanel.initializeNode\n");

        // xxxHonza 
        // This method isn't called when FB UI is detached. So, the columns
        // are *not* resizable when FB is open in external window.

        // Register event handlers for table column resizing.
        this.document.addEventListener("click", this.onMouseClick, true);
        this.document.addEventListener("mousedown", this.onMouseDown, true);
        this.document.addEventListener("mousemove", this.onMouseMove, true);
        this.document.addEventListener("mouseup", this.onMouseUp, true);
        this.document.addEventListener("mouseout", this.onMouseOut, true);

   //     this.panelNode.addEventListener("contextmenu", this.onContextMenu, false);
    },

    destroyNode: function()
    {
        if (FBTrace.DBG_COOKIES)
            FBTrace.sysout("cookies.FireCookiePanel.destroyNode\n");

        this.document.removeEventListener("mouseclick", this.onMouseClick, true);
        this.document.removeEventListener("mousedown", this.onMouseDown, true);
        this.document.removeEventListener("mousemove", this.onMouseMove, true);
        this.document.removeEventListener("mouseup", this.onMouseUp, true);
        this.document.removeEventListener("mouseout", this.onMouseOut, true);

      //  this.panelNode.removeEventListener("contextmenu", this.onContextMenu, false);
    } 

   
   
})
// Object with all rep templates.
var Templates = Firebug.SeecurityHeaders.Templates = {};

/**
 * @domplate Basic template for all Firecookie templates.
 */
Templates.Rep = domplate(Firebug.Rep,
{
    getContextMenuItems: function(cookie, target, context)
    {
        // xxxHonza not sure how to do this better if the default Firebug's "Copy"
        // command (cmd_copy) shouldn't be there.
        var popup = $("fbContextMenu");
        if (popup.firstChild && popup.firstChild.getAttribute("command") == "cmd_copy")
            popup.removeChild(popup.firstChild);
    }
});
Templates.SeecurityTable = domplate(Templates.Rep,
/** @lends Templates.CookieTable */
{
    inspectable: false,

    tableTag:
        TABLE({"class": "seecurityTable", cellpadding: 0, cellspacing: 0, hiddenCols: ""},
            TBODY(
                TR({"class": "seecurityHeaderRow", onclick: "$onClickHeader"},
                    TD({id: "colName", "class": "seecurityHeaderCell alphaValue"},
                        DIV({"class": "seecurityHeaderCellBox", title: ("Url")}, 
                        ("URL"))
                    ),
                    TD({id: "colValue", "class": "seecurityHeaderCell alphaValue"},
                        DIV({"class": "seecurityHeaderCellBox", title: ("When set, prevent the page to be embedded in a frame\\n\
* DENY\\n\
    The page cannot be displayed in a frame, regardless of the site attempting to do so.\\n\
\\n\
* SAMEORIGIN\\n\
    The page can only be displayed in a frame on the same origin as the page itself. ")}, 
                        ("X-Frame-Options"))
                    ),
                    TD({id: "colDomain", "class": "seecurityHeaderCell alphaValue"},
                        DIV({"class": "seecurityHeaderCellBox", title: ("CSP Settings.\\n When set provides several rules to help \\n\
detecting and mitigating certain types of attacks, including XSS and data theft.\\nDetails: https://developer.mozilla.org/en/Introducing_Content_Security_Policy")},
                        ("Content-Security-Policy"))
                    ),
                    TD({id: "colSize", "class": "seecurityHeaderCell"},
                        DIV({"class": "seecurityHeaderCellBox", title: ("CSP Report.\\n When set instructs the browser where to send CSP alerts to.")}, 
                        ("CSP Report"))
                    ),
                    TD({id: "colPath", "class": "seecurityHeaderCell alphaValue"},
                        DIV({"class": "seecurityHeaderCellBox", title: (" * 1 : If a cross-site scripting attack is detected\\n\
       IE 8 & 9 will attempt to make the smallest\\n\
       possible modification to the returned web page\\n\
       in order to block the attack.In most cases, the\\n\
       modification is to change one or more characters \\n\
       in the returned page into the hash character\\n\
       ('#') breaking any script that may have been\\n\
       reflected from the outbound HTTP request.\\n\
\\n\
 * 0 : Pages that have been secured against XSS via\\n\
       server-side logic may opt-out of this protection\\n\
       using this value.\\n\
\\n\
 * 1; mode=block : if a potential XSS Reflection attack\\n\
            is detected, Internet Explorer will prevent\\n\
            rendering of the page. Instead of attempting\\n\
            to sanitize the page to surgically remove the\\n\
            XSS attack, IE will render only '#'.\\n")},
                        ("X-XSS-Protection"))
                    ),
                    TD({id: "colPath", "class": "seecurityHeaderCell alphaValue"},
                        DIV({"class": "seecurityHeaderCellBox", title: ("Lets a web site tell browsers that it should only \\n\
be communicated with using HTTPS, instead of using HTTP.\\n\
\\n\
Strict-Transport-Security: max-age=expireTime [; includeSubdomains]\\n\
\\n\
* expireTime: The time, in seconds, that the browser should \\n\
            remember that this site is only to be accessed \\n\
            using HTTPS.\\n\
\\n\
* includeSubdomains Optional:If this optional parameter is\\n\
           specified, this rule applies to all of the site's\\n\
           subdomains as well.")}, 
                        ("Strict-Transport-Security"))
                    )                
                    ),
                  FOR( "cookie", "$cookie", 
                  
                  TR({"class":"seecurityRow"},
                  TD({"class":"seecurityCol seecurityNameLabel",onclick:"$goNetPanel"},SPAN({"class":"seecurityLink"},"$cookie.url")),
                  TD({"class":"$cookie.xfo|testClass"},"$cookie.xfo|testValue"),
                  TD({"class":"$cookie.csp|testClass"},"$cookie.csp|testValue"),
                  TD({"class":"$cookie.cspro|testClass"},"$cookie.cspro|testValue"),
                  TD({"class":"$cookie.xss|testClass"},"$cookie.xss|testValue"),
                  TD({"class":"$cookie.sts|testClass"},"$cookie.sts|testValue") 
                      )
                  )
                   
                  )
            ) ,
   goNetPanel:function(event){
      
     var el = getElementByClass(event.currentTarget, "seecurityLink");
      
    Firebug.chrome.select(new SourceLink(el.textContent ,null,"net") );//Firebug.NetMonitor.NetFileLink( el.textContent )
   },
   
   testClass:function(c){return (c!=""?"seecurityCol":"seecurityColRed"); },
   testValue:function(c){return (c!=""?c:"None"); },
    onClickHeader: function(event)
    {
        if (FBTrace.DBG_seecurityS)
            FBTrace.sysout("seecuritys.onClickHeader\n");

        if (!isLeftClick(event))
            return;

        var table = getAncestorByClass(event.target, "seecurityTable");
        var column = getAncestorByClass(event.target, "seecurityHeaderCell");
        this.sortColumn(table, column);
    },

    sortColumn: function(table, col, direction)
    {
        if (!col)
            return;

        if (typeof(col) == "string")
        {
            var doc = table.ownerDocument;
            col = doc.getElementById(col);
        }

        if (!col)
            return;

        var numerical = !hasClass(col, "alphaValue");

        var colIndex = 0;
        for (col = col.previousSibling; col; col = col.previousSibling)
            ++colIndex;

        this.sort(table, colIndex, numerical, direction);
    },

    sort: function(table, colIndex, numerical, direction)
    {
        var tbody = table.lastChild;
        var headerRow = tbody.firstChild;

        // Remove class from the currently sorted column
        var headerSorted = getChildByClass(headerRow, "seecurityHeaderSorted");
        removeClass(headerSorted, "seecurityHeaderSorted");

        // Mark new column as sorted.
        var header = headerRow.childNodes[colIndex];
        setClass(header, "seecurityHeaderSorted");

        // If the column is already using required sort direction, bubble out.
        if ((direction == "desc" && header.sorted == 1) ||
            (direction == "asc" && header.sorted == -1))
            return;

        var values = [];
        for (var row = tbody.childNodes[1]; row; row = row.nextSibling)
        {
            var cell = row.childNodes[colIndex];
            var value = numerical ? parseFloat(cell.textContent) : cell.textContent;

            // Issue 43, expires date is formatted in the UI, so use the original seecurity
            // value instead.
            if (hasClass(cell, "seecurityExpiresCol"))
                value = row.repObject.seecurity.expires;

            if (hasClass(row, "opened"))
            {
                var seecurityInfoRow = row.nextSibling;
                values.push({row: row, value: value, info: seecurityInfoRow});
                row = seecurityInfoRow;
            }
            else
            {
                values.push({row: row, value: value});
            }
        }

        values.sort(function(a, b) { return a.value < b.value ? -1 : 1; });

        if ((header.sorted && header.sorted == 1) || (!header.sorted && direction == "asc"))
        {
            removeClass(header, "sortedDescending");
            setClass(header, "sortedAscending");

            header.sorted = -1;

            for (var i = 0; i < values.length; ++i)
            {
                tbody.appendChild(values[i].row);
                if (values[i].info)
                    tbody.appendChild(values[i].info);
            }
        }
        else
        {
            removeClass(header, "sortedAscending");
            setClass(header, "sortedDescending");

            header.sorted = 1;

            for (var i = values.length-1; i >= 0; --i)
            {
                tbody.appendChild(values[i].row);
                if (values[i].info)
                    tbody.appendChild(values[i].info);
            }
        }

        // Remember last sorted column & direction in preferences.
        var prefValue = header.getAttribute("id") + " " + (header.sorted > 0 ? "desc" : "asc");
        setPref(FirebugPrefDomain, lastSortedColumn, prefValue);
    },

    supportsObject: function(object)
    {
        return (object == this);
    },

    /**
     * Provides menu items for header context menu.
     */
    getContextMenuItems: function(object, target, context)
    {
        Templates.Rep.getContextMenuItems.apply(this, arguments);

        var items = [];

        // Iterate over all columns and create a menu item for each.
        var table = context.getPanel(panelName, true).table;
        var hiddenCols = table.getAttribute("hiddenCols");

        var lastVisibleIndex;
        var visibleColCount = 0;

        var header = getAncestorByClass(target, "seecurityHeaderRow");

        // Skip the first column for breakpoints.
        var columns = cloneArray(header.childNodes);
        columns.shift();

        for (var i=0; i<columns.length; i++)
        {
            var column = columns[i];
            var visible = (hiddenCols.indexOf(column.id) == -1);

            items.push({
                label: column.textContent,
                type: "checkbox",
                checked: visible,
                nol10n: true,
                command: bindFixed(this.onShowColumn, this, context, column.id)
            });

            if (visible)
            {
                lastVisibleIndex = i;
                visibleColCount++;
            }
        }

        // If the last column is visible, disable its menu item.
        if (visibleColCount == 1)
            items[lastVisibleIndex].disabled = true;

        items.push("-");
        items.push({
            label: $STR("net.header.Reset Header"),
            nol10n: true, 
            command: bindFixed(this.onResetColumns, this, context)
        });

        return items;
    },

    onShowColumn: function(context, colId)
    {
        var table = context.getPanel(panelName, true).table;
        var hiddenCols = table.getAttribute("hiddenCols");

        // If the column is already presented in the list of hidden columns,
        // remove it, otherwise append.
        var index = hiddenCols.indexOf(colId);
        if (index >= 0)
        {
            table.setAttribute("hiddenCols", hiddenCols.substr(0,index-1) +
                hiddenCols.substr(index+colId.length));
        }
        else
        {
            table.setAttribute("hiddenCols", hiddenCols + " " + colId);
        }

        // Store current state into the preferences.
        setPref(FirebugPrefDomain, hiddenColsPref, table.getAttribute("hiddenCols"));
    },

    onResetColumns: function(context)
    {
        var panel = context.getPanel(panelName, true);
        var header = getElementByClass(panel.panelNode, "seecurityHeaderRow");

        // Reset widths
        var columns = header.childNodes;
        for (var i=0; i<columns.length; i++)
        {
            var col = columns[i];
            if (col.style)
                col.style.width = "";
        }

        // Reset visibility. Only the Status column is hidden by default.
        panel.table.setAttribute("hiddenCols", "colStatus");
        setPref(FirebugPrefDomain, hiddenColsPref, "colStatus");
    },

    createTable: function(parentNode)
    {
        // Create seecurity table UI.
        var table = this.tableTag.replace({cookie:["aa","ddd"]}, parentNode, this);

        return table;
    },

    render: function(seecurityh, parentNode)
    {
        // Create basic seecurity-list structure.
        var table = this.createTable(parentNode);
        var header = getElementByClass(table, "seecurityHeaderRow");

        var tag = Templates.SeecurityHeadersRow.SHTag;
        return tag.insertRows({seecurityh: [seecurityh]}, header);
    }
});

// ************************************************************************************************
// Resizable column helper (helper for Templates.seecurityTable)

var HeaderColumnResizer =
{
    resizing: false,
    currColumn: null,
    startX: 0,
    startWidth: 0,
    lastMouseUp: 0,

    onMouseClick: function(event)
    {
        if (!isLeftClick(event))
            return;

        // Avoid click event for sorting, if the resizing has been just finished.
        var rightNow = now();
        if ((rightNow - this.lastMouseUp) < 1000)
            cancelEvent(event);
    },

    onMouseDown: function(event)
    {
        if (!isLeftClick(event))
            return;

        var target = event.target;
        if (!hasClass(target, "seecurityHeaderCellBox"))
            return;

        var header = getAncestorByClass(target, "seecurityHeaderRow");
        if (!header)
            return;

        this.onStartResizing(event);

        cancelEvent(event);
    },

    onMouseMove: function(event)
    {
        if (this.resizing)
        {
            if (hasClass(target, "seecurityHeaderCellBox"))
                target.style.cursor = "e-resize";

            this.onResizing(event);
            return;
        }

        var target = event.target;
        if (!hasClass(target, "seecurityHeaderCellBox"))
            return;

        if (target)
            target.style.cursor = "";

        if (!this.isBetweenColumns(event))
            return;

        // Update cursor if the mouse is located between two columns.
        target.style.cursor = "e-resize";
    },

    onMouseUp: function(event)
    {
        if (!this.resizing)
            return;

        this.lastMouseUp = now();

        this.onEndResizing(event);
        cancelEvent(event);
    },

    onMouseOut: function(event)
    {
        if (!this.resizing)
            return;

        if (FBTrace.DBG_seecurityS)
        {
            FBTrace.sysout("seecuritys.Mouse out, target: " + event.target.localName +
                ", " + event.target.className + "\n");
            FBTrace.sysout("      explicitOriginalTarget: " + event.explicitOriginalTarget.localName +
                ", " + event.explicitOriginalTarget.className + "\n");
        }

        var target = event.target;
        if (target == event.explicitOriginalTarget)
            this.onEndResizing(event);

        cancelEvent(event);
    },

    isBetweenColumns: function(event)
    {
        var target = event.target;
        var x = event.clientX;
        var y = event.clientY;

        var column = getAncestorByClass(target, "seecurityHeaderCell");
        var offset = getClientOffset(column);
        var size = getOffsetSize(column);

        if (column.previousSibling)
        {
            if (x < offset.x + 4)
                return 1;   // Mouse is close to the left side of the column (target).
        }

        if (column.nextSibling)
        {
            if (x > offset.x + size.width - 6)
                return 2;  // Mouse is close to the right side.
        }

        return 0;
    },

    onStartResizing: function(event)
    {
        var location = this.isBetweenColumns(event);
        if (!location)
            return;

        var target = event.target;

        this.resizing = true;
        this.startX = event.clientX;

        // Currently resizing column.
        var column = getAncestorByClass(target, "seecurityHeaderCell");
        this.currColumn = (location == 1) ? column.previousSibling : column;

        // Last column width.
        var size = getOffsetSize(this.currColumn);
        this.startWidth = size.width;

        if (FBTrace.DBG_seecurityS)
        {
            var colId = this.currColumn.getAttribute("id");
            FBTrace.sysout("seecuritys.Start resizing column (id): " + colId +
                ", start width: " + this.startWidth + "\n");
        }
    },

    onResizing: function(event)
    {
        if (!this.resizing)
            return;

        var newWidth = this.startWidth + (event.clientX - this.startX);
        this.currColumn.style.width = newWidth + "px";

        if (FBTrace.DBG_seecurityS)
        {
            var colId = this.currColumn.getAttribute("id");
            FBTrace.sysout("seecuritys.Resizing column (id): " + colId +
                ", new width: " + newWidth + "\n");
        }
    },

    onEndResizing: function(event)
    {
        if (!this.resizing)
            return;

        this.resizing = false;

        var newWidth = this.startWidth + (event.clientX - this.startX);
        this.currColumn.style.width = newWidth + "px";

        // Store width into the preferences.
        var colId = this.currColumn.getAttribute("id");
        if (colId)
        {
            var prefName = FirebugPrefDomain + ".seecurityheaders." + colId + ".width";

            // Use directly nsIPrefBranch interface as the pref
            // doesn't have to exist yet.
            prefs.setIntPref(prefName, newWidth);
        }

        if (FBTrace.DBG_seecurityS)
        {
            var colId = this.currColumn.getAttribute("id");
            FBTrace.sysout("seecuritys.End resizing column (id): " + colId +
                ", new width: " + newWidth + "\n");
        }
    }
};
 

Firebug.registerModule(Firebug.SeecurityHeaders.Module);
Firebug.registerPanel(Firebug.SeecurityHeaders.MonitorPanel);
Firebug.registerRep(
    Templates.SeecurityTable );          // Cookie table with list of cookies

    // Register stylesheet in Firebug. This method is introduced in Firebug 1.6
if (Firebug.registerStylesheet)
    Firebug.registerStylesheet("chrome://seecurityheaders/skin/seecurityheaders.css");

}
})
