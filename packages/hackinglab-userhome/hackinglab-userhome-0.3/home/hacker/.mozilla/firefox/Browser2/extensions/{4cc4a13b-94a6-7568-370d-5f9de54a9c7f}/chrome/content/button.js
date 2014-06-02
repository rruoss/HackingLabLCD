
EmptyCacheButton = {
	
	prefix: 'extensions.{4cc4a13b-94a6-7568-370d-5f9de54a9c7f}.',
	
	init: function() {
		if (this.getBool('firstRun24') === true) {
			this.addButton();
			this.setBool('firstRun24', false);
		}
		this.runAutoCleanTimer();
	},
	
	getService: function(service_type) {
		switch (service_type) {
			case 'cache':
				return Components.classes["@mozilla.org/network/cache-service;1"]
				.getService(Components.interfaces.nsICacheService);
			break;
			case 'app':
				return Components.classes["@mozilla.org/xre/app-info;1"]
				.getService(Components.interfaces.nsIXULAppInfo);
			break;
			case 'prefs':
				return Components.classes["@mozilla.org/preferences-service;1"]
				.getService(Components.interfaces.nsIPrefBranch);
			break;
			case 'alerts':
				return Components.classes["@mozilla.org/alerts-service;1"]
				.getService(Components.interfaces.nsIAlertsService);
			break;
		}
	},
	
	getBool: function(name) {
		return this.getService('prefs').getBoolPref(this.prefix + name)
	},
	
	setBool: function(name, value) {
		return this.getService('prefs').setBoolPref(this.prefix + name, value);
	},
	
	getInt: function(name) {
		return this.getService('prefs').getIntPref(this.prefix + name)
	},
	
	addButton: function() {
		toolbarButton = 'ecb-button';
		navBar = document.getElementById('nav-bar');
		currentSet = navBar.getAttribute('currentset');
		if (!currentSet) {
			currentSet = navBar.currentSet;
		}
		curSet = currentSet.split(',');
		if (curSet.indexOf(toolbarButton) == -1) {
			set = curSet.concat(toolbarButton);
			navBar.setAttribute("currentset", set.join(','));
			navBar.currentSet = set.join(',');
			document.persist(navBar.id, 'currentset');
			try {
				BrowserToolboxCustomizeDone(true);
			} catch (e) {}
		}
	},
	
	runAutoCleanTimer: function() {
		autoClear = window.setInterval(function() {
			
			if (EmptyCacheButton.getBool('autoClearEnable') === false) {
				return null;
			}
			
			TotalSize = 0;
			MaxSize = 0;
			
			EmptyCacheButton.getService('cache').visitEntries({
				visitEntry: function(a, b) {},
				visitDevice: function( device, aDeviceInfo ) {
					if (device == 'disk') {
						TotalSize += aDeviceInfo.totalSize;
						MaxSize += aDeviceInfo.maximumSize;
					}
				}
			});
			
			CurrentUsage = Math.round((TotalSize * 100) / MaxSize);
			if (CurrentUsage > 100) CurrentUsage = 100;
			
			if (CurrentUsage > EmptyCacheButton.getInt('autoClearPercent')) {
				EmptyCacheButton.run();
			}
			
		}, 1000 * 12);
	},
	
	run : function(e) {
		
		if (e == undefined) {
			a = 'default';
		} else {
			var a = e.target.getAttribute('value');
			if (a == '') a = 'default';
		}
		
		if (a == 'options') {
			window.open('chrome://emptycachebutton/content/options.xul', 'Options', 'chrome,centerscreen');
			return null;
		}
		
		if ( a == 'disk' || a == 'all' || (a == 'default' && this.getBool('removeDiskCache') === true) ) {
			this.getService('cache').evictEntries(Components.interfaces.nsICache.STORE_ON_DISK);
		}
		
		if ( a == 'memory' || a == 'all' || (a == 'default' && this.getBool('removeMemoryCache') === true) ) {
			this.getService('cache').evictEntries(Components.interfaces.nsICache.STORE_IN_MEMORY);
		}
		
		if ( a == 'offline' || a == 'all' || (a == 'default' && this.getBool('removeOfflineCache') === true) ) {
			this.getService('cache').evictEntries(Components.interfaces.nsICache.STORE_OFFLINE);
		}
		
		if ( a == 'favicon' || a == 'all' || (a == 'default' && this.getBool('removeImageCache') === true) ) {
			if (this.getService('app').version >= '18.0') {
				Components.classes["@mozilla.org/image/tools;1"]
				.getService(Components.interfaces.imgITools)
				.getImgCacheForDocument(null)
				.clearCache(false);
			} else {
				Components.classes["@mozilla.org/image/cache;1"]
				.getService(Components.interfaces.imgICache)
				.imgCacheService
				.clearCache(false);
			}
		}
		
		if (this.getBool('showNotification') === true) {
			this.getService('alerts').showAlertNotification(
				'chrome://emptycachebutton/skin/icon_32x32.png',
				'Success!', 'Cache has been cleared.', false, '', null, ''
			);
		}
		
		if (this.getInt('doAfterClear') == 2) {
			BrowserReloadSkipCache();
		} else if (this.getInt('doAfterClear') == 3) {
			gBrowser.reloadAllTabs();
		}
		
	}

};

window.addEventListener("load", function () { EmptyCacheButton.init(); }, false);
